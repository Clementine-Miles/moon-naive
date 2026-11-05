//! H2/H3 frontends with shared authenticated egress and Pingora website engine.
mod congestion;
mod egress;
mod h2;
mod h3;
mod outbound;
mod redirect;
mod site;
#[cfg(test)]
mod tests;
pub(crate) mod tls;
mod tunnel;

use crate::acme::Result;
use bytes::Bytes;
use moon_naive_core::{
    auth::Credentials,
    config::Config,
    config::TransportProfile,
    ingress::{self, Dispatch, RequestHead},
    policy::{Budget, Permit},
};
use serde::Deserialize;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::{Semaphore, watch},
};

pub(crate) const CHUNK: usize = 16 * 1024;
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
#[derive(Clone)]
pub(crate) struct Head {
    binding: Option<moon_naive_core::auth::Binding>,
    client_ip: Option<std::net::IpAddr>,
    method: String,
    authority: String,
    scheme: Option<String>,
    path: Option<String>,
    protocol: Option<String>,
    headers: Vec<(String, Vec<u8>)>,
}
impl Head {
    fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }
    fn valid(&self) -> bool {
        let mut length = None;
        let framing_valid = self.headers.iter().all(|(name, value)| {
            if name == "te" {
                return value.eq_ignore_ascii_case(b"trailers");
            }
            if name != "content-length" {
                return true;
            }
            let Ok(value) = std::str::from_utf8(value) else {
                return false;
            };
            value.split(',').all(|item| {
                let item = item.trim_matches([' ', '\t']);
                if item.is_empty() || !item.bytes().all(|b| b.is_ascii_digit()) {
                    return false;
                }
                let Ok(n) = item.parse::<u64>() else {
                    return false;
                };
                if length.is_some_and(|previous| previous != n) {
                    return false;
                }
                length = Some(n);
                true
            })
        });
        let authority_valid = self.authority.parse::<http::uri::Authority>().is_ok()
            && !self.authority.contains('@')
            && self
                .headers
                .iter()
                .filter(|(name, _)| name == "host")
                .count()
                <= 1
            && self
                .header("host")
                .is_none_or(|value| value.eq_ignore_ascii_case(self.authority.as_bytes()));
        let target_valid = self.method.parse::<http::Method>().is_ok()
            && (self.method == "CONNECT"
                || (matches!(self.scheme.as_deref(), Some("http" | "https"))
                    && self.path.as_deref().is_some_and(|path| {
                        path.starts_with('/') || (self.method == "OPTIONS" && path == "*")
                    })
                    && self.protocol.is_none()));
        framing_valid
            && authority_valid
            && target_valid
            && self.headers.len() <= 128
            && self
                .headers
                .iter()
                .map(|(n, v)| n.len() + v.len() + 32)
                .sum::<usize>()
                + self.authority.len()
                + self.path.as_ref().map_or(0, String::len)
                <= 32768
            && self.headers.iter().all(|(name, value)| {
                !name.starts_with(':')
                    && !name.bytes().any(|b| b.is_ascii_uppercase())
                    && http::header::HeaderName::from_bytes(name.as_bytes()).is_ok()
                    && http::HeaderValue::from_bytes(value).is_ok()
                    && ![
                        "connection",
                        "proxy-connection",
                        "keep-alive",
                        "transfer-encoding",
                        "upgrade",
                    ]
                    .contains(&name.as_str())
                    && memchr::memchr3(0, b'\r', b'\n', value).is_none()
            })
    }
}
pub(crate) struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Bytes,
}
impl Reply {
    fn error(status: u16) -> Self {
        let body = Bytes::from(format!(
            "{}\n",
            http::StatusCode::from_u16(status)
                .unwrap()
                .canonical_reason()
                .unwrap_or("Error")
        ));
        Self {
            status,
            headers: vec![
                ("content-type".into(), "text/plain; charset=utf-8".into()),
                ("content-length".into(), body.len().to_string()),
            ],
            body,
        }
    }
    fn head(mut self, is_head: bool) -> Self {
        if is_head {
            self.body = Bytes::new();
        }
        self
    }
    fn tunnel() -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }
}
pub(crate) enum Plan {
    Site(Reply),
    Website(Head),
    Forward(Head, Arc<site::Site>),
    Tunnel {
        target: outbound::Stream,
        framed: Option<moon_naive_core::codec::Mode>,
        response: Reply,
        _permit: Permit,
    },
}
#[derive(Default)]
pub struct Stats {
    #[cfg(test)]
    pub h3_driver_iterations: AtomicUsize,
    #[cfg(test)]
    pub h3_path_events: AtomicUsize,
    pub h2_connections: AtomicUsize,
    pub h3_connections: AtomicUsize,
    pub dials: AtomicUsize,
    pub resolutions: AtomicUsize,
    pub streams: AtomicUsize,
}
pub(crate) struct Active(Arc<Stats>);
impl Active {
    fn new(stats: Arc<Stats>) -> Self {
        stats.streams.fetch_add(1, Ordering::Relaxed);
        Self(stats)
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        self.0.streams.fetch_sub(1, Ordering::Relaxed);
    }
}
pub(crate) struct App {
    credentials: Credentials,
    site: Arc<site::Site>,
    egress: egress::Egress,
    tunnels: Budget,
    requests: Budget,
    pub stats: Arc<Stats>,
    pub profile: TransportProfile,
    pub idle: Duration,
    pub graceful: Duration,
    receive: Arc<Semaphore>,
    early: u32,
    tcp_congestion: moon_naive_core::config::TcpCongestion,
    h1: bool,
    config: Arc<Config>,
    forwards: std::sync::Mutex<std::collections::HashMap<(usize, String), Arc<site::Site>>>,
}
impl App {
    fn load(config: &Arc<Config>) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Users {
            users: Vec<moon_naive_core::config::User>,
        }
        let users = if config.proxy.users.is_empty() {
            crate::acme::state::load_toml::<Users>(&config.credentials_file, 512 * 1024)?
        } else {
            Users {
                users: config.proxy.users.clone(),
            }
        };
        if users
            .users
            .iter()
            .map(|u| &u.username)
            .collect::<std::collections::HashSet<_>>()
            .len()
            != users.users.len()
        {
            return Err("duplicate proxy usernames".into());
        }
        let credentials = Credentials::new(
            &users
                .users
                .iter()
                .map(|u| (u.username.as_str(), u.password.as_str()))
                .collect::<Vec<_>>(),
        )?;
        let stats = Arc::new(Stats::default());
        Ok(Self {
            credentials,
            site: Arc::new(site::Site::load(config)?),
            egress: egress::Egress::new(config, stats.clone())?,
            tunnels: Budget::new(config.limits.max_streams)?,
            requests: Budget::new(config.limits.max_streams.saturating_mul(2))?,
            stats,
            profile: TransportProfile::from_config(config)?,
            idle: Duration::from_secs(config.limits.idle_timeout_secs),
            graceful: Duration::from_secs(config.limits.graceful_timeout_secs),
            receive: Arc::new(Semaphore::new(config.limits.max_total_receive_bytes)),
            early: config.limits.max_early_data_bytes as u32,
            tcp_congestion: config.transport.tcp_congestion,
            h1: config.listener.h1,
            config: config.clone(),
            forwards: Default::default(),
        })
    }
    async fn prepare(&self, head: &Head) -> Result<Plan> {
        if !head.valid() {
            return Ok(Plan::Site(Reply::error(400).head(head.method == "HEAD")));
        }
        if head.protocol.is_some() {
            if head.method != "CONNECT"
                || head.protocol.as_deref() != Some("websocket")
                || head.scheme.as_deref() != Some("https")
                || head.path.as_deref().is_none_or(|p| !p.starts_with('/'))
            {
                return Ok(Plan::Site(Reply::error(400)));
            }
            let prepared = match site::websocket::prepare(&self.config, head) {
                Ok(prepared) => prepared,
                Err(status) => return Ok(Plan::Site(Reply::error(status))),
            };
            let Some(permit) = self.tunnels.acquire() else {
                return Ok(Plan::Site(Reply::error(503)));
            };
            return match tokio::time::timeout(
                std::time::Duration::from_secs(self.config.website.connect_timeout_secs),
                site::websocket::connect(prepared),
            )
            .await
            {
                Ok(Ok((target, response))) => Ok(Plan::Tunnel {
                    target,
                    framed: None,
                    response,
                    _permit: permit,
                }),
                Ok(Err(status)) => Ok(Plan::Site(Reply::error(status))),
                Err(_) => Ok(Plan::Site(Reply::error(504))),
            };
        }
        let headers: Vec<_> = head
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_slice()))
            .collect();
        if head.method != "CONNECT" && head.protocol.is_none() {
            let host = head
                .authority
                .parse::<http::uri::Authority>()
                .map_err(|_| "invalid authority")?;
            if self.config.site_name(host.host()).is_none()
                && let Some(user) = (RequestHead {
                    binding: head.binding.as_ref(),
                    method: &head.method,
                    authority: &head.authority,
                    scheme: head.scheme.as_deref(),
                    path: head.path.as_deref(),
                    protocol: head.protocol.as_deref(),
                    headers: &headers,
                })
                .principal(&self.credentials)
            {
                let origin = format!(
                    "{}://{}",
                    head.scheme.as_deref().ok_or("missing scheme")?,
                    head.authority
                );
                let key = (user, origin.clone());
                let mut sites = self
                    .forwards
                    .lock()
                    .map_err(|_| "forward pool lock poisoned")?;
                let site = if let Some(site) = sites.get(&key) {
                    site.clone()
                } else {
                    let site = Arc::new(site::Site::forward(
                        &self.config,
                        &origin,
                        user,
                        self.egress.clone(),
                        &self.site,
                    )?);
                    if sites.len() >= 128
                        && let Some(old) = sites.keys().next().cloned()
                    {
                        sites.remove(&old);
                    }
                    sites.insert(key, site.clone());
                    site
                };
                let mut sanitized = head.clone();
                sanitized.binding = None;
                sanitized
                    .headers
                    .retain(|(name, _)| !ingress::is_proxy_header(name));
                return Ok(Plan::Forward(sanitized, site));
            }
        }
        let route = ingress::dispatch(
            RequestHead {
                binding: head.binding.as_ref(),
                method: &head.method,
                authority: &head.authority,
                scheme: head.scheme.as_deref(),
                path: head.path.as_deref(),
                protocol: head.protocol.as_deref(),
                headers: &headers,
            },
            &self.credentials,
        );
        let tunnel = match route {
            Ok(Dispatch::Site(site)) => {
                let sanitized = Head {
                    binding: None,
                    client_ip: head.client_ip,
                    method: site.method.into(),
                    authority: site.authority.into(),
                    scheme: site.scheme.map(str::to_owned),
                    path: site.path.map(str::to_owned),
                    protocol: None,
                    headers: site
                        .headers
                        .into_iter()
                        .map(|(n, v)| (n.to_owned(), v.to_vec()))
                        .collect(),
                };
                return Ok(Plan::Website(sanitized));
            }
            Ok(Dispatch::Tunnel(tunnel)) => tunnel,
            Err(_) => return Ok(Plan::Site(Reply::error(400))),
        };
        let Some(permit) = self.tunnels.acquire() else {
            return Ok(Plan::Site(Reply::error(503)));
        };
        match self.egress.dial(tunnel.target()).await {
            Ok(target) => Ok(Plan::Tunnel {
                target,
                framed: Some(self.config.traffic.select(tunnel.offer())),
                response: {
                    let mut reply = Reply::tunnel();
                    let context = moon_naive_core::auth::Context {
                        binding: head
                            .binding
                            .as_ref()
                            .ok_or("missing authenticated binding")?,
                        method: &head.method,
                        authority: &head.authority,
                        scheme: head.scheme.as_deref(),
                        path: head.path.as_deref(),
                        protocol: head.protocol.as_deref(),
                    };
                    reply.headers.push((
                        "proxy-authentication-info".into(),
                        self.credentials
                            .confirmation_with(
                                tunnel.principal(),
                                &context,
                                tunnel.offer(),
                                self.config.traffic.select(tunnel.offer()),
                            )
                            .ok_or("invalid authenticated principal")?,
                    ));
                    reply
                },
                _permit: permit,
            }),
            Err(status) => Ok(Plan::Site(Reply::error(status))),
        }
    }
}
/// Validate the website/users before ACME may create an order. Reuse the loaded
/// application when the first certificate becomes ready.
pub(crate) struct Prepared {
    app: App,
    config: Arc<Config>,
}
impl Prepared {
    pub async fn load(config: Arc<Config>) -> Result<Self> {
        config.validate()?;
        congestion::check(&config)?;
        let local = config.clone();
        let app = tokio::task::spawn_blocking(move || App::load(&local)).await??;
        Ok(Self { app, config })
    }
    pub async fn bind(self) -> Result<Network> {
        let Self { mut app, config } = self;
        let local = config.clone();
        let tls = tokio::task::spawn_blocking(move || tls::Slot::load(&local)).await??;
        if let Ok(Ok(addresses)) = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::lookup_host((config.domain.as_str(), config.listener.tcp.port())),
        )
        .await
        {
            app.egress
                .own
                .extend(addresses.take(32).map(|address| address.ip()));
        }
        let tcp = congestion::listen(config.listener.tcp, config.transport.tcp_congestion)?;
        let udp = UdpSocket::bind(config.listener.udp).await?;
        let redirect = match config.listener.http_redirect {
            Some(addr) => Some(TcpListener::bind(addr).await?),
            None => None,
        };
        let connections = Budget::new(config.limits.max_connections)?;
        let stats = app.stats.clone();
        Ok(Network {
            app: Arc::new(app),
            tls,
            tcp,
            udp,
            redirect,
            connections,
            config,
            stats,
        })
    }
}
/// Both binds succeed before accepting; all certificate validation finishes first.
pub struct Network {
    app: Arc<App>,
    tls: tls::Slot,
    tcp: TcpListener,
    udp: UdpSocket,
    redirect: Option<TcpListener>,
    connections: Budget,
    config: Arc<Config>,
    pub stats: Arc<Stats>,
}
impl Network {
    pub async fn bind(config: Config) -> Result<Self> {
        Prepared::load(Arc::new(config)).await?.bind().await
    }
    pub fn tcp_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self.tcp.local_addr()?)
    }
    pub fn udp_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self.udp.local_addr()?)
    }
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        if *shutdown.borrow() {
            return Ok(());
        }
        let Self {
            app,
            tls,
            tcp,
            udp,
            redirect,
            connections,
            config,
            ..
        } = self;
        let mut tasks = tokio::task::JoinSet::new();
        if let Some(listener) = redirect {
            let config = config.clone();
            let stop = shutdown.clone();
            let budget = connections.clone();
            tasks.spawn(async move {
                redirect::serve(listener, config, budget, stop).await?;
                Ok(true)
            });
        }
        let reload = tls.clone();
        let reload_stop = shutdown.clone();
        tasks.spawn(async move {
            tls::watch(config, reload, reload_stop).await;
            Ok::<_, crate::acme::Error>(false)
        });
        let h3_app = app.clone();
        let h3_tls = tls.clone();
        let h3_stop = shutdown.clone();
        let h3_connections = connections.clone();
        tasks.spawn(async move {
            h3::serve(udp, h3_app, h3_tls, h3_connections, h3_stop).await?;
            Ok(true)
        });
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                _=shutdown.changed()=>break,
                Some(result)=tasks.join_next(),if !tasks.is_empty()=>{if result?? {if *shutdown.borrow(){break;}return Err("listener driver stopped unexpectedly".into());}},
                result=tcp.accept()=>{
                    let (socket,_)=result?;
                    let Some(permit)=connections.acquire() else {drop(socket);continue;};
                    let tls=tls.clone();let app=app.clone();let stop=shutdown.clone();
                    tasks.spawn(async move {let _permit=permit;let _=h2::serve(socket,app,tls,stop).await;Ok(false)});
                }
            }
        }
        app.site.stop_bridge();
        {
            let sites = app.forwards.lock().unwrap_or_else(|e| e.into_inner());
            for site in sites.values() {
                site.stop_bridge();
            }
        }
        // Shared shutdown receiver tells both drivers to stop accepting streams.
        let grace = app.graceful;
        let _ =
            tokio::time::timeout(grace, async { while tasks.join_next().await.is_some() {} }).await;
        tasks.abort_all();
        Ok(())
    }
}

/// Validates feature availability and per-socket kernel support without binding
/// listeners, reading private files, changing sysctls or making network calls.
pub fn check_transport(config: &Config) -> Result<()> {
    config.validate()?;
    congestion::check(config)
}

pub fn kernel_security_report() -> String {
    congestion::kernel_report()
}

/// Local preflight diagnostics: this probes a new socket, not a live connection.
pub fn flow_control_report(config: &Config) -> Result<String> {
    let profile = TransportProfile::from_config(config)?;
    let initial = config
        .limits
        .max_early_data_bytes
        .min(profile.stream_window() as usize);
    Ok(format!(
        "tcp_congestion_effective={}\ntcp_socket_buffers=system_managed\nquic_pacing=quiche_send_time\nh2_initial_stream_receive_bytes={initial}\nh3_initial_stream_receive_bytes={initial}\nh3_max_stream_receive_bytes={}\nconnection_receive_bytes={}\ntotal_receive_budget_bytes={}",
        congestion::effective(config.transport.tcp_congestion)?,
        profile.stream_window(),
        profile.connection_window(),
        config.limits.max_total_receive_bytes,
    ))
}

/// Operator diagnostics only. Libraries dispatch on the deployment CPU (and OS
/// SIMD state), independently of the CPU that compiled this portable binary.
pub fn acceleration_report() -> String {
    use std::fmt::Write;
    let mut report = String::new();
    write!(
        &mut report,
        "cpu_arch={}\ncpu_dispatch=runtime\nheader_scan=memchr-runtime\nsha256=sha2-runtime\ntls_crypto=boringssl-runtime",
        std::env::consts::ARCH,
    ).unwrap();
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        for (name, supported) in [
            ("sse2", std::arch::is_x86_feature_detected!("sse2")),
            ("ssse3", std::arch::is_x86_feature_detected!("ssse3")),
            ("sse4_1", std::arch::is_x86_feature_detected!("sse4.1")),
            ("avx2", std::arch::is_x86_feature_detected!("avx2")),
            ("aes", std::arch::is_x86_feature_detected!("aes")),
            (
                "pclmulqdq",
                std::arch::is_x86_feature_detected!("pclmulqdq"),
            ),
            ("sha", std::arch::is_x86_feature_detected!("sha")),
            ("avx512f", std::arch::is_x86_feature_detected!("avx512f")),
        ] {
            // These are capabilities, not a claim that every short input or TLS
            // cipher uses the widest vector unit. Each library selects its path.
            write!(&mut report, "\ncpu_{name}={supported}").unwrap();
        }
    }
    report
}

/// Export only after the completed handshake; never use early exporters.
fn exporter(ssl: &boring::ssl::SslRef) -> Result<[u8; 32]> {
    if ssl.version2() != Some(boring::ssl::SslVersion::TLS1_3) {
        return Err("moon-naive requires TLS 1.3".into());
    }
    let mut output = [0; 32];
    ssl.export_keying_material(
        &mut output,
        moon_naive_core::auth::EXPORTER_LABEL,
        Some(b""),
    )?;
    Ok(output)
}
