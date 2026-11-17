//! H2/H3 frontends with shared authenticated egress and Pingora website engine.
mod congestion;
mod egress;
pub(crate) use egress::connect_candidates;
mod forward_cache;
mod h2;
mod h3;
mod rate;
mod redirect;
mod resources;
mod site;
#[cfg(test)]
mod tests;
pub(crate) mod tls;
mod tunnel;

use crate::Result;
use bytes::Bytes;
use moon_naive_core::{
    auth::Credentials,
    config::Config,
    config::TransportProfile,
    ingress::{self, Dispatch, RequestHead},
    policy::Budget,
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
    sync::watch,
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
    Forward(Head, Arc<site::Site>, resources::TunnelLease),
    Tunnel {
        target: egress::Stream,
        framed: Option<moon_naive_core::codec::Mode>,
        response: Reply,
        _permit: resources::TunnelLease,
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
    credentials: Arc<Credentials>,
    site: Arc<site::Site>,
    egress: egress::Egress,
    resources: resources::Resources,
    pub stats: Arc<Stats>,
    pub profile: TransportProfile,
    pub idle: Duration,
    pub graceful: Duration,
    early: u32,
    tcp_congestion: moon_naive_core::config::TcpCongestion,
    h1: bool,
    config: Arc<Config>,
    forwards: Arc<forward_cache::Cache<site::Site>>,
    global_site: Arc<site::Site>,
    endpoint_limits: moon_naive_core::config::Limits,
    endpoint_index: usize,
    endpoint_name: String,
    h2: bool,
    handshake: Duration,
    rate: Arc<rate::Rate>,
}
impl App {
    fn load(config: &Arc<Config>) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Users {
            users: Vec<moon_naive_core::config::User>,
        }
        let users = if config.proxy.users.is_empty() {
            crate::acme::persist::load_toml::<Users>(&config.credentials_file, 512 * 1024)?
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
        let resources = resources::Resources::new(config, users.users.len())?;
        let mut site = site::Site::load(config, resources.tunnels.clone())?;
        site.buffers = resources.buffers.clone();
        let site = Arc::new(site);
        Ok(Self {
            credentials: Arc::new(credentials),
            global_site: site.clone(),
            site,
            egress: egress::Egress::new(config, stats.clone())?,
            resources,
            stats,
            profile: TransportProfile::from_config(config)?,
            idle: Duration::from_secs(config.limits.idle_timeout_secs),
            graceful: Duration::from_secs(config.limits.graceful_timeout_secs),
            early: config.limits.max_early_data_bytes as u32,
            tcp_congestion: config.transport.tcp_congestion,
            h1: config.listener.h1,
            config: config.clone(),
            forwards: Default::default(),
            endpoint_limits: config.limits.clone(),
            endpoint_index: 0,
            endpoint_name: config.effective_listeners()[0].name.clone(),
            h2: config.effective_listeners()[0].listener.h2,
            handshake: Duration::from_secs(config.effective_listeners()[0].handshake_timeout_secs),
            rate: rate::Rate::new(config.effective_listeners()[0].bandwidth_bytes_per_sec)?,
        })
    }
    fn endpoint(&self, index: usize, endpoint: &moon_naive_core::config::Endpoint) -> Result<Self> {
        let limits = endpoint.limits.as_ref().expect("effective endpoint limits");
        let resources = self.resources.endpoint(&self.config, limits)?;
        let site = Arc::new(self.site.endpoint(
            &endpoint.name,
            limits,
            resources.buffers.clone(),
            resources.tunnels.clone(),
        ));
        Ok(Self {
            credentials: self.credentials.clone(),
            site,
            egress: self
                .egress
                .with_timeout(Duration::from_secs(limits.connect_timeout_secs)),
            resources,
            stats: self.stats.clone(),
            profile: TransportProfile::for_endpoint(&self.config, endpoint)?,
            idle: Duration::from_secs(limits.idle_timeout_secs),
            graceful: Duration::from_secs(limits.graceful_timeout_secs),
            early: limits.max_early_data_bytes as u32,
            tcp_congestion: self.tcp_congestion,
            h1: endpoint.listener.h1,
            h2: endpoint.listener.h2,
            config: self.config.clone(),
            forwards: self.forwards.clone(),
            global_site: self.global_site.clone(),
            endpoint_limits: limits.clone(),
            endpoint_index: index,
            endpoint_name: endpoint.name.clone(),
            handshake: Duration::from_secs(endpoint.handshake_timeout_secs),
            rate: rate::Rate::new(endpoint.bandwidth_bytes_per_sec)?,
        })
    }
    async fn prepare(&self, head: &Head) -> Result<Plan> {
        let Some(_waiting) = self.resources.waiting.acquire() else {
            return Ok(Plan::Site(Reply::error(503)));
        };
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
            let prepared = match site::websocket::prepare(&self.config, head, &self.site) {
                Ok(prepared) => prepared,
                Err(status) => return Ok(Plan::Site(Reply::error(status))),
            };
            let Some(permit) = self.resources.tunnel(None) else {
                return Ok(Plan::Site(Reply::error(503)));
            };
            return match tokio::time::timeout(
                std::time::Duration::from_secs(
                    self.config
                        .website
                        .connect_timeout_secs
                        .min(self.endpoint_limits.connect_timeout_secs),
                ),
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
                let Some(lease) = self.resources.forward(user) else {
                    return Ok(Plan::Site(Reply::error(503)));
                };
                let slot = self.forwards.slot((user, origin.clone())).await;
                let site = slot
                    .get_or_try_init(|| async {
                        // The permit belongs to the blocking job even if this waiter
                        // is cancelled. No global cache lock covers TLS/pool setup.
                        let permit = self
                            .resources
                            .initializers
                            .clone()
                            .try_acquire_owned()
                            .map_err(|_| "forward initialization busy")?;
                        let config = self.config.clone();
                        let max_connect = self
                            .config
                            .effective_listeners()
                            .iter()
                            .filter_map(|e| e.limits.as_ref().map(|l| l.connect_timeout_secs))
                            .max()
                            .unwrap_or(self.config.limits.connect_timeout_secs);
                        let egress = self.egress.with_timeout(Duration::from_secs(max_connect));
                        let website = self.global_site.clone();
                        tokio::task::spawn_blocking(move || {
                            let _permit = permit;
                            site::Site::forward(&config, &origin, user, egress, &website)
                                .map(Arc::new)
                        })
                        .await
                        .map_err(|_| "forward initialization task failed")?
                    })
                    .await?
                    .clone();
                let site = site.cached_endpoint(
                    &self.endpoint_name,
                    &self.endpoint_limits,
                    self.resources.buffers.clone(),
                    self.resources.tunnels.clone(),
                )?;
                let mut sanitized = head.clone();
                sanitized.binding = None;
                sanitized
                    .headers
                    .retain(|(name, _)| !ingress::is_proxy_header(name));
                return Ok(Plan::Forward(sanitized, site, lease));
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
        let Some(permit) = self.resources.tunnel(Some(tunnel.principal())) else {
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
        tls.current()?;
        // DNS ownership is independent of the requested service port. Resolve
        // the shared domain once, then clone the completed deny set into views.
        let primary = config.effective_listeners().remove(0);
        if let Ok(Ok(addresses)) = tokio::time::timeout(
            Duration::from_secs(5),
            crate::resolve::lookup(config.domain.as_str(), primary.listener.tcp.port()),
        )
        .await
        {
            app.egress.own.extend(addresses.take(32).map(|a| a.ip()));
        }
        let connections = app.resources.connections.clone();
        let stats = app.stats.clone();
        let mut endpoints = Vec::new();
        for (index, endpoint) in config.effective_listeners().iter().enumerate() {
            let local_app = if config.listeners.is_empty() {
                None
            } else {
                Some(Arc::new(app.endpoint(index, endpoint)?))
            };
            let bind = &endpoint.listener;
            let tcp = if bind.h1 || bind.h2 {
                Some(congestion::listen(
                    bind.tcp,
                    config.transport.tcp_congestion,
                )?)
            } else {
                None
            };
            let udp = if bind.h3 {
                Some(congestion::listen_udp(bind.udp)?)
            } else {
                None
            };
            let redirect = bind
                .http_redirect
                .map(|a| congestion::listen(a, config.transport.tcp_congestion))
                .transpose()?;
            endpoints.push((local_app, tcp, udp, redirect));
        }
        // No driver starts until every bind succeeds. Any error above drops all
        // prior sockets and contexts; ACME/TLS state is never rolled back.
        let (primary, tcp, udp, redirect) = endpoints.remove(0);
        let app = primary.unwrap_or_else(|| Arc::new(app));
        let additional = endpoints
            .into_iter()
            .map(|(app, tcp, udp, redirect)| EndpointNetwork {
                app: app.expect("multiple listeners have local state"),
                tcp,
                udp,
                redirect,
            })
            .collect();
        Ok(Network {
            app,
            tls,
            tcp,
            udp,
            redirect,
            additional,
            connections,
            config,
            stats,
        })
    }
}
struct EndpointNetwork {
    app: Arc<App>,
    tcp: Option<TcpListener>,
    udp: Option<UdpSocket>,
    redirect: Option<TcpListener>,
}
pub type ListenerAddress = (
    String,
    Option<std::net::SocketAddr>,
    Option<std::net::SocketAddr>,
);

/// All endpoint sockets bind transactionally before accepting traffic.
pub struct Network {
    app: Arc<App>,
    tls: tls::Slot,
    tcp: Option<TcpListener>,
    udp: Option<UdpSocket>,
    redirect: Option<TcpListener>,
    additional: Vec<EndpointNetwork>,
    connections: Budget,
    config: Arc<Config>,
    pub stats: Arc<Stats>,
}
impl Network {
    pub async fn bind(config: Config) -> Result<Self> {
        Prepared::load(Arc::new(config)).await?.bind().await
    }
    pub fn tcp_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self
            .tcp
            .as_ref()
            .ok_or("primary TCP listener disabled")?
            .local_addr()?)
    }
    pub fn udp_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self
            .udp
            .as_ref()
            .ok_or("primary UDP listener disabled")?
            .local_addr()?)
    }
    pub fn listener_addrs(&self) -> Result<Vec<ListenerAddress>> {
        let mut addresses = vec![(
            self.app.endpoint_name.clone(),
            self.tcp.as_ref().map(TcpListener::local_addr).transpose()?,
            self.udp.as_ref().map(UdpSocket::local_addr).transpose()?,
        )];
        for endpoint in &self.additional {
            addresses.push((
                endpoint.app.endpoint_name.clone(),
                endpoint
                    .tcp
                    .as_ref()
                    .map(TcpListener::local_addr)
                    .transpose()?,
                endpoint
                    .udp
                    .as_ref()
                    .map(UdpSocket::local_addr)
                    .transpose()?,
            ));
        }
        Ok(addresses)
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
            additional,
            connections,
            config,
            ..
        } = self;
        let (stop, receive) = watch::channel(false);
        let mut tasks = tokio::task::JoinSet::new();
        let reload = tls.clone();
        let reload_config = config.clone();
        let reload_stop = receive.clone();
        tasks.spawn(async move {
            tls::watch(reload_config, reload, reload_stop).await;
            Ok::<_, crate::Error>(false)
        });
        let mut endpoints = vec![EndpointNetwork {
            app: app.clone(),
            tcp,
            udp,
            redirect,
        }];
        endpoints.extend(additional);
        let mut apps = Vec::new();
        for endpoint in endpoints {
            let EndpointNetwork {
                app,
                tcp,
                udp,
                redirect,
            } = endpoint;
            let budget = if config.listeners.is_empty() {
                connections.clone()
            } else {
                app.resources.connections.clone()
            };
            apps.push(app.clone());
            if let Some(listener) = redirect {
                let config = config.clone();
                let budget = budget.clone();
                let stop = receive.clone();
                let rate = app.rate.clone();
                let https_port = tcp
                    .as_ref()
                    .expect("redirect requires TCP")
                    .local_addr()?
                    .port();
                tasks.spawn(async move {
                    redirect::serve(listener, config, budget, https_port, rate, stop).await?;
                    Ok(true)
                });
            }
            if let Some(socket) = udp {
                let app = app.clone();
                let tls = tls.clone();
                let stop = receive.clone();
                let budget = budget.clone();
                tasks.spawn(async move {
                    h3::serve(socket, app, tls, budget, stop).await?;
                    Ok(true)
                });
            }
            if let Some(listener) = tcp {
                let app = app.clone();
                let tls = tls.clone();
                let stop = receive.clone();
                tasks.spawn(async move {
                    serve_tcp(listener, app, tls, budget, stop).await?;
                    Ok(true)
                });
            }
        }
        let result = loop {
            tokio::select! {
                _=crate::runtime::wait_stop(&mut shutdown)=>break Ok(()),
                result=tasks.join_next()=>match result {
                    Some(Ok(Ok(false)))=>{},
                    Some(Ok(Ok(true)))=>break Err("listener driver stopped unexpectedly".into()),
                    Some(Ok(Err(error)))=>break Err(error),
                    Some(Err(error))=>break Err(error.into()),
                    None=>break Err("all network drivers stopped unexpectedly".into()),
                }
            }
        };
        let _ = stop.send(true);
        for app in &apps {
            app.site.stop_bridge();
        }
        app.forwards.clear().await;
        let grace = apps
            .iter()
            .map(|app| app.graceful)
            .max()
            .unwrap_or(Duration::from_secs(config.limits.graceful_timeout_secs));
        let _ =
            tokio::time::timeout(grace, async { while tasks.join_next().await.is_some() {} }).await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    }
}
async fn serve_tcp(
    listener: TcpListener,
    app: Arc<App>,
    tls: tls::Slot,
    connections: Budget,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    let result = loop {
        tokio::select! {
            _=crate::runtime::wait_stop(&mut stop)=>break Ok(()),
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            accepted=listener.accept()=>match accepted {
                Ok((socket,_))=>{let Some(permit)=connections.acquire() else {drop(socket);continue;};let app=app.clone();let tls=tls.clone();let stop=stop.clone();tasks.spawn(async move {let _permit=permit;let _=h2::serve(socket,app,tls,stop).await;});},
                Err(error)=>break Err(error.into()),
            }
        }
    };
    let _ = tokio::time::timeout(app.graceful, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
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
    config.validate()?;
    if !config.listeners.is_empty() {
        let mut lines = vec![format!(
            "global_max_connections={}\nglobal_max_streams={}\nglobal_receive_budget_bytes={}\nglobal_buffer_budget_bytes={}\napplication_buffers=separate_from_wire_credit\ntcp_congestion_effective={}\nquic_pacing=quiche_send_time",
            config.limits.max_connections,
            config.limits.max_streams,
            config.limits.max_total_receive_bytes,
            config.limits.max_total_buffer_bytes,
            congestion::effective(config.transport.tcp_congestion)?,
        )];
        for endpoint in config.effective_listeners() {
            let limits = endpoint.limits.as_ref().expect("effective limits");
            let profile = TransportProfile::for_endpoint(config, &endpoint)?;
            lines.push(format!(
                "listener={}\nh1={}\nh2={}\nh3={}\nmax_connections={}\nmax_streams={}\nh2_initial_stream_receive_bytes={}\nh2_connection_receive_bytes={}\nh3_initial_stream_receive_bytes={}\nh3_max_stream_receive_bytes={}\nh3_connection_receive_bytes={}\nquic_control_reserve_bytes={}\nendpoint_receive_budget_bytes={}\nendpoint_buffer_budget_bytes={}\nhandshake_timeout_secs={}\nconnect_timeout_secs={}\nidle_timeout_secs={}\nbandwidth_bytes_per_sec={}",
                endpoint.name, endpoint.listener.h1, endpoint.listener.h2, endpoint.listener.h3,
                limits.max_connections, limits.max_streams,
                limits.max_early_data_bytes.min(profile.stream_window() as usize), profile.connection_window(),
                limits.max_early_data_bytes.min(profile.h3_stream_window() as usize), profile.h3_stream_window(), profile.h3_connection_window(),
                profile.h3_control_reserve(), limits.max_total_receive_bytes, limits.max_total_buffer_bytes,
                endpoint.handshake_timeout_secs, limits.connect_timeout_secs, limits.idle_timeout_secs,
                endpoint.bandwidth_bytes_per_sec.map_or_else(|| "unlimited".to_owned(), |n| n.to_string()),
            ));
        }
        return Ok(lines.join("\n"));
    }
    let profile = TransportProfile::from_config(config)?;
    let initial = config
        .limits
        .max_early_data_bytes
        .min(profile.stream_window() as usize);
    let capacity = config
        .limits
        .max_connections
        .min(config.limits.max_total_receive_bytes / profile.connection_window() as usize);
    Ok(format!(
        "receive_connection_capacity={capacity}\nwaiting_request_capacity={}\nactive_tunnel_capacity={}\nper_user_tunnel_capacity={}\napplication_buffer_pool_bytes={}\nquic_control_reserve_bytes={}\napplication_buffers=separate_from_wire_credit\ntcp_congestion_effective={}\ntcp_socket_buffers=system_managed\nquic_pacing=quiche_send_time\nh2_initial_stream_receive_bytes={initial}\nh3_initial_stream_receive_bytes={}\nh3_max_stream_receive_bytes={}\nconnection_receive_bytes={}\ntotal_receive_budget_bytes={}",
        config
            .limits
            .max_pending_requests
            .min(config.limits.max_streams.saturating_mul(2)),
        config.limits.max_streams,
        config
            .limits
            .max_tunnels_per_user
            .min(config.limits.max_streams),
        config.limits.max_total_buffer_bytes,
        profile.h3_control_reserve(),
        congestion::effective(config.transport.tcp_congestion)?,
        initial.min(profile.h3_stream_window() as usize),
        profile.h3_stream_window(),
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
