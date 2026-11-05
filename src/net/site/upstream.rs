//! Fixed configuration origins; async bounded DNS, Pingora peers/pools and passive failover.
use super::{Result, Website};
use moon_naive_core::{config::Config, website::Upstream};
use pingora_core::{
    protocols::ALPN,
    upstreams::peer::{HttpPeer, HttpUpstreamRequestPolicy},
};
use std::{
    io::Read,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
pub(super) struct Pool {
    pub config: Upstream,
    origins: Vec<Origin>,
    next: AtomicUsize,
    frontend: SocketAddr,
    node_domain: String,
    tcp_congestion: moon_naive_core::config::TcpCongestion,
    group: u64,
}
struct Origin {
    host: String,
    port: u16,
    tls: bool,
    ca: Option<Arc<Box<[boring::x509::X509]>>>,
    addresses: Mutex<Option<(Instant, Vec<SocketAddr>)>>,
    failed_until: Mutex<Option<Instant>>,
}
impl Pool {
    pub fn load(config: &Upstream, app: &Config) -> Result<Self> {
        let ca = if let Some(path) = &config.ca_file {
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 1024 * 1024 {
                return Err("website CA bundle too large".into());
            }
            let certs = boring::x509::X509::stack_from_pem(&bytes)?;
            if certs.is_empty() {
                return Err("empty website CA bundle".into());
            }
            Some(Arc::new(certs.into_boxed_slice()))
        } else {
            None
        };
        let origins = config
            .origins
            .iter()
            .map(|value| {
                let uri = value.parse::<http::Uri>().expect("validated origin");
                let host = uri
                    .host()
                    .expect("validated host")
                    .trim_matches(['[', ']'])
                    .to_owned();
                let tls = uri.scheme_str() == Some("https");
                let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
                if host.eq_ignore_ascii_case(&app.domain) && port == app.listener.tcp.port() {
                    return Err("website origin points at frontend".into());
                }
                Ok(Origin {
                    host,
                    port,
                    tls,
                    ca: ca.clone(),
                    addresses: Mutex::new(None),
                    failed_until: Mutex::new(None),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            config: config.clone(),
            origins,
            next: AtomicUsize::new(0),
            frontend: app.listener.tcp,
            node_domain: app.domain.clone(),
            tcp_congestion: app.transport.tcp_congestion,
            group: app
                .website
                .upstreams
                .iter()
                .position(|p| p.name == config.name)
                .expect("validated pool") as u64
                + 1,
        })
    }
    pub fn len(&self) -> usize {
        self.origins.len()
    }
    pub fn failed(&self, index: usize) {
        if let Ok(mut slot) = self.origins[index].failed_until.try_lock() {
            *slot = Some(Instant::now() + Duration::from_secs(5));
        }
    }
    pub fn succeeded(&self, index: usize) {
        if let Ok(mut slot) = self.origins[index].failed_until.try_lock() {
            *slot = None;
        }
    }
    pub async fn peer(
        &self,
        attempt: usize,
        config: &Website,
    ) -> pingora_core::Result<(usize, HttpPeer)> {
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let mut index = start % self.origins.len();
        for n in 0..self.origins.len() {
            let candidate = (start + n) % self.origins.len();
            let failed = self.origins[candidate].failed_until.lock().await;
            if failed.is_none_or(|until| until <= Instant::now()) {
                index = candidate;
                break;
            }
        }
        let origin = &self.origins[index];
        let mut cache = origin.addresses.lock().await;
        if cache
            .as_ref()
            .is_none_or(|(until, _)| *until <= Instant::now())
        {
            let addresses = tokio::time::timeout(
                Duration::from_secs(config.connect_timeout_secs),
                tokio::net::lookup_host((origin.host.as_str(), origin.port)),
            )
            .await
            .map_err(|_| pingora_core::Error::new_up(pingora_core::ErrorType::ConnectTimedout))?
            .map_err(|e| {
                pingora_core::Error::because(
                    pingora_core::ErrorType::ConnectError,
                    "website DNS",
                    e,
                )
            })?
            .take(33)
            .collect::<Vec<_>>();
            if addresses.is_empty() || addresses.len() > 32 {
                return Err(pingora_core::Error::new_up(
                    pingora_core::ErrorType::ConnectError,
                ));
            }
            // Only fixed origins can reach this resolver; request authority is never a target.
            *cache = Some((
                Instant::now() + Duration::from_secs(config.dns_ttl_secs),
                addresses,
            ));
        }
        let addresses = &cache.as_ref().expect("resolved addresses").1;
        let address = addresses[(start + attempt) % addresses.len()];
        if address.port() == self.frontend.port()
            && (address.ip() == self.frontend.ip()
                || address.ip().is_loopback()
                || origin.host.eq_ignore_ascii_case(&self.node_domain))
        {
            return Err(pingora_core::Error::new_up(
                pingora_core::ErrorType::ConnectError,
            ));
        }
        let sni = self
            .config
            .tls_server_name
            .as_deref()
            .unwrap_or(&origin.host)
            .to_owned();
        let mut peer = HttpPeer::new(address, origin.tls, sni);
        peer.group_key = self.group;
        let algorithm = self.tcp_congestion;
        peer.options.upstream_tcp_sock_tweak_hook = Some(Arc::new(move |socket| {
            super::super::congestion::apply_connecting(socket, algorithm).map_err(|e| {
                pingora_core::Error::because(
                    pingora_core::ErrorType::ConnectError,
                    "website TCP congestion",
                    e,
                )
            })
        }));
        peer.options.connection_timeout = Some(Duration::from_secs(config.connect_timeout_secs));
        peer.options.total_connection_timeout = peer.options.connection_timeout;
        peer.options.read_timeout = Some(Duration::from_secs(config.read_timeout_secs));
        peer.options.write_timeout = Some(Duration::from_secs(config.write_timeout_secs));
        peer.options.idle_timeout = Some(Duration::from_secs(config.upstream_idle_secs));
        peer.options.verify_cert = true;
        peer.options.verify_hostname = true;
        peer.options.ca = origin.ca.clone();
        peer.options.alpn = if origin.tls && self.config.http2 {
            ALPN::H2H1
        } else {
            ALPN::H1
        };
        peer.options.max_h2_streams = 100;
        peer.options.h2_stream_window_size = Some(256 * 1024);
        peer.options.h2_connection_window_size = Some(1024 * 1024);
        peer.options.http_upstream_request_policy = HttpUpstreamRequestPolicy::standard();
        Ok((index, peer))
    }
}
pub(super) fn clean_response(header: &mut pingora_http::ResponseHeader) {
    let upgrade = header.status == http::StatusCode::SWITCHING_PROTOCOLS;
    let nominated = header
        .headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|s| s.trim().to_owned())
        .collect::<Vec<_>>();
    for name in nominated {
        if !upgrade || !name.eq_ignore_ascii_case("upgrade") {
            header.remove_header(&name);
        }
    }
    let metadata = header
        .headers
        .keys()
        .filter(|name| super::is_proxy_header(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    for name in metadata {
        header.remove_header(&name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "alt-svc",
        "server",
        "x-powered-by",
    ] {
        if !upgrade || !["connection", "upgrade"].contains(&name) {
            header.remove_header(name);
        }
    }
}
