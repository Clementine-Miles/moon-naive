//! Fixed configuration origins; async bounded DNS, Pingora peers/pools and passive failover.
use super::{Result, Website};
use crate::net::egress::Egress;
use moon_naive_core::policy::{Authority, allows_ip};
use moon_naive_core::{config::Config, website::Upstream};
use pingora_core::{
    connectors::L4Connect,
    protocols::l4::{stream::Stream as L4, virt::VirtualSocketStream},
};
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
    public_addresses: Vec<std::net::IpAddr>,
    tcp_congestion: moon_naive_core::config::TcpCongestion,
    group: u64,
}
struct Origin {
    host: String,
    port: u16,
    tls: bool,
    ca: Option<Arc<Box<[boring::x509::X509]>>>,
    addresses: Mutex<Option<(Instant, Vec<SocketAddr>)>>,
    failed_until: std::sync::Mutex<Option<Instant>>,
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
                    failed_until: std::sync::Mutex::new(None),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            config: config.clone(),
            origins,
            next: AtomicUsize::new(0),
            frontend: app.listener.tcp,
            node_domain: app.domain.clone(),
            public_addresses: app.listener.public_addresses.clone(),
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
    pub fn selection(&self) -> usize {
        self.next.fetch_add(1, Ordering::Relaxed) % self.origins.len()
    }
    pub fn len(&self) -> usize {
        self.origins.len()
    }
    pub fn failed(&self, index: usize) {
        if let Ok(mut slot) = self.origins[index].failed_until.lock() {
            *slot = Some(Instant::now() + Duration::from_secs(5));
        }
    }
    pub fn succeeded(&self, index: usize) {
        if let Ok(mut slot) = self.origins[index].failed_until.lock() {
            *slot = None;
        }
    }
    pub async fn peer(
        &self,
        start: usize,
        config: &Website,
    ) -> pingora_core::Result<(usize, HttpPeer)> {
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(config.connect_timeout_secs);
        let mut last = pingora_core::Error::new_up(pingora_core::ErrorType::ConnectError);
        for n in 0..self.origins.len() {
            let index = (start + n) % self.origins.len();
            if self.origins[index]
                .failed_until
                .lock()
                .map_err(|_| pingora_core::Error::new_str("origin health lock poisoned"))?
                .is_some_and(|until| until > Instant::now())
            {
                continue;
            }
            match tokio::time::timeout_at(deadline, self.peer_one(index, config)).await {
                Ok(Ok(peer)) => return Ok(peer),
                Ok(Err(error)) => {
                    self.failed(index);
                    last = error;
                }
                Err(_) => {
                    return Err(pingora_core::Error::new_up(
                        pingora_core::ErrorType::ConnectTimedout,
                    ));
                }
            }
        }
        Err(last)
    }
    async fn peer_one(
        &self,
        index: usize,
        config: &Website,
    ) -> pingora_core::Result<(usize, HttpPeer)> {
        let origin = &self.origins[index];
        let mut cache = origin.addresses.lock().await;
        if cache
            .as_ref()
            .is_none_or(|(until, _)| *until <= Instant::now())
        {
            let addresses = tokio::time::timeout(
                Duration::from_secs(config.connect_timeout_secs).min(Duration::from_secs(2)),
                crate::resolve::lookup(origin.host.as_str(), origin.port),
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
        let addresses: Vec<_> = cache
            .as_ref()
            .expect("resolved addresses")
            .1
            .iter()
            .copied()
            .filter(|address| {
                !(address.port() == self.frontend.port()
                    && (super::super::egress::same_ip(address.ip(), self.frontend.ip())
                        || super::super::egress::is_local(address.ip())
                        || self
                            .public_addresses
                            .iter()
                            .any(|ip| super::super::egress::same_ip(*ip, address.ip()))
                        || origin.host.eq_ignore_ascii_case(&self.node_domain)))
            })
            .collect();
        let address = *addresses
            .first()
            .ok_or_else(|| pingora_core::Error::new_up(pingora_core::ErrorType::ConnectError))?;
        let sni = self
            .config
            .tls_server_name
            .as_deref()
            .unwrap_or(&origin.host)
            .to_owned();
        let mut peer = HttpPeer::new(address, origin.tls, sni);
        peer.group_key = self.group;
        peer.options.custom_l4 = Some(Arc::new(ResolvedConnector {
            addresses,
            algorithm: self.tcp_congestion,
            deadline: Duration::from_secs(config.connect_timeout_secs),
            next: AtomicUsize::new(0),
        }));
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
        configure_peer(&mut peer, config);
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

/// Only configured origins reach this connector. Do not apply the public-target
/// policy here: explicitly configured private website origins are supported.
#[derive(Debug)]
struct ResolvedConnector {
    addresses: Vec<SocketAddr>,
    algorithm: moon_naive_core::config::TcpCongestion,
    deadline: Duration,
    next: AtomicUsize,
}
#[async_trait::async_trait]
impl pingora_core::connectors::L4Connect for ResolvedConnector {
    fn connection_attempts(&self) -> usize {
        self.addresses.len()
    }
    fn attempt_timeout(&self) -> Option<Duration> {
        Some(self.deadline.min(Duration::from_secs(3)))
    }
    async fn connect(
        &self,
        _addr: &pingora_core::protocols::l4::socket::SocketAddr,
    ) -> pingora_core::Result<pingora_core::protocols::l4::stream::Stream> {
        let mut candidates = self.addresses.clone();
        let len = candidates.len();
        candidates.rotate_left(self.next.fetch_add(1, Ordering::Relaxed) % len);
        let socket = tokio::time::timeout(
            self.deadline,
            super::super::egress::connect_candidates(candidates, Arc::default(), self.algorithm),
        )
        .await
        .map_err(|_| pingora_core::Error::new_up(pingora_core::ErrorType::ConnectTimedout))?
        .map_err(|_| pingora_core::Error::new_up(pingora_core::ErrorType::ConnectError))?;
        Ok(socket.into())
    }
}

pub(super) struct ForwardOrigin {
    authority: Authority,
    tls: bool,
    user: usize,
    egress: Egress,
}
impl ForwardOrigin {
    pub fn new(origin: &str, user: usize, egress: Egress) -> Result<Self> {
        let uri: http::Uri = origin.parse()?;
        let host = uri.host().ok_or("forward host missing")?;
        let tls = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err("unsupported forward scheme".into()),
        };
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        let authority = Authority::parse(&format!("{host}:{port}"))?;
        Ok(Self {
            authority,
            tls,
            user,
            egress,
        })
    }
    pub async fn peer(&self, config: &Website) -> pingora_core::Result<Box<HttpPeer>> {
        let fail = || pingora_core::Error::new(pingora_core::ErrorType::HTTPStatus(502));
        if self.egress.is_self(&self.authority.host) {
            return Err(fail());
        }
        let addresses = tokio::time::timeout(
            Duration::from_secs(config.connect_timeout_secs),
            crate::resolve::lookup(self.authority.host.as_str(), self.authority.port),
        )
        .await
        .map_err(|_| fail())?
        .map_err(|_| fail())?
        .take(33)
        .collect::<Vec<_>>();
        if addresses.len() > 32 {
            return Err(fail());
        }
        let addresses: Vec<_> = addresses
            .into_iter()
            .filter(|a| {
                allows_ip(a.ip(), &self.egress.own) && !super::super::egress::is_local(a.ip())
            })
            .collect();
        let addr = *addresses.first().ok_or_else(fail)?;
        let mut peer = HttpPeer::new(addr, self.tls, self.authority.host.clone());
        peer.group_key = self.user as u64 + 1;
        peer.options.custom_l4 = Some(Arc::new(ForwardConnector {
            egress: self.egress.clone(),
            addresses,
            next: std::sync::atomic::AtomicUsize::new(0),
        }));
        if self.tls {
            peer.options.ca = self.egress.roots.get().await.map_err(|_| fail())?;
        }
        peer.options.alpn = if self.tls {
            pingora_core::protocols::ALPN::H2H1
        } else {
            pingora_core::protocols::ALPN::H1
        };
        configure_peer(&mut peer, config);
        Ok(Box::new(peer))
    }
}
struct ForwardConnector {
    egress: Egress,
    addresses: Vec<std::net::SocketAddr>,
    next: std::sync::atomic::AtomicUsize,
}
impl std::fmt::Debug for ForwardConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CheckedEgress")
    }
}
#[async_trait::async_trait]
impl L4Connect for ForwardConnector {
    fn connection_attempts(&self) -> usize {
        self.addresses.len()
    }
    fn attempt_timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(3))
    }
    async fn connect(
        &self,
        _addr: &pingora_core::protocols::l4::socket::SocketAddr,
    ) -> pingora_core::Result<L4> {
        let mut addresses = self.addresses.clone();
        let len = addresses.len();
        addresses.rotate_left(self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % len);
        let stream: crate::net::egress::Stream = self
            .egress
            .dial_candidates(addresses)
            .await
            .map_err(|_| pingora_core::Error::new(pingora_core::ErrorType::ConnectError))?;
        Ok(L4::from(VirtualSocketStream::new(Box::new(stream))))
    }
}

fn configure_peer(peer: &mut HttpPeer, config: &Website) {
    peer.options.connection_timeout = Some(Duration::from_secs(config.connect_timeout_secs));
    peer.options.total_connection_timeout = peer.options.connection_timeout;
    peer.options.read_timeout = Some(Duration::from_secs(config.read_timeout_secs));
    peer.options.write_timeout = Some(Duration::from_secs(config.write_timeout_secs));
    peer.options.idle_timeout = Some(Duration::from_secs(config.upstream_idle_secs));
    peer.options.verify_cert = true;
    peer.options.verify_hostname = true;
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_core::upstreams::peer::Peer;
    #[tokio::test]
    async fn tcp_success_with_stalled_tls_advances_to_next_candidate() {
        let (acceptor, ca) = crate::net::tests::test_origin_tls_material();
        let roots = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(roots.path(), ca).unwrap();
        let bad = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bad_addr = bad.local_addr().unwrap();
        let good_addr = good.local_addr().unwrap();
        let stalled = tokio::spawn(async move {
            let (_socket, _) = bad.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let working = tokio::spawn(async move {
            let (socket, _) = good.accept().await.unwrap();
            let _tls = tokio_boring::accept(&acceptor, socket).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let mut config = Config::parse(include_str!("../../../config.example.toml")).unwrap();
        config.website.upstreams[0].origins = vec![format!("https://{bad_addr}")];
        config.website.upstreams[0].tls_server_name = Some("proxy.example.test".into());
        config.website.upstreams[0].ca_file = Some(roots.path().into());
        let pool = Pool::load(&config.website.upstreams[0], &config).unwrap();
        *pool.origins[0].addresses.lock().await = Some((
            Instant::now() + Duration::from_secs(60),
            vec![bad_addr, good_addr],
        ));
        let (_, mut peer) = pool.peer(0, &config.website).await.unwrap();
        peer.options.alpn = ALPN::H1;
        let connector = pingora_core::connectors::http::Connector::<()>::new(None);
        let session =
            tokio::time::timeout(Duration::from_secs(5), connector.get_http_session(&peer))
                .await
                .unwrap()
                .unwrap();
        assert!(matches!(
            session.0,
            pingora_core::protocols::http::client::HttpSession::H1(_)
        ));
        stalled.abort();
        working.await.unwrap();
    }
    #[tokio::test]
    async fn dns_failure_selects_backup_and_cools_failed_origin() {
        let mut config = Config::parse(include_str!("../../../config.example.toml")).unwrap();
        let backup = config.website.upstreams[0].origins[0].clone();
        config.website.upstreams[0].origins.push(backup);
        let mut pool = Pool::load(&config.website.upstreams[0], &config).unwrap();
        pool.origins[0].host = "bad\0host".into();
        *pool.origins[1].addresses.lock().await = Some((
            Instant::now() + Duration::from_secs(60),
            vec!["127.0.0.1:8080".parse().unwrap()],
        ));
        assert_eq!(pool.peer(0, &config.website).await.unwrap().0, 1);
        assert!(pool.origins[0].failed_until.lock().unwrap().is_some());
        assert_eq!(pool.peer(0, &config.website).await.unwrap().0, 1);
    }
    #[tokio::test]
    async fn one_origin_retains_all_candidates_before_any_request_is_sent() {
        let config = Config::parse(include_str!("../../../config.example.toml")).unwrap();
        let pool = Pool::load(&config.website.upstreams[0], &config).unwrap();
        let refused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = refused.local_addr().unwrap();
        drop(refused);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = listener.local_addr().unwrap();
        *pool.origins[0].addresses.lock().await =
            Some((Instant::now() + Duration::from_secs(60), vec![dead, live]));
        let (index, peer) = pool.peer(pool.selection(), &config.website).await.unwrap();
        assert_eq!(index, 0);
        let stream = peer
            .options
            .custom_l4
            .as_ref()
            .unwrap()
            .connect(peer.address())
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        drop((stream, accepted));
    }
}
