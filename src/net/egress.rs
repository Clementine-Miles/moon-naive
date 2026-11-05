use super::outbound::Stream;
use super::{Config, Stats};
use moon_naive_core::policy::{Authority, allows_ip};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::net::TcpStream;

#[derive(Clone)]
pub(super) struct Egress {
    timeout: Duration,
    pub own: Vec<IpAddr>,
    domain: String,
    stats: Arc<Stats>,
    tcp_congestion: moon_naive_core::config::TcpCongestion,
    upstream: Option<Arc<super::outbound::NextHop>>,
    pub roots: crate::trust::Roots,
}
impl Egress {
    pub fn new(config: &Config, stats: Arc<Stats>) -> super::Result<Self> {
        Ok(Self {
            timeout: Duration::from_secs(config.limits.connect_timeout_secs),
            own: vec![config.listener.tcp.ip(), config.listener.udp.ip()],
            domain: config.domain.clone(),
            stats,
            tcp_congestion: config.transport.tcp_congestion,
            upstream: config
                .proxy
                .upstream
                .clone()
                .map(super::outbound::NextHop::new)
                .transpose()?
                .map(Arc::new),
            roots: crate::trust::Roots::new(crate::trust::system_ca_file()),
        })
    }
    pub fn is_self(&self, host: &str) -> bool {
        host.eq_ignore_ascii_case(&self.domain)
    }
    pub async fn dial(&self, target: &Authority) -> Result<Stream, u16> {
        let stream = tokio::time::timeout(self.timeout, self.dial_inner(target))
            .await
            .map_err(|_| 504u16)??;
        if let Some(tcp) = stream.tcp() {
            super::congestion::apply(tcp, self.tcp_congestion).map_err(|_| 502u16)?;
        }
        Ok(stream)
    }
    async fn dial_inner(&self, target: &Authority) -> Result<Stream, u16> {
        if target.host.eq_ignore_ascii_case(&self.domain) {
            return Err(403);
        }
        let addresses: Vec<SocketAddr> = if let Ok(ip) = target.host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, target.port)]
        } else {
            self.stats.resolutions.fetch_add(1, Ordering::Relaxed);
            tokio::net::lookup_host((target.host.as_str(), target.port))
                .await
                .map_err(|_| 502u16)?
                .take(33)
                .collect()
        };
        if addresses.len() > 32 {
            return Err(502);
        }
        let addresses: Vec<_> = addresses
            .into_iter()
            .filter(|a| allows_ip(a.ip(), &self.own))
            .collect();
        if addresses.is_empty() {
            return Err(403);
        }
        if let Some(upstream) = &self.upstream {
            let proxy = &upstream.authority;
            let proxy_addresses = tokio::net::lookup_host((proxy.host.as_str(), proxy.port))
                .await
                .map_err(|_| 502u16)?
                .take(33)
                .collect::<Vec<_>>();
            if proxy_addresses.is_empty()
                || proxy_addresses.len() > 32
                || proxy.host.eq_ignore_ascii_case(&self.domain)
                || proxy_addresses.iter().any(|a| self.own.contains(&a.ip()))
            {
                return Err(502);
            }
            for address in addresses {
                let socket = connect_candidates(
                    proxy_addresses.clone(),
                    self.stats.clone(),
                    self.tcp_congestion,
                )
                .await?;
                super::congestion::apply(&socket, self.tcp_congestion).map_err(|_| 502u16)?;
                if let Ok(stream) = upstream.handshake(socket, address).await {
                    return Ok(stream);
                }
            }
            Err(502)
        } else {
            connect_candidates(addresses, self.stats.clone(), self.tcp_congestion)
                .await
                .map(Stream::Plain)
        }
    }
}

/// At most two in-flight connects. Alternate families and stagger the second
/// attempt; dropping this future cancels the sockets together with admission.
async fn connect_candidates(
    addresses: Vec<SocketAddr>,
    stats: Arc<Stats>,
    algorithm: moon_naive_core::config::TcpCongestion,
) -> Result<TcpStream, u16> {
    let first_v6 = addresses.first().is_some_and(SocketAddr::is_ipv6);
    let (mut v6, mut v4): (std::collections::VecDeque<_>, std::collections::VecDeque<_>) =
        addresses.into_iter().partition(SocketAddr::is_ipv6);
    let mut ordered = std::collections::VecDeque::new();
    let mut next_v6 = first_v6;
    while !v6.is_empty() || !v4.is_empty() {
        let address = if next_v6 {
            v6.pop_front().or_else(|| v4.pop_front())
        } else {
            v4.pop_front().or_else(|| v6.pop_front())
        };
        ordered.extend(address);
        next_v6 = !next_v6;
    }
    let mut tasks = tokio::task::JoinSet::new();
    let mut next = tokio::time::Instant::now();
    loop {
        if tasks.is_empty() && ordered.is_empty() {
            return Err(502);
        }
        if !ordered.is_empty()
            && (tasks.is_empty() || tasks.len() < 2 && tokio::time::Instant::now() >= next)
        {
            let address = ordered.pop_front().unwrap();
            stats.dials.fetch_add(1, Ordering::Relaxed);
            tasks.spawn(async move {
                let socket = if address.is_ipv4() {
                    tokio::net::TcpSocket::new_v4()?
                } else {
                    tokio::net::TcpSocket::new_v6()?
                };
                super::congestion::apply_connecting(&socket, algorithm)
                    .map_err(|_| std::io::Error::other("TCP congestion unavailable"))?;
                socket.connect(address).await
            });
            next = tokio::time::Instant::now() + Duration::from_millis(250);
        }
        tokio::select! {
            result=tasks.join_next(),if !tasks.is_empty()=>{if let Some(Ok(Ok(stream)))=result {stream.set_nodelay(true).map_err(|_|502u16)?;return Ok(stream);}},
            _=tokio::time::sleep_until(next),if tasks.len()<2 && !ordered.is_empty()=>{},
        }
    }
}
