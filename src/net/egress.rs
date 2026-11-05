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
    #[cfg(test)]
    pub test_target: Option<SocketAddr>,
    #[cfg(test)]
    pub test_delay: Option<Duration>,
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
            #[cfg(test)]
            test_target: None,
            #[cfg(test)]
            test_delay: None,
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
        #[cfg(test)]
        if let Some(delay) = self.test_delay {
            tokio::time::sleep(delay).await;
        }
        #[cfg(test)]
        if let Some(address) = self.test_target {
            self.stats.dials.fetch_add(1, Ordering::Relaxed);
            let socket = TcpStream::connect(address).await.map_err(|_| 502u16)?;
            socket.set_nodelay(true).map_err(|_| 502u16)?;
            return Ok(Stream::Plain(socket));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn single_candidate_keeps_socket_policy_and_errors() {
        let open = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = open.local_addr().unwrap();
        let stats = Arc::new(Stats::default());
        let algorithm = moon_naive_core::config::TcpCongestion::System;
        let stream = connect_candidates(vec![address], stats.clone(), algorithm)
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), address);
        assert!(stream.nodelay().unwrap());
        let (accepted, _) = open.accept().await.unwrap();
        drop((stream, accepted, open));
        assert_eq!(
            connect_candidates(vec![address], stats.clone(), algorithm)
                .await
                .unwrap_err(),
            502
        );
        assert_eq!(stats.dials.load(Ordering::Relaxed), 2);
        assert_eq!(
            connect_candidates(vec![], stats.clone(), algorithm)
                .await
                .unwrap_err(),
            502
        );
        assert_eq!(stats.dials.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    #[ignore = "release latency benchmark; run separately with --nocapture --test-threads=1"]
    async fn benchmark_single_address_dial() {
        const SAMPLES: usize = 512;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..SAMPLES {
                drop(listener.accept().await.unwrap());
            }
        });
        let stats = Arc::new(Stats::default());
        let mut samples = Vec::new();
        for _ in 0..SAMPLES {
            let start = std::time::Instant::now();
            let stream = connect_candidates(
                vec![address],
                stats.clone(),
                moon_naive_core::config::TcpCongestion::System,
            )
            .await
            .unwrap();
            samples.push(start.elapsed().as_secs_f64() * 1_000_000.);
            drop(stream);
        }
        server.await.unwrap();
        assert_eq!(stats.dials.load(Ordering::Relaxed), SAMPLES);
        samples.sort_by(f64::total_cmp);
        eprintln!(
            "PERF {{\"case\":\"single_address_dial\",\"samples\":{SAMPLES},\"median_us\":{},\"p95_us\":{}}}",
            samples[SAMPLES / 2],
            samples[SAMPLES * 95 / 100]
        );
    }

    #[tokio::test]
    async fn failed_candidate_falls_back_and_races_are_cancelled() {
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = closed.local_addr().unwrap();
        drop(closed);
        let open = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stats = Arc::new(Stats::default());
        let stream = tokio::time::timeout(
            Duration::from_secs(2),
            connect_candidates(
                vec![address, open.local_addr().unwrap()],
                stats.clone(),
                moon_naive_core::config::TcpCongestion::System,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), open.local_addr().unwrap());
        assert_eq!(stats.dials.load(Ordering::Relaxed), 2);
    }
}
