use super::{Config, Result, Stats};
use base64::Engine;
use moon_naive_core::config::{ProxyKind, ProxyUpstream};
use moon_naive_core::policy::{Authority, allows_ip};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

pub(super) fn same_ip(a: IpAddr, b: IpAddr) -> bool {
    fn normalize(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        }
    }
    normalize(a) == normalize(b)
}
pub(super) fn is_local(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    };
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    // UDP connect selects a route/source without transmitting a datagram. Unlike
    // a successful bind(), this does not classify every address as local on a
    // host with ip_nonlocal_bind enabled.
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    std::net::UdpSocket::bind(bind).is_ok_and(|socket| {
        socket.connect(SocketAddr::new(ip, 9)).is_ok()
            && socket
                .local_addr()
                .is_ok_and(|local| same_ip(local.ip(), ip))
    })
}

#[derive(Clone)]
pub(super) struct Egress {
    timeout: Duration,
    pub own: Vec<IpAddr>,
    domain: String,
    stats: Arc<Stats>,
    tcp_congestion: moon_naive_core::config::TcpCongestion,
    upstream: Option<Arc<super::egress::NextHop>>,
    pub roots: crate::trust::Roots,
}
impl Egress {
    pub fn new(config: &Config, stats: Arc<Stats>) -> super::Result<Self> {
        Ok(Self {
            timeout: Duration::from_secs(config.limits.connect_timeout_secs),
            own: [
                vec![config.listener.tcp.ip(), config.listener.udp.ip()],
                config.listener.public_addresses.clone(),
            ]
            .concat(),
            domain: config.domain.clone(),
            stats,
            tcp_congestion: config.transport.tcp_congestion,
            upstream: config
                .proxy
                .upstream
                .clone()
                .map(super::egress::NextHop::new)
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
            tokio::time::timeout(
                Duration::from_secs(2),
                crate::resolve::lookup(target.host.as_str(), target.port),
            )
            .await
            .map_err(|_| 504u16)?
            .map_err(|_| 502u16)?
            .take(33)
            .collect()
        };
        if addresses.len() > 32 {
            return Err(502);
        }
        let addresses: Vec<_> = addresses
            .into_iter()
            .filter(|a| allows_ip(a.ip(), &self.own) && !is_local(a.ip()))
            .collect();
        if addresses.is_empty() {
            return Err(403);
        }
        self.dial_addresses_inner(addresses).await
    }
    /// Already resolved concrete candidates; revalidate policy without DNS lookup.
    pub async fn dial_candidates(&self, addresses: Vec<SocketAddr>) -> Result<Stream, u16> {
        if addresses.is_empty() || addresses.len() > 32 {
            return Err(502);
        }

        let addresses = addresses
            .into_iter()
            .filter(|a| allows_ip(a.ip(), &self.own) && !is_local(a.ip()))
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(403);
        }
        tokio::time::timeout(self.timeout, self.dial_addresses_inner(addresses))
            .await
            .map_err(|_| 504u16)?
    }
    async fn dial_addresses_inner(&self, addresses: Vec<SocketAddr>) -> Result<Stream, u16> {
        if let Some(upstream) = &self.upstream {
            let proxy = &upstream.authority;
            let proxy_addresses = tokio::time::timeout(
                Duration::from_secs(2),
                crate::resolve::lookup(proxy.host.as_str(), proxy.port),
            )
            .await
            .map_err(|_| 504u16)?
            .map_err(|_| 502u16)?
            .take(33)
            .collect::<Vec<_>>();
            if proxy_addresses.is_empty()
                || proxy_addresses.len() > 32
                || proxy.host.eq_ignore_ascii_case(&self.domain)
                || proxy_addresses
                    .iter()
                    .any(|a| self.own.iter().any(|ip| same_ip(*ip, a.ip())))
            {
                return Err(502);
            }
            for address in addresses {
                for proxy_address in &proxy_addresses {
                    let Ok(socket) = connect_candidates(
                        vec![*proxy_address],
                        self.stats.clone(),
                        self.tcp_congestion,
                    )
                    .await
                    else {
                        continue;
                    };
                    if let Ok(Ok(stream)) = tokio::time::timeout(
                        Duration::from_secs(2),
                        upstream.handshake(socket, address),
                    )
                    .await
                    {
                        return Ok(stream);
                    }
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
pub(super) async fn connect_candidates(
    addresses: Vec<SocketAddr>,
    stats: Arc<Stats>,
    algorithm: moon_naive_core::config::TcpCongestion,
) -> Result<TcpStream, u16> {
    let stream = race_candidates(addresses, move |address| {
        let stats = stats.clone();
        async move {
            stats.dials.fetch_add(1, Ordering::Relaxed);
            let socket = if address.is_ipv4() {
                tokio::net::TcpSocket::new_v4()?
            } else {
                tokio::net::TcpSocket::new_v6()?
            };
            super::congestion::apply_connecting(&socket, algorithm)
                .map_err(|_| std::io::Error::other("TCP congestion unavailable"))?;
            socket.connect(address).await
        }
    })
    .await?;
    stream.set_nodelay(true).map_err(|_| 502u16)?;
    Ok(stream)
}
async fn race_candidates<T, F, Fut>(addresses: Vec<SocketAddr>, mut connect: F) -> Result<T, u16>
where
    T: Send + 'static,
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<T>> + Send + 'static,
{
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
            let attempt = connect(address);
            tasks.spawn(async move {
                tokio::time::timeout(Duration::from_secs(2), attempt)
                    .await
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
            });
            next = tokio::time::Instant::now() + Duration::from_millis(250);
        }
        tokio::select! {
            result=tasks.join_next(),if !tasks.is_empty()=>{if let Some(Ok(Ok(stream)))=result {return Ok(stream);}},
            _=tokio::time::sleep_until(next),if tasks.len()<2 && !ordered.is_empty()=>{},
        }
    }
}

#[derive(Debug)]
pub(crate) enum Stream {
    Plain(TcpStream),
    Tls(tokio_boring::SslStream<TcpStream>),
    Prefixed {
        stream: Box<Stream>,
        prefix: bytes::Bytes,
    },
    Upgrade {
        stream: pingora_core::protocols::Stream,
        prefix: bytes::Bytes,
    },
}
impl Stream {
    pub fn tcp(&self) -> Option<&TcpStream> {
        match self {
            Self::Plain(s) => Some(s),
            Self::Tls(s) => Some(s.get_ref()),
            Self::Prefixed { stream, .. } => stream.tcp(),
            Self::Upgrade { .. } => None,
        }
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
            Self::Prefixed { stream, prefix } => {
                if !prefix.is_empty() {
                    let n = prefix.len().min(buf.remaining());
                    buf.put_slice(&prefix.split_to(n));
                    Poll::Ready(Ok(()))
                } else {
                    Pin::new(stream).poll_read(cx, buf)
                }
            }
            Self::Upgrade { stream, prefix } => {
                if !prefix.is_empty() {
                    let n = prefix.len().min(buf.remaining());
                    buf.put_slice(&prefix.split_to(n));
                    Poll::Ready(Ok(()))
                } else {
                    Pin::new(stream).poll_read(cx, buf)
                }
            }
        }
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
            Self::Prefixed { stream, .. } => Pin::new(stream).poll_write(cx, buf),
            Self::Upgrade { stream, .. } => Pin::new(stream).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
            Self::Prefixed { stream, .. } => Pin::new(stream).poll_flush(cx),
            Self::Upgrade { stream, .. } => Pin::new(stream).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
            Self::Prefixed { stream, .. } => Pin::new(stream).poll_shutdown(cx),
            Self::Upgrade { stream, .. } => Pin::new(stream).poll_shutdown(cx),
        }
    }
}
impl pingora_core::protocols::l4::virt::VirtualSocket for Stream {
    fn set_socket_option(
        &self,
        opt: pingora_core::protocols::l4::virt::VirtualSockOpt,
    ) -> std::io::Result<()> {
        match opt {
            pingora_core::protocols::l4::virt::VirtualSockOpt::NoDelay => {
                self.tcp().map_or(Ok(()), |s| s.set_nodelay(true))
            }
            _ => Ok(()),
        }
    }
}
/// Fixed next-hop policy and TLS context, prepared once on App::load's blocking
/// worker. Every connection still gets a fresh SSL object and verifies its peer.
pub(super) struct NextHop {
    pub authority: moon_naive_core::policy::Authority,
    config: ProxyUpstream,
    tls: Option<boring::ssl::SslConnector>,
}
impl NextHop {
    pub fn new(config: ProxyUpstream) -> Result<Self> {
        let authority = moon_naive_core::policy::Authority::parse(&config.address)?;
        let tls = if config.kind == ProxyKind::Https {
            let mut connector = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())?;
            if let Some(ca) = config.ca_file.clone().or_else(crate::trust::system_ca_file) {
                connector.set_ca_file(ca)?;
            }
            connector.set_alpn_protos(b"\x08http/1.1")?;
            connector.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_2))?;
            Some(connector.build())
        } else {
            None
        };
        Ok(Self {
            authority,
            config,
            tls,
        })
    }
    pub async fn handshake(&self, socket: TcpStream, target: SocketAddr) -> Result<Stream> {
        let config = &self.config;
        let mut stream = if let Some(connector) = &self.tls {
            Stream::Tls(
                tokio_boring::connect(
                    connector.configure()?,
                    config
                        .tls_server_name
                        .as_deref()
                        .unwrap_or(&self.authority.host),
                    socket,
                )
                .await?,
            )
        } else {
            Stream::Plain(socket)
        };
        if config.kind == ProxyKind::Socks5 {
            socks(&mut stream, config, target).await?;
        } else {
            let prefix = http(&mut stream, config, target).await?;
            if !prefix.is_empty() {
                stream = Stream::Prefixed {
                    stream: Box::new(stream),
                    prefix,
                };
            }
        }
        Ok(stream)
    }
}
async fn http(
    stream: &mut Stream,
    config: &ProxyUpstream,
    target: SocketAddr,
) -> Result<bytes::Bytes> {
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let (Some(user), Some(password)) = (&config.username, &config.password) {
        request.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        ));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    response(stream).await
}

/// Bounded read-ahead: retain bytes after the final header as tunnel input.
async fn response(stream: &mut (impl AsyncRead + Unpin)) -> Result<bytes::Bytes> {
    const LIMIT: usize = 32768;
    // Prebuild once; memchr chooses AVX2/SSE2/fallback using the running CPU.
    static END: std::sync::LazyLock<memchr::memmem::Finder<'static>> =
        std::sync::LazyLock::new(|| memchr::memmem::Finder::new(b"\r\n\r\n"));
    let mut buffered = bytes::BytesMut::with_capacity(2048);
    let mut chunk = [0; 2048];
    let mut total = 0;
    for _ in 0..8 {
        let mut scan = 0;
        let end = loop {
            if let Some(offset) = END.find(&buffered[scan..]) {
                break scan + offset + 4;
            }
            let remaining = LIMIT - total - buffered.len();
            if remaining == 0 {
                return Err("upstream response headers too large".into());
            }
            scan = buffered.len().saturating_sub(3);
            let size = remaining.min(chunk.len());
            let n = stream.read(&mut chunk[..size]).await?;
            if n == 0 {
                return Err("upstream response ended before headers".into());
            }
            buffered.extend_from_slice(&chunk[..n]);
        };
        total += end;
        let header = buffered.split_to(end);
        let line = header
            .as_ref()
            .split(|b| *b == b'\n')
            .next()
            .ok_or("upstream status missing")?;
        let mut fields = line.split(|b| *b == b' ');
        if !matches!(fields.next(), Some(b"HTTP/1.1" | b"HTTP/1.0")) {
            return Err("invalid upstream response".into());
        }
        let status = fields.next().ok_or("invalid upstream response")?;
        if status.len() != 3 || !status.iter().all(u8::is_ascii_digit) {
            return Err("invalid upstream response".into());
        }
        if status[0] == b'2' {
            return Ok(buffered.freeze());
        }
        if status[0] != b'1' || status == b"101" {
            return Err("upstream CONNECT rejected".into());
        }
    }
    Err("too many upstream informational responses".into())
}
async fn socks(stream: &mut Stream, config: &ProxyUpstream, target: SocketAddr) -> Result<()> {
    let auth = config.username.is_some();
    stream.write_all(&[5, 1, if auth { 2 } else { 0 }]).await?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [5, if auth { 2 } else { 0 }] {
        return Err("SOCKS5 authentication negotiation failed".into());
    }
    if let (Some(user), Some(password)) = (&config.username, &config.password) {
        let mut credentials = vec![1, user.len() as u8];
        credentials.extend(user.as_bytes());
        credentials.push(password.len() as u8);
        credentials.extend(password.as_bytes());
        stream.write_all(&credentials).await?;
        stream.read_exact(&mut reply).await?;
        if reply != [1, 0] {
            return Err("SOCKS5 authentication failed".into());
        }
    }
    let mut request = vec![5, 1, 0];
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            request.push(1);
            request.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            request.push(4);
            request.extend(ip.octets());
        }
    }
    request.extend(target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    if head[..3] != [5, 0, 0] {
        return Err("SOCKS5 CONNECT rejected".into());
    }
    let len = match head[3] {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await? as usize,
        _ => return Err("invalid SOCKS5 address".into()),
    };
    let mut rest = vec![0; len + 2];
    stream.read_exact(&mut rest).await?;
    Ok(())
}
