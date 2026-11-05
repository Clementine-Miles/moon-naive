//! A single authenticated next hop. Target IPs have already passed egress policy.
use super::Result;
use base64::Engine;
use moon_naive_core::config::{ProxyKind, ProxyUpstream};
use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};

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

#[cfg(test)]
mod tests {
    use super::*;

    struct Fragmented<'a> {
        bytes: &'a [u8],
        size: usize,
        reads: usize,
    }
    impl AsyncRead for Fragmented<'_> {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            this.reads += 1;
            let n = this.size.min(this.bytes.len()).min(buf.remaining());
            buf.put_slice(&this.bytes[..n]);
            this.bytes = &this.bytes[n..];
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn fragmented_informational_headers_preserve_binary_tunnel_prefix() {
        let wire = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nX: y\r\n\r\nHTTP/1.0 200 OK\r\n\r\n\x00\xffHTTP/1.1\r\n\r\ndata";
        for size in [1, 2, 3, 4, 7, 64, 2048] {
            let mut stream = Fragmented {
                bytes: wire,
                size,
                reads: 0,
            };
            let mut payload = response(&mut stream).await.unwrap().to_vec();
            stream.read_to_end(&mut payload).await.unwrap();
            assert_eq!(&payload, b"\x00\xffHTTP/1.1\r\n\r\ndata", "chunk={size}");
        }
    }

    #[tokio::test]
    async fn response_limits_rejections_and_eof_remain_bounded() {
        for wire in [
            b"HTTP/1.1 407 Authentication required\r\n\r\n".as_slice(),
            b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
            b"HTTP/2 200 OK\r\n\r\n",
            b"HTTP/1.1 2xx Invalid\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"",
        ] {
            assert!(response(&mut &wire[..]).await.is_err());
        }
        let final_head = b"HTTP/1.1 200 OK\r\nX: ";
        for len in [32767, 32768, 32769] {
            let mut wire = final_head.to_vec();
            wire.resize(len - 4, b'a');
            wire.extend_from_slice(b"\r\n\r\n");
            assert_eq!(response(&mut wire.as_slice()).await.is_ok(), len <= 32768);
        }
        for count in [7, 8] {
            let mut wire = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(count);
            wire.extend_from_slice(b"HTTP/1.1 200 OK\r\n\r\n");
            assert_eq!(response(&mut wire.as_slice()).await.is_ok(), count < 8);
        }
        let mut wire = b"HTTP/1.1 100 Continue\r\nX: ".to_vec();
        wire.resize(32760, b'a');
        wire.extend_from_slice(b"\r\n\r\nHTTP/1.1 200 OK\r\n\r\n");
        assert!(response(&mut wire.as_slice()).await.is_err());
    }

    #[tokio::test]
    async fn large_header_uses_chunk_reads_instead_of_per_byte_reads() {
        let mut wire = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
        wire.resize(8188, b'a');
        wire.extend_from_slice(b"\r\n\r\n");
        let mut stream = Fragmented {
            bytes: &wire,
            size: usize::MAX,
            reads: 0,
        };
        assert!(response(&mut stream).await.unwrap().is_empty());
        assert_eq!(stream.reads, 4);
    }

    #[tokio::test]
    async fn response_delimiters_cross_vector_and_read_boundaries_without_losing_payload() {
        for length in [30, 31, 32, 33, 63, 64, 65, 2047, 2048, 2049, 8192, 32768] {
            let mut wire = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
            wire.resize(length - 4, b'a');
            wire.extend_from_slice(b"\r\n\r\n");
            let payload = b"\0\xff\r\n\r\nnext protocol";
            wire.extend_from_slice(payload);
            for size in [1, 15, 16, 31, 32, 2047, 2048, 2049] {
                let mut stream = Fragmented {
                    bytes: &wire,
                    size,
                    reads: 0,
                };
                let mut bytes = response(&mut stream).await.unwrap().to_vec();
                stream.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, payload, "header={length}, fragment={size}");
            }
        }
    }

    /// Actual loopback TCP IO; old parser below is the pre-optimization byte loop.
    #[tokio::test]
    #[ignore = "release microbenchmark; run separately with --nocapture --test-threads=1"]
    async fn benchmark_connect_response_reads() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let socket = TcpStream::connect(address).await.unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        socket.set_nodelay(true).unwrap();
        peer.set_nodelay(true).unwrap();
        let mut stream = Stream::Plain(socket);
        let mut wire = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
        wire.resize(8188, b'a');
        wire.extend_from_slice(b"\r\n\r\n");
        let mut old = Vec::new();
        let mut new = Vec::new();
        for _ in 0..31 {
            peer.write_all(&wire).await.unwrap();
            let start = std::time::Instant::now();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(stream.read_u8().await.unwrap());
            }
            old.push(start.elapsed());
            assert_eq!(header, wire);
            peer.write_all(&wire).await.unwrap();
            let start = std::time::Instant::now();
            assert!(response(&mut stream).await.unwrap().is_empty());
            new.push(start.elapsed());
        }
        old.sort();
        new.sort();
        eprintln!(
            "CONNECT response: old_byte_reads={:?} new_chunk_reads={:?} (median, 8192 header bytes, samples=31, loopback TCP)",
            old[15], new[15]
        );
    }

    #[tokio::test]
    #[ignore = "release latency benchmark; run separately with --nocapture --test-threads=1"]
    async fn benchmark_header_scan() {
        const ITERATIONS: usize = 10_000;
        for length in [128, 8192, 32768] {
            let mut wire = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
            wire.resize(length - 4, b'a');
            wire.extend_from_slice(b"\r\n\r\n");
            let start = std::time::Instant::now();
            for _ in 0..ITERATIONS {
                let mut stream = Fragmented {
                    bytes: std::hint::black_box(&wire),
                    size: 2048,
                    reads: 0,
                };
                assert!(std::hint::black_box(response(&mut stream).await.unwrap()).is_empty());
            }
            let nanos = start.elapsed().as_secs_f64() * 1_000_000_000. / ITERATIONS as f64;
            eprintln!(
                "PERF {{\"case\":\"header_scan\",\"bytes\":{length},\"iterations\":{ITERATIONS},\"ns_per_response\":{nanos}}}"
            );
        }
    }
}
