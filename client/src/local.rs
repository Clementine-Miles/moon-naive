//! Local front end: SOCKS5 (RFC 1928, CONNECT only, no authentication) and
//! HTTP CONNECT on one listener, distinguished by the first byte.
use crate::{config::split_host_port, tunnel::OpenError};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Socks5,
    HttpConnect,
}
/// A parsed local request awaiting the remote tunnel.
#[derive(Debug)]
pub struct Request {
    pub protocol: Protocol,
    /// `host:port` or `[v6]:port`, exactly as signed and sent to the server.
    pub authority: String,
}

const MAX_HTTP_HEAD: usize = 8192;

/// Read and validate the local request. Errors already answered the peer
/// where the protocol allows it.
pub async fn negotiate(stream: &mut TcpStream) -> Result<Request, String> {
    let mut first = [0u8; 1];
    stream
        .read_exact(&mut first)
        .await
        .map_err(|e| e.to_string())?;
    if first[0] == 5 {
        socks5(stream).await
    } else {
        http_connect(stream, first[0]).await
    }
}

async fn socks5(stream: &mut TcpStream) -> Result<Request, String> {
    let io = |e: std::io::Error| e.to_string();
    let count = stream.read_u8().await.map_err(io)?;
    let mut methods = vec![0u8; usize::from(count)];
    stream.read_exact(&mut methods).await.map_err(io)?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).await.map_err(io)?;
        return Err("SOCKS5 client offered no supported authentication method".into());
    }
    stream.write_all(&[5, 0]).await.map_err(io)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(io)?;
    if head[0] != 5 || head[2] != 0 {
        return Err("malformed SOCKS5 request".into());
    }
    let host = match head[3] {
        1 => {
            let mut v4 = [0u8; 4];
            stream.read_exact(&mut v4).await.map_err(io)?;
            std::net::Ipv4Addr::from(v4).to_string()
        }
        3 => {
            let length = stream.read_u8().await.map_err(io)?;
            let mut name = vec![0u8; usize::from(length)];
            stream.read_exact(&mut name).await.map_err(io)?;
            match String::from_utf8(name) {
                Ok(name) if valid_host(&name) => name,
                _ => {
                    reply_socks(stream, 0x08).await;
                    return Err("SOCKS5 domain name is not an ASCII DNS name".into());
                }
            }
        }
        4 => {
            let mut v6 = [0u8; 16];
            stream.read_exact(&mut v6).await.map_err(io)?;
            format!("[{}]", std::net::Ipv6Addr::from(v6))
        }
        _ => {
            reply_socks(stream, 0x08).await;
            return Err("unsupported SOCKS5 address type".into());
        }
    };
    let port = stream.read_u16().await.map_err(io)?;
    if head[1] != 1 {
        // BIND and UDP ASSOCIATE are not supported.
        reply_socks(stream, 0x07).await;
        return Err("unsupported SOCKS5 command".into());
    }
    if port == 0 {
        reply_socks(stream, 0x01).await;
        return Err("SOCKS5 port 0".into());
    }
    Ok(Request {
        protocol: Protocol::Socks5,
        authority: format!("{host}:{port}"),
    })
}

fn valid_host(name: &str) -> bool {
    name.is_ascii() && moon_naive_core::policy::valid_dns_name(&name.to_ascii_lowercase())
}

async fn http_connect(stream: &mut TcpStream, first: u8) -> Result<Request, String> {
    // Byte-wise reads never consume bytes beyond the header, so any early
    // tunnel payload stays in the socket for the relay.
    let mut head = vec![first];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HTTP_HEAD {
            reply_http(stream, 431).await;
            return Err("HTTP request head too large".into());
        }
        head.push(stream.read_u8().await.map_err(|e| e.to_string())?);
    }
    let text = std::str::from_utf8(&head).map_err(|_| "non-UTF-8 HTTP request head")?;
    let line = text.lines().next().unwrap_or_default();
    let mut parts = line.split(' ');
    let (method, target, version) = (parts.next(), parts.next(), parts.next());
    if method != Some("CONNECT") || parts.next().is_some() {
        reply_http(stream, 405).await;
        return Err("only HTTP CONNECT is supported".into());
    }
    if !matches!(version, Some("HTTP/1.1" | "HTTP/1.0")) {
        reply_http(stream, 400).await;
        return Err("unsupported HTTP version".into());
    }
    let target = target.unwrap_or_default();
    match split_host_port(target) {
        Ok((host, _)) if host.parse::<std::net::IpAddr>().is_ok() || valid_host(&host) => {
            Ok(Request {
                protocol: Protocol::HttpConnect,
                authority: target.to_owned(),
            })
        }
        _ => {
            reply_http(stream, 400).await;
            Err("invalid CONNECT authority".into())
        }
    }
}

async fn reply_socks(stream: &mut TcpStream, code: u8) {
    let _ = stream.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await;
}
async fn reply_http(stream: &mut TcpStream, status: u16) {
    let reason = match status {
        200 => "Connection Established",
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Bad Gateway",
    };
    let close = if status == 200 {
        ""
    } else {
        "Connection: close\r\n"
    };
    let _ = stream
        .write_all(format!("HTTP/1.1 {status} {reason}\r\n{close}\r\n").as_bytes())
        .await;
}

pub async fn succeed(stream: &mut TcpStream, protocol: Protocol) {
    match protocol {
        Protocol::Socks5 => reply_socks(stream, 0).await,
        Protocol::HttpConnect => reply_http(stream, 200).await,
    }
}
pub async fn fail(stream: &mut TcpStream, protocol: Protocol, error: &OpenError) {
    match protocol {
        Protocol::Socks5 => reply_socks(stream, socks_code(error)).await,
        Protocol::HttpConnect => reply_http(stream, http_status(error)).await,
    }
}
pub fn socks_code(error: &OpenError) -> u8 {
    match error {
        OpenError::Status(403) => 0x02, // connection not allowed by ruleset
        OpenError::Status(502) => 0x04, // host unreachable
        OpenError::Status(504) | OpenError::Timeout => 0x06, // TTL expired
        _ => 0x01,                      // general failure
    }
}
pub fn http_status(error: &OpenError) -> u16 {
    match error {
        OpenError::Status(status @ (400 | 403 | 502 | 503 | 504)) => *status,
        OpenError::Timeout => 504,
        _ => 502,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        (client, listener.accept().await.unwrap().0)
    }
    async fn exchange(input: &[u8]) -> (Result<Request, String>, Vec<u8>) {
        let (mut client, mut server) = pair().await;
        client.write_all(input).await.unwrap();
        let result = negotiate(&mut server).await;
        drop(server);
        // Unread input makes the kernel answer the close with RST; keep
        // everything received before it.
        let mut answer = Vec::new();
        let mut chunk = [0u8; 256];
        while let Ok(n) = client.read(&mut chunk).await {
            if n == 0 {
                break;
            }
            answer.extend_from_slice(&chunk[..n]);
        }
        (result, answer)
    }
    #[tokio::test]
    async fn socks5_connect_forms() {
        let (r, a) = exchange(b"\x05\x01\x00\x05\x01\x00\x03\x0bexample.org\x01\xbb").await;
        assert_eq!(r.unwrap().authority, "example.org:443");
        assert_eq!(a, [5, 0]);
        let (r, _) = exchange(b"\x05\x01\x00\x05\x01\x00\x01\x01\x02\x03\x04\x00\x50").await;
        assert_eq!(r.unwrap().authority, "1.2.3.4:80");
        let mut v6 = b"\x05\x01\x00\x05\x01\x00\x04".to_vec();
        v6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0x1f, 0x90]);
        let (r, _) = exchange(&v6).await;
        assert_eq!(r.unwrap().authority, "[::1]:8080");
    }
    #[tokio::test]
    async fn socks5_rejections_are_answered() {
        let (r, a) = exchange(b"\x05\x01\x02").await;
        assert!(r.is_err());
        assert_eq!(a, [5, 0xff]);
        // BIND
        let (r, a) = exchange(b"\x05\x01\x00\x05\x02\x00\x01\x01\x02\x03\x04\x00\x50").await;
        assert!(r.is_err());
        assert_eq!(a[2..4], [5, 0x07]);
        // Non-ASCII / invalid domain
        let (r, a) = exchange(b"\x05\x01\x00\x05\x01\x00\x03\x03a b\x00\x50").await;
        assert!(r.is_err());
        assert_eq!(a[2..4], [5, 0x08]);
    }
    #[tokio::test]
    async fn http_connect_forms_and_rejections() {
        let (r, a) =
            exchange(b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n").await;
        let request = r.unwrap();
        assert_eq!(
            (request.protocol, request.authority.as_str()),
            (Protocol::HttpConnect, "example.org:443")
        );
        assert!(
            a.is_empty(),
            "success is answered only after the tunnel opens"
        );
        let (r, _) = exchange(b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n").await;
        assert_eq!(r.unwrap().authority, "[2001:db8::1]:443");
        let (r, a) = exchange(b"GET http://example.org/ HTTP/1.1\r\n\r\n").await;
        assert!(r.is_err());
        assert!(a.starts_with(b"HTTP/1.1 405 "));
        let (r, a) = exchange(b"CONNECT example.org HTTP/1.1\r\n\r\n").await;
        assert!(r.is_err());
        assert!(a.starts_with(b"HTTP/1.1 400 "));
        let mut huge = b"CONNECT example.org:443 HTTP/1.1\r\nX: ".to_vec();
        huge.resize(MAX_HTTP_HEAD + 10, b'a');
        let (r, a) = exchange(&huge).await;
        assert!(r.is_err());
        assert!(a.starts_with(b"HTTP/1.1 431 "));
    }
    #[test]
    fn error_mapping() {
        assert_eq!(socks_code(&OpenError::Status(403)), 2);
        assert_eq!(socks_code(&OpenError::Timeout), 6);
        assert_eq!(http_status(&OpenError::Status(503)), 503);
        assert_eq!(http_status(&OpenError::Confirmation), 502);
    }
}
