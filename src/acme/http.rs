//! Bounded HTTP/1 transport for CA and DNS control traffic, never a public H1 listener.
use super::{Error, Result};
use boring::ssl::{SslConnector, SslMethod};
use bytes::Bytes;
use http::{Request, Response, Uri, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use instant_acme::{BodyWrapper, BytesResponse, HttpClient};
use std::{
    future::Future,
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

#[derive(Debug)]
pub(crate) struct ApiFailure {
    pub status: u16,
    pub response: serde_json::Value,
}
impl std::fmt::Display for ApiFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DNS/control API returned HTTP {}", self.status)
    }
}
impl std::error::Error for ApiFailure {}
/// Structured authentication/permission rejection, not an ambiguous transport/5xx failure.
pub(crate) fn mutation_rejected(error: &super::Error) -> bool {
    error.downcast_ref::<ApiFailure>().is_some_and(|e| {
        matches!(e.status, 401 | 403)
            && (e.response["success"] == false || e.response["status"] == "ERROR")
    })
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type BoxIo = Box<dyn Io>;

#[derive(Clone)]
pub struct Http {
    tls: SslConnector,
    pub retry_after: Arc<AtomicU64>,
    timeout: Duration,
}
impl Http {
    pub fn new(ca_file: Option<&Path>, timeout: Duration) -> Result<Self> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_2))?;
        builder.set_default_verify_paths()?;
        if let Some(file) = crate::trust::system_ca_file() {
            builder.set_ca_file(file)?;
        }
        if let Some(file) = ca_file {
            builder.set_ca_file(file)?;
        }
        builder.set_alpn_protos(b"\x08http/1.1")?;
        Ok(Self {
            tls: builder.build(),
            retry_after: Arc::new(AtomicU64::new(0)),
            timeout,
        })
    }
    pub async fn request<B>(&self, request: Request<B>) -> Result<Response<Full<Bytes>>>
    where
        B: hyper::body::Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<Error> + Send + Sync,
    {
        tokio::time::timeout(self.timeout, self.send(request))
            .await
            .map_err(|_| -> Error { "control HTTP deadline exceeded".into() })?
    }
    async fn send<B>(&self, mut request: Request<B>) -> Result<Response<Full<Bytes>>>
    where
        B: hyper::body::Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<Error> + Send + Sync,
    {
        let uri = request.uri().clone();
        let host = uri
            .host()
            .ok_or("HTTP host missing")?
            .trim_matches(['[', ']']);
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        if uri.scheme_str() != Some("https") {
            return Err("control endpoints require HTTPS".into());
        }
        let port = uri.port_u16().unwrap_or(443);
        let authority = uri.authority().ok_or("HTTP authority missing")?.as_str();
        if authority.contains('@') {
            return Err("HTTP URL userinfo forbidden".into());
        }
        let proxy = if loopback || bypass_proxy(host) {
            None
        } else {
            std::env::var("HTTPS_PROXY")
                .or_else(|_| std::env::var("https_proxy"))
                .ok()
                .filter(|p| !p.is_empty())
        };
        let io: BoxIo = if let Some(proxy) = proxy {
            let proxy: Uri = proxy.parse().map_err(|_| "invalid HTTPS proxy URI")?;
            if proxy.scheme_str() != Some("http") {
                return Err("HTTPS proxy must use an HTTP CONNECT endpoint".into());
            }
            let stream = control_socket(
                proxy.host().ok_or("proxy host missing")?,
                proxy.port_u16().unwrap_or(80),
            )
            .await?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(stream))
                    .await?;

            let task = AbortTask(tokio::spawn(async move {
                let _ = connection.with_upgrades().await;
            }));
            let destination = if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            let request = Request::builder()
                .method("CONNECT")
                .uri(&destination)
                .header(header::HOST, &destination)
                .body(Full::new(Bytes::new()))?;
            let mut response = sender.send_request(request).await?;
            if !response.status().is_success() {
                return Err("HTTPS proxy refused CONNECT".into());
            }
            let upgraded = hyper::upgrade::on(&mut response).await?;
            drop(task);
            Box::new(TokioIo::new(upgraded))
        } else {
            Box::new(control_socket(host, port).await?)
        };
        let io: BoxIo = Box::new(
            tokio_boring::connect(self.tls.configure()?, host, io)
                .await
                .map_err(|_| "control TLS handshake/hostname verification failed")?,
        );
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(64 * 1024)
            .handshake(TokioIo::new(io))
            .await?;

        let _task = AbortTask(tokio::spawn(async move {
            let _ = connection.await;
        }));
        *request.uri_mut() = uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .parse()?;
        request
            .headers_mut()
            .insert(header::HOST, authority.parse()?);
        request.headers_mut().insert(
            header::CONNECTION,
            header::HeaderValue::from_static("close"),
        );
        let response = sender.send_request(request).await?;
        // The protocol client still receives Problems (including badNonce).
        // Never turn unrepresentable remote input into a saturated durable date.
        if let instant_acme::RetryAfter::At(at) = instant_acme::parse_retry_after(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            std::time::SystemTime::now(),
        ) && let Ok(duration) = at.duration_since(UNIX_EPOCH)
        {
            let until = duration
                .as_secs()
                .checked_add(u64::from(duration.subsec_nanos() != 0));
            if let Some(until) = until {
                self.retry_after.fetch_max(until, Ordering::Relaxed);
            }
        }
        let (parts, body) = response.into_parts();
        let bytes = Limited::new(body, 4 * 1024 * 1024)
            .collect()
            .await?
            .to_bytes();
        Ok(Response::from_parts(parts, Full::new(bytes)))
    }
    pub async fn json(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        value: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        self.json_headers(method, uri, token, value, &[]).await
    }
    pub async fn json_headers(
        &self,
        method: &str,
        uri: &str,
        token: Option<&str>,
        value: Option<serde_json::Value>,
        headers: &[(&str, &str)],
    ) -> Result<serde_json::Value> {
        let mut request = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let bytes = match value {
            Some(value) => serde_json::to_vec(&value)?,
            None => Vec::new(),
        };
        let response = self
            .request(
                request
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(bytes)))?,
            )
            .await?;
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();
        if !status.is_success() {
            return Err(Box::new(ApiFailure {
                status: status.as_u16(),
                response: serde_json::from_slice(&body).unwrap_or_default(),
            }));
        }
        if body.is_empty() {
            return Ok(serde_json::Value::Null);
        }
        Ok(serde_json::from_slice(&body)?)
    }
}
// A cancelled HTTP waiter must not release a running system resolver job.
async fn control_socket(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let addresses: Vec<_> = crate::resolve::lookup_control(host, port).await?.collect();
    if addresses.is_empty() || addresses.len() > 32 {
        return Err(std::io::Error::other("invalid control DNS candidate count"));
    }
    TcpStream::connect(addresses.as_slice()).await
}
struct AbortTask(tokio::task::JoinHandle<()>);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn bypass_proxy(host: &str) -> bool {
    std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|suffix| {
            let suffix = suffix.trim_start_matches('.');
            suffix == "*"
                || host.eq_ignore_ascii_case(suffix)
                || host
                    .to_ascii_lowercase()
                    .ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
        })
}
impl HttpClient for Http {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<BytesResponse, instant_acme::Error>> + Send>>
    {
        let client = self.clone();
        Box::pin(async move {
            client
                .request(req)
                .await
                .map(BytesResponse::from)
                .map_err(instant_acme::Error::Other)
        })
    }
}
