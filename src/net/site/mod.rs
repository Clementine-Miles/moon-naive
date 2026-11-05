//! Shared Pingora website engine. H2 enters directly; H3 uses a bounded memory bridge.
mod bridge;
mod forward;
mod upstream;
pub(super) mod websocket;
use super::{Head, Reply, Result};
use bytes::Bytes;
use moon_naive_core::{
    config::Config,
    ingress::{is_proxy_header, normalized_header_eq},
    website::Website,
};
use pingora_core::{
    apps::HttpServerApp,
    modules::http::{
        HttpModules,
        compression::{ResponseCompression, ResponseCompressionBuilder},
    },
    protocols::http::{HttpTask, ServerSession, v2::server::HttpSession},
    server::configuration::ServerConf,
};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{HttpProxy, ProxyHttp, ProxyWarnLogContext, Session};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, OnceCell, mpsc, oneshot, watch};

// Client-supplied forwarding identity is discarded before trusted values are added.
const FORWARDED_HEADERS: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
];
fn is_forwarded_header(name: &str) -> bool {
    FORWARDED_HEADERS
        .iter()
        .any(|field| normalized_header_eq(name, field))
}

// Honor the request preference and the response prohibition against
// transformation (RFC 9111 sections 5.2.1.6 / 5.2.2.6).
fn no_transform(headers: &http::HeaderMap) -> bool {
    headers
        .get_all("cache-control")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("no-transform"))
        })
}

// Check the raw head as well as Pingora's parsed view: Pingora can remove CL
// when TE is present. An ambiguous request must never reach a reused origin.
fn valid_h1_framing(raw: &[u8]) -> bool {
    if raw.len() > 32768 || !raw.ends_with(b"\r\n\r\n") {
        return false;
    }
    let mut lines = raw[..raw.len() - 2].split_inclusive(|b| *b == b'\n');
    let Some(line) = lines.next().and_then(|line| line.strip_suffix(b"\r\n")) else {
        return false;
    };
    let mut parts = line.split(|b| *b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if http::Method::from_bytes(method).is_err()
        || target.is_empty()
        || !target.iter().all(u8::is_ascii_graphic)
        || !matches!(version, b"HTTP/1.0" | b"HTTP/1.1")
    {
        return false;
    }
    let mut host: Option<http::uri::Authority> = None;
    let mut length = false;
    let mut transfer = false;
    for (index, line) in lines.enumerate() {
        let Some(line) = line.strip_suffix(b"\r\n") else {
            return false;
        };
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            return false;
        };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if index >= 128
            || http::header::HeaderName::from_bytes(name).is_err()
            || value.iter().any(|b| (*b < 32 && *b != b'\t') || *b == 127)
        {
            return false;
        }
        let value = value.trim_ascii();
        if name.eq_ignore_ascii_case(b"host") {
            let Ok(value) = std::str::from_utf8(value) else {
                return false;
            };
            let Ok(authority) = value.parse::<http::uri::Authority>() else {
                return false;
            };
            if host.is_some() || value.contains('@') {
                return false;
            }
            host = Some(authority);
        } else if name.eq_ignore_ascii_case(b"content-length") {
            if length
                || value.is_empty()
                || !value.iter().all(u8::is_ascii_digit)
                || std::str::from_utf8(value)
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_none()
            {
                return false;
            }
            length = true;
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            if transfer || !value.eq_ignore_ascii_case(b"chunked") {
                return false;
            }
            transfer = true;
        } else if name.eq_ignore_ascii_case(b"connection") {
            for token in value.split(|b| *b == b',') {
                let Ok(field) = http::header::HeaderName::from_bytes(token.trim_ascii()) else {
                    return false;
                };
                let field = field.as_str();
                if is_proxy_header(field)
                    || is_forwarded_header(field)
                    || [
                        "host",
                        "content-length",
                        "transfer-encoding",
                        "authorization",
                    ]
                    .iter()
                    .any(|protected| normalized_header_eq(field, protected))
                {
                    return false;
                }
            }
        }
    }
    if version == b"HTTP/1.1" && host.is_none() {
        return false;
    }
    // Absolute-form still uses the fixed website route, never an arbitrary
    // backend. Reject ambiguous authorities before any upstream connection.
    if method != b"CONNECT" {
        let Ok(target) = std::str::from_utf8(target) else {
            return false;
        };
        let Ok(uri) = target.parse::<http::Uri>() else {
            return false;
        };
        if let Some(scheme) = uri.scheme_str() {
            if !matches!(scheme, "http" | "https") {
                return false;
            }
            let (Some(authority), Some(host)) = (uri.authority(), host.as_ref()) else {
                return false;
            };
            if authority.as_str().contains('@') || authority.as_str() != host.as_str() {
                return false;
            }
        }
    }
    !(length && transfer)
}
type Proxy = HttpProxy<Router>;
pub(crate) struct Site {
    proxy: Arc<Proxy>,
    bridge: OnceCell<bridge::Bridge>,
    max_streams: u32,
}
pub(super) enum Input {
    Data(Bytes),
    Trailers(http::HeaderMap),
}
pub(super) struct Exchange {
    pub input: mpsc::Sender<Input>,
    pub output: mpsc::Receiver<HttpTask>,
    pub task: tokio::task::JoinHandle<()>,
    pub completion: oneshot::Receiver<Result<()>>,
}
struct Router {
    config: Website,
    domain: String,
    public_name: Option<String>,
    pools: Vec<upstream::Pool>,
    routes: Vec<(moon_naive_core::website::Route, usize)>,
    alt_svc: String,
    forward: Option<forward::Origin>,
    stats: Arc<WebStats>,
}
#[derive(Default)]
pub struct WebStats {
    pub requests: AtomicUsize,
    pub upstream_connections: AtomicUsize,
    pub upstream_reuses: AtomicUsize,
    pub upstream_failures: AtomicUsize,
}
#[derive(Default)]
struct Context {
    pool: Option<usize>,
    origin: usize,
    attempt: usize,
    path: Option<String>,
    uploaded: usize,
}
impl Site {
    pub fn load(config: &Config) -> Result<Self> {
        config.website.validate()?;
        if config.website.routes.is_empty() {
            return Err("website requires a configured reverse-proxy route".into());
        }
        let pools = config
            .website
            .upstreams
            .iter()
            .map(|p| upstream::Pool::load(p, config))
            .collect::<Result<Vec<_>>>()?;
        let mut routes: Vec<_> = config
            .website
            .routes
            .iter()
            .map(|route| {
                (
                    route.clone(),
                    config
                        .website
                        .upstreams
                        .iter()
                        .position(|p| p.name == route.upstream)
                        .expect("validated upstream"),
                )
            })
            .collect();
        routes.sort_by_key(|(r, _)| std::cmp::Reverse(r.path_prefix.len()));
        let stats = Arc::default();
        let router = Router {
            config: config.website.clone(),
            domain: config.domain.clone(),
            public_name: config.ech.as_ref().map(|ech| ech.public_name.clone()),
            pools,
            routes,
            stats: Arc::clone(&stats),
            forward: None,
            alt_svc: format!("h3=\":{}\"; ma=86400", config.listener.udp.port()),
        };
        let conf = Arc::new(ServerConf {
            ca_file: crate::trust::system_ca_file().map(|path| path.to_string_lossy().into_owned()),
            threads: 1,
            max_retries: 2,
            upstream_keepalive_pool_size: 128,
            ..ServerConf::default()
        });
        let mut proxy = pingora_proxy::http_proxy(&conf, router);
        let mut options = pingora_core::apps::HttpServerOptions::default();
        options.allow_connect_method_proxying = true;
        options.h1_header_timeout = Some(super::HEADER_TIMEOUT);
        proxy.server_options = Some(options);
        Ok(Self {
            proxy: Arc::new(proxy),
            bridge: OnceCell::new(),
            max_streams: config.limits.max_streams as u32,
        })
    }
    pub(super) fn forward(
        config: &Config,
        origin: &str,
        user: usize,
        egress: super::egress::Egress,
    ) -> Result<Self> {
        let router = Router {
            config: config.website.clone(),
            domain: config.domain.clone(),
            public_name: config.ech.as_ref().map(|ech| ech.public_name.clone()),
            pools: vec![],
            routes: vec![],
            stats: Arc::default(),
            alt_svc: String::new(),
            forward: Some(forward::Origin::new(origin, user, egress)?),
        };
        let conf = Arc::new(ServerConf {
            max_retries: 1,
            upstream_keepalive_pool_size: 16,
            ..ServerConf::default()
        });
        Ok(Self {
            proxy: Arc::new(pingora_proxy::http_proxy(&conf, router)),
            bridge: OnceCell::new(),
            max_streams: config.limits.max_streams as u32,
        })
    }
    pub async fn h1(
        &self,
        stream: pingora_core::protocols::Stream,
        mut stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut session = ServerSession::new_http1(stream);
        session.set_keepalive(Some(super::HEADER_TIMEOUT.as_secs()));
        // We drive Pingora sessions directly rather than through http_app's
        // accept loop, so initialize its persisted reuse counter here.
        session.set_keepalive_reuses_remaining(Some(999));
        loop {
            session.set_read_timeout(Some(Duration::from_secs(30)));
            session.set_write_timeout(Some(Duration::from_secs(30)));
            let shutdown = stop.clone();
            let reused = tokio::select! { _ = stop.changed() => break, r = self.proxy.process_new_http(session, &shutdown) => r };
            let Some(reused) = reused else { break };
            let (stream, settings) = reused.consume();
            session = ServerSession::new_http1(stream);
            if let Some(settings) = settings {
                settings.apply_to_session(&mut session);
            }
        }
        Ok(())
    }
    pub async fn h2(&self, mut session: HttpSession, head: Head) -> Result<()> {
        *session.req_header_mut() = request_header(&head)?;
        let (_send, stop) = watch::channel(false);
        self.proxy
            .process_new_http(ServerSession::new_http2(session), &stop)
            .await;
        Ok(())
    }
    pub(super) fn start(self: &Arc<Self>, head: Head, end: bool, wake: Arc<Notify>) -> Exchange {
        let (input, receive) = mpsc::channel(2);
        let (send, output) = mpsc::channel(2);
        let site = self.clone();
        let (result_send, completion) = oneshot::channel();
        let task = tokio::spawn(async move {
            let result: Result<()> = async {
                let bridge = site
                    .bridge
                    .get_or_try_init(|| bridge::Bridge::new(site.proxy.clone(), site.max_streams))
                    .await?;
                bridge
                    .exchange(
                        request_header(&head)?,
                        end,
                        receive,
                        send.clone(),
                        wake.clone(),
                    )
                    .await
            }
            .await;
            if result.is_err() {
                let _ = send
                    .send(HttpTask::Failed(pingora_core::Error::new_str(
                        "website stream failed",
                    )))
                    .await;
            }
            let _ = result_send.send(result);
            wake.notify_one();
        });
        Exchange {
            input,
            output,
            task,
            completion,
        }
    }
}
fn request_header(head: &Head) -> Result<RequestHeader> {
    let target = if head.method == "CONNECT" {
        head.authority.as_str()
    } else {
        head.path.as_deref().unwrap_or("/")
    };
    let mut request = RequestHeader::build(head.method.as_bytes(), target.as_bytes(), None)?;
    request.set_version(http::Version::HTTP_2);
    for (name, value) in &head.headers {
        if name != "host"
            && name != "content-length"
            && !is_forwarded_header(name)
            && !is_proxy_header(name)
        {
            request.append_header(
                http::header::HeaderName::from_bytes(name.as_bytes())?,
                value.as_slice(),
            )?;
        }
    }
    // Head::valid already checked every duplicate/comma value for equality.
    // Emit one decimal value so every H1/H2 origin sees identical framing.
    if let Some(value) = head.header("content-length") {
        let value = std::str::from_utf8(value)?
            .split(',')
            .next()
            .unwrap()
            .trim();
        request.insert_header("content-length", value.parse::<u64>()?.to_string())?;
    }
    request.insert_header("host", head.authority.as_str())?;
    request.insert_header("x-forwarded-host", head.authority.as_str())?;
    request.insert_header("x-forwarded-proto", "https")?;
    if let Some(ip) = head.client_ip {
        request.insert_header("x-forwarded-for", ip.to_string())?;
    }
    Ok(request)
}
#[async_trait::async_trait]
impl ProxyHttp for Router {
    type CTX = Context;
    fn new_ctx(&self) -> Context {
        Context::default()
    }
    fn init_downstream_modules(&self, m: &mut HttpModules) {
        m.add_module(ResponseCompressionBuilder::enable(
            self.config.compression_level,
        ));
    }
    async fn early_request_filter(
        &self,
        s: &mut Session,
        _ctx: &mut Context,
    ) -> pingora_core::Result<()> {
        self.stats.requests.fetch_add(1, Ordering::Relaxed);
        if matches!(
            s.req_header().version,
            http::Version::HTTP_10 | http::Version::HTTP_11
        ) {
            if !valid_h1_framing(&s.as_downstream().to_h1_raw()) {
                s.set_keepalive(None);
                return Err(pingora_core::Error::new(
                    pingora_core::ErrorType::HTTPStatus(400),
                ));
            }
            let req = s.req_header_mut();
            let remove = req
                .headers
                .keys()
                .filter(|name| is_proxy_header(name.as_str()) || is_forwarded_header(name.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            for name in remove {
                req.remove_header(&name);
            }
            req.insert_header("x-forwarded-proto", "https")?;
        }
        s.set_read_timeout(Some(Duration::from_secs(self.config.read_timeout_secs)));
        s.set_write_timeout(Some(Duration::from_secs(self.config.write_timeout_secs)));
        if (s.req_header().method == http::Method::HEAD
            || s.req_header().headers.contains_key("range")
            || no_transform(&s.req_header().headers))
            && let Some(c) = s.downstream_modules_ctx.get_mut::<ResponseCompression>()
        {
            c.adjust_level(0);
        }
        Ok(())
    }
    async fn request_filter(
        &self,
        s: &mut Session,
        ctx: &mut Context,
    ) -> pingora_core::Result<bool> {
        let req = s.req_header();
        if req
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|n| n > self.config.max_request_body_bytes as u64)
        {
            return Err(pingora_core::Error::new(
                pingora_core::ErrorType::HTTPStatus(413),
            ));
        }
        if self.forward.is_some() {
            ctx.path = Some(
                req.uri
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/")
                    .to_owned(),
            );
            return Ok(false);
        }
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<http::uri::Authority>().ok());
        if host.is_none_or(|h| {
            !h.host().eq_ignore_ascii_case(&self.domain)
                && !self
                    .public_name
                    .as_ref()
                    .is_some_and(|name| h.host().eq_ignore_ascii_case(name))
        }) {
            self.send_local(s, Reply::error(404)).await?;
            return Ok(true);
        }
        if req.method == http::Method::CONNECT {
            self.send_local(s, Reply::error(405)).await?;
            return Ok(true);
        }
        let path = req.uri.path();
        for (route, pool) in &self.routes {
            if path.starts_with(&route.path_prefix) {
                ctx.pool = Some(*pool);
                let mut target = if route.strip_prefix {
                    let suffix = &path[route.path_prefix.len()..];
                    if route.path_prefix.ends_with('/') || !suffix.starts_with('/') {
                        format!("/{suffix}")
                    } else {
                        suffix.to_owned()
                    }
                } else {
                    path.to_owned()
                };
                if let Some(q) = req.uri.query() {
                    target.push('?');
                    target.push_str(q);
                }
                ctx.path = Some(target);
                return Ok(false);
            }
        }
        self.send_local(s, Reply::error(404)).await?;
        Ok(true)
    }
    async fn upstream_peer(
        &self,
        s: &mut Session,
        ctx: &mut Context,
    ) -> pingora_core::Result<Box<pingora_core::upstreams::peer::HttpPeer>> {
        if let Some(origin) = &self.forward {
            return origin.peer(&self.config).await;
        }
        let (origin, mut peer) = self.pools[ctx.pool.expect("routed request")]
            .peer(ctx.attempt, &self.config)
            .await?;
        if s.req_header().headers.contains_key("upgrade") {
            peer.options.alpn = pingora_core::protocols::ALPN::H1;
        }
        ctx.origin = origin;
        ctx.attempt += 1;
        Ok(Box::new(peer))
    }
    async fn upstream_request_filter(
        &self,
        _s: &mut Session,
        req: &mut RequestHeader,
        ctx: &mut Context,
    ) -> pingora_core::Result<()> {
        req.set_uri(
            ctx.path
                .as_ref()
                .expect("routed path")
                .parse()
                .expect("valid path"),
        );
        if let Some(host) = ctx
            .pool
            .and_then(|pool| self.pools[pool].config.host_header.as_ref())
        {
            req.insert_header("host", host.as_str())?;
        }
        let remove = req
            .headers
            .keys()
            .filter(|name| {
                is_proxy_header(name.as_str())
                    || ["forwarded", "x-real-ip"].contains(&name.as_str())
                    // Website metadata is useful to a fixed, trusted origin.
                    // Arbitrary forward-proxy targets must not receive the
                    // client's address or proxy-chain identity (hide_ip/via).
                    || (self.forward.is_some()
                        && (is_forwarded_header(name.as_str())
                            || normalized_header_eq(name.as_str(), "via")))
            })
            .cloned()
            .collect::<Vec<_>>();
        for name in remove {
            req.remove_header(&name);
        }
        Ok(())
    }
    async fn request_body_filter(
        &self,
        s: &mut Session,
        body: &mut Option<Bytes>,
        _end: bool,
        ctx: &mut Context,
    ) -> pingora_core::Result<()> {
        // After a successful 101 this is a duplex protocol, not an HTTP request body.
        if s.was_upgraded() {
            return Ok(());
        }
        ctx.uploaded = ctx
            .uploaded
            .saturating_add(body.as_ref().map_or(0, Bytes::len));
        if ctx.uploaded > self.config.max_request_body_bytes {
            return Err(pingora_core::Error::new(
                pingora_core::ErrorType::HTTPStatus(413),
            ));
        }
        Ok(())
    }
    async fn response_filter(
        &self,
        s: &mut Session,
        response: &mut ResponseHeader,
        _ctx: &mut Context,
    ) -> pingora_core::Result<()> {
        upstream::clean_response(response);
        if self.forward.is_none() {
            response.insert_header("alt-svc", self.alt_svc.as_str())?;
        }
        if s.req_header().version == http::Version::HTTP_11
            && s.req_header().method != http::Method::HEAD
            && !response.status.is_informational()
            && !matches!(response.status.as_u16(), 204 | 304)
            && !response.headers.contains_key("content-length")
        {
            // Hop-by-hop cleanup removes the upstream transfer encoding. Restore
            // framing only for unknown-length responses; mirror downloads and
            // ranges retain their representation length. Pingora's compression
            // module removes Content-Length itself when it transforms a body.
            response.insert_header("transfer-encoding", "chunked")?;
        }
        let disable_compression = response.status == http::StatusCode::PARTIAL_CONTENT
            || response.headers.get("content-type").is_some_and(|v| {
                v.as_bytes().starts_with(b"text/event-stream")
                    || v.as_bytes().starts_with(b"application/grpc")
            })
            || no_transform(&response.headers);
        if disable_compression
            && let Some(c) = s.downstream_modules_ctx.get_mut::<ResponseCompression>()
        {
            c.adjust_level(0);
        }
        Ok(())
    }
    async fn response_trailer_filter(
        &self,
        _s: &mut Session,
        trailers: &mut http::HeaderMap,
        _ctx: &mut Context,
    ) -> pingora_core::Result<Option<Bytes>> {
        let remove = trailers
            .keys()
            .filter(|name| forbidden_trailer(name.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        for name in remove {
            trailers.remove(name);
        }
        Ok(None)
    }
    fn fail_to_connect(
        &self,
        s: &mut Session,
        _peer: &pingora_core::upstreams::peer::HttpPeer,
        ctx: &mut Context,
        mut e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        self.stats.upstream_failures.fetch_add(1, Ordering::Relaxed);
        if self.forward.is_some() {
            e.set_retry(false);
            return e;
        }
        let pool = &self.pools[ctx.pool.expect("routed request")];
        pool.failed(ctx.origin);
        e.set_retry(
            matches!(
                s.req_header().method,
                http::Method::GET | http::Method::HEAD | http::Method::OPTIONS
            ) && ctx.attempt < pool.len().min(2),
        );
        e
    }
    async fn connected_to_upstream(
        &self,
        _s: &mut Session,
        reused: bool,
        _peer: &pingora_core::upstreams::peer::HttpPeer,
        _fd: pingora_core::protocols::UniqueIDType,
        _digest: Option<&pingora_core::protocols::Digest>,
        ctx: &mut Context,
    ) -> pingora_core::Result<()> {
        if reused {
            self.stats.upstream_reuses.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats
                .upstream_connections
                .fetch_add(1, Ordering::Relaxed);
        }
        if let Some(pool) = ctx.pool {
            self.pools[pool].succeeded(ctx.origin);
        }
        Ok(())
    }
    fn suppress_error_log(&self, _s: &Session, _ctx: &Context, _e: &pingora_core::Error) -> bool {
        true
    }
    fn suppress_proxy_warn_log(
        &self,
        _s: &Session,
        _ctx: &Context,
        _e: &pingora_core::Error,
        _c: ProxyWarnLogContext,
    ) -> bool {
        true
    }
}
impl Router {
    async fn send_local(&self, s: &mut Session, mut reply: Reply) -> pingora_core::Result<()> {
        reply.headers.push(("alt-svc".into(), self.alt_svc.clone()));
        send_local(s, reply).await
    }
}
async fn send_local(s: &mut Session, reply: Reply) -> pingora_core::Result<()> {
    let mut h = ResponseHeader::build(reply.status, None)?;
    for (name, value) in reply.headers {
        h.append_header(name, value)?;
    }
    let end = reply.body.is_empty() || s.req_header().method == http::Method::HEAD;
    s.write_response_header(Box::new(h), end).await?;
    if !end {
        s.write_response_body(Some(reply.body), true).await?;
    }
    Ok(())
}
pub(super) fn forbidden_trailer(name: &str) -> bool {
    is_proxy_header(name)
        || is_forwarded_header(name)
        || [
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "upgrade",
            "te",
            "trailer",
            "authorization",
        ]
        .iter()
        .any(|field| normalized_header_eq(name, field))
}
