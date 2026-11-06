//! RFC 8441/9220 website WebSocket to fixed HTTP/1.1 origin Upgrade.
use super::{Head, Reply, upstream};
use crate::net::outbound::Stream;
use base64::{Engine, engine::general_purpose::STANDARD};
use moon_naive_core::{
    config::Config,
    website::{Route, Upstream},
};
use pingora_core::{connectors::http::Connector, protocols::http::client::HttpSession};

/// A fixed website route validated without IO or a tunnel permit. Rejected
/// requests must not expose whether the shared tunnel budget is exhausted.
pub(crate) struct Prepared<'a> {
    config: &'a Config,
    head: &'a Head,
    uri: http::Uri,
    route: &'a Route,
    pool: &'a Upstream,
    peers: &'a upstream::Pool,
    protocols: Vec<String>,
}

pub(crate) fn prepare<'a>(
    config: &'a Config,
    head: &'a Head,
    site: &'a super::Site,
) -> Result<Prepared<'a>, u16> {
    let host = head
        .authority
        .parse::<http::uri::Authority>()
        .map_err(|_| 400u16)?;
    if config.site_name(host.host()).is_none() {
        return Err(404);
    }
    if head
        .headers
        .iter()
        .filter(|(name, _)| name == "sec-websocket-version")
        .count()
        != 1
        || head.header("sec-websocket-version") != Some(b"13".as_slice())
        || head.header("sec-websocket-key").is_some()
    {
        return Err(400);
    }
    let path = head.path.as_deref().ok_or(400u16)?;
    let uri: http::Uri = path.parse().map_err(|_| 400u16)?;
    let route = config
        .website
        .routes
        .iter()
        .filter(|r| uri.path().starts_with(&r.path_prefix))
        .max_by_key(|r| r.path_prefix.len())
        .ok_or(404u16)?;
    let pool = config
        .website
        .upstreams
        .iter()
        .find(|p| p.name == route.upstream)
        .ok_or(502u16)?;
    let index = config
        .website
        .upstreams
        .iter()
        .position(|p| p.name == route.upstream)
        .ok_or(502u16)?;
    let peers = site.pools.get(index).ok_or(502u16)?;
    let protocols = super::transform::protocols(head)?;
    Ok(Prepared {
        peers,
        protocols,
        config,
        head,
        uri,
        route,
        pool,
    })
}

pub(crate) async fn connect(prepared: Prepared<'_>) -> Result<(Stream, Reply), u16> {
    let Prepared {
        config,
        head,
        uri,
        route,
        pool,
        peers,
        protocols,
    } = prepared;
    let connector = Connector::<()>::new(None);
    let start = peers.selection();
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(config.website.connect_timeout_secs);
    let mut selected = None;
    // Only connection establishment is retried. No Upgrade request has been sent.
    for offset in 0..peers.len() {
        let (index, mut peer) = peers
            .peer(start + offset, &config.website)
            .await
            .map_err(|_| 502u16)?;
        peer.options.alpn = pingora_core::protocols::ALPN::H1;
        let phase = (deadline - tokio::time::Instant::now()).min(std::time::Duration::from_secs(3));
        match tokio::time::timeout(phase, connector.get_http_session(&peer)).await {
            Ok(Ok((HttpSession::H1(session), _))) => {
                peers.succeeded(index);
                selected = Some(session);
                break;
            }
            _ => peers.failed(index),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(504);
        }
    }
    let mut session = selected.ok_or(502u16)?;
    let target = super::transform::target(&uri, &route.path_prefix, route.strip_prefix);
    let mut request =
        pingora_http::RequestHeader::build("GET", target.as_bytes(), None).map_err(|_| 502u16)?;
    request.set_version(http::Version::HTTP_11);
    for (name, value) in &head.headers {
        if super::is_proxy_header(name)
            || super::is_forwarded_header(name)
            || [
                "host",
                "connection",
                "upgrade",
                "content-length",
                "expect",
                "te",
                "transfer-encoding",
                "sec-websocket-key",
                "sec-websocket-version",
            ]
            .contains(&name.as_str())
        {
            continue;
        }
        request
            .append_header(
                http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| 400u16)?,
                value.as_slice(),
            )
            .map_err(|_| 400u16)?;
    }
    let mut entropy = [0; 16];
    boring::rand::rand_bytes(&mut entropy).map_err(|_| 502u16)?;
    let key = STANDARD.encode(entropy);
    for (name, value) in [
        (
            "host",
            pool.host_header.as_deref().unwrap_or(&head.authority),
        ),
        ("connection", "Upgrade"),
        ("upgrade", "websocket"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", key.as_str()),
        ("x-forwarded-proto", "https"),
    ] {
        request.insert_header(name, value).map_err(|_| 502u16)?;
    }
    super::transform::metadata(&mut request, &head.authority, head.client_ip)
        .map_err(|_| 502u16)?;
    session
        .write_request_header(Box::new(request))
        .await
        .map_err(|_| 502u16)?;
    for _ in 0..8 {
        session.read_response().await.map_err(|_| 502u16)?;
        let response = session.resp_header().ok_or(502u16)?;
        if response.status != http::StatusCode::SWITCHING_PROTOCOLS {
            if response.status.is_informational() {
                continue;
            }
            return Err(if response.status.is_client_error() {
                response.status.as_u16()
            } else {
                502
            });
        }
        let expected = STANDARD.encode(boring::sha::sha1(
            format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
        ));
        if response
            .headers
            .get("sec-websocket-accept")
            .is_none_or(|v| v.as_bytes() != expected.as_bytes())
            || response
                .headers
                .get("upgrade")
                .is_none_or(|v| !v.as_bytes().eq_ignore_ascii_case(b"websocket"))
        {
            return Err(502);
        }
        if response.headers.get_all("upgrade").iter().count() != 1
            || response
                .headers
                .get_all("sec-websocket-accept")
                .iter()
                .count()
                != 1
            || response
                .headers
                .get_all("sec-websocket-protocol")
                .iter()
                .count()
                > 1
            || !response.headers.get_all("connection").iter().any(|v| {
                v.to_str().is_ok_and(|s| {
                    s.split(',')
                        .any(|s| s.trim().eq_ignore_ascii_case("upgrade"))
                })
            })
        {
            return Err(502);
        }
        if let Some(protocol) = response.headers.get("sec-websocket-protocol") {
            let selected = protocol.to_str().map_err(|_| 502u16)?;
            if !super::transform::valid_token(selected)
                || !protocols.iter().any(|offered| offered == selected)
            {
                return Err(502);
            }
        }
        let offers = head
            .headers
            .iter()
            .filter(|(name, _)| name == "sec-websocket-extensions")
            .filter_map(|(_, value)| std::str::from_utf8(value).ok())
            .collect::<Vec<_>>()
            .join(",");
        for extensions in response.headers.get_all("sec-websocket-extensions") {
            let extensions = extensions.to_str().map_err(|_| 502u16)?;
            for extension in extensions.split(',') {
                let name = extension.split(';').next().unwrap_or("").trim();
                if name.is_empty()
                    || !offers
                        .split(',')
                        .any(|offer| offer.split(';').next().unwrap_or("").trim() == name)
                {
                    return Err(502);
                }
            }
        }
        let hop_fields = response
            .headers
            .get_all("connection")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|s| s.split(','))
            .map(|s| s.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        let mut headers = Vec::new();
        for (name, value) in &response.headers {
            if [
                "connection",
                "keep-alive",
                "proxy-connection",
                "te",
                "trailer",
                "upgrade",
                "sec-websocket-accept",
                "content-length",
                "transfer-encoding",
                "alt-svc",
                "server",
                "x-powered-by",
            ]
            .contains(&name.as_str())
                || super::is_proxy_header(name.as_str())
                || hop_fields.iter().any(|field| field == name.as_str())
            {
                continue;
            }
            if let Ok(value) = value.to_str() {
                headers.push((name.to_string(), value.to_owned()));
            }
        }
        let (stream, prefix) = session.into_upgraded_parts().map_err(|_| 502u16)?;
        return Ok((
            Stream::Upgrade { stream, prefix },
            Reply {
                status: 200,
                headers,
                body: bytes::Bytes::new(),
            },
        ));
    }
    Err(502)
}
