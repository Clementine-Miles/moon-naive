// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use http::header::{self, HeaderName};
use pingora_core::protocols::http::authority::{raw_target_authority, RawTargetAuthority};
use pingora_core::upstreams::peer::{H1UpgradePolicy, HttpUpstreamRequestPolicy};
use pingora_error::{Error, ErrorType::InvalidHTTPHeader, OrErr, Result};
use pingora_http::RequestHeader;

const MAX_CONNECTION_NOMINATIONS: usize = 10;
pub(crate) const KEEP_ALIVE: &str = "keep-alive";
pub(crate) const PROXY_CONNECTION: &str = "proxy-connection";
pub(crate) const HTTP2_SETTINGS: &str = "http2-settings";

/// Authority handling that avoids imposing standard HTTP semantics on custom downstream sessions.
///
/// - `Standard`:
///   - Reconciles `Host`, URI authority, and absolute-form authority.
///   - Revalidates after filters.
///   - Rejects conflicting or ambiguous representations.
/// - `Custom`:
///   - Preserves authority relationships defined by the custom protocol.
///   - Enforces only the chosen H1/H2 upstream protocol's wire requirements.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityPolicy {
    Standard,
    Custom,
}

impl AuthorityPolicy {
    pub(crate) fn from(custom: bool) -> Self {
        if custom {
            Self::Custom
        } else {
            Self::Standard
        }
    }

    pub(crate) fn is_standard(self) -> bool {
        self == Self::Standard
    }

    pub(crate) fn is_custom(self) -> bool {
        self == Self::Custom
    }
}

/// Whether `byte` is a `tchar`, the character set of an HTTP `token` (RFC 9110 §5.6.2). Checked
/// here because `HeaderName::from_bytes` may accept bytes outside the `token` set.
fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_websocket_upgrade_request(req: &RequestHeader, downstream_is_http11: bool) -> bool {
    downstream_is_http11
        && req
            .headers
            .get(header::UPGRADE)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"))
}

struct ConnectionNominations {
    headers: [Option<HeaderName>; MAX_CONNECTION_NOMINATIONS],
    len: usize,
}

impl ConnectionNominations {
    fn parse(req: &RequestHeader, reject_malformed: bool) -> Result<Self> {
        let mut headers = std::array::from_fn(|_| None);
        let mut len = 0;
        let mut nomination_count = 0;

        // This is inspired by Envoy's defensive Connection-header sanitization checks. Bound the
        // amount of token processing so it cannot become a request-time DoS vector.
        for token in req
            .headers
            .get_all(header::CONNECTION)
            .iter()
            .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
            .map(|token| token.trim_ascii())
            .filter(|token| !token.is_empty())
        {
            nomination_count += 1;
            if nomination_count >= MAX_CONNECTION_NOMINATIONS {
                return Error::e_explain(
                    InvalidHTTPHeader,
                    "too many Connection header nominations",
                );
            }

            // `:`-prefixed tokens nominate pseudo-headers (e.g. `:authority`); rejected in both modes.
            if token.starts_with(b":") {
                return Error::e_explain(
                    InvalidHTTPHeader,
                    "protected header cannot be nominated by the Connection header",
                );
            }

            // A nomination is an HTTP `token` (RFC 9110 §5.6.2). We validate that ourselves rather
            // than trust `HeaderName::from_bytes`, which may accept non-`token` bytes and let a
            // decorated spelling like `Connection: "X-Forwarded-For"` slip past the protected-name
            // check below. The RFC lets a recipient reject or ignore a malformed option, so
            // `reject_malformed` is a policy choice: fail closed (default) or tolerate it.
            if reject_malformed && !token.iter().all(|&byte| is_tchar(byte)) {
                return Error::e_explain(
                    InvalidHTTPHeader,
                    "invalid token nominated by the Connection header",
                );
            }

            // `HeaderName` lowercases, so the protected-set check below cannot be evaded via casing.
            let name = match HeaderName::from_bytes(token) {
                Ok(name) => name,
                // Strict mode: every token is valid `tchar` and parses; a residual failure (e.g. a
                // length limit) still fails closed. Lenient mode: an unparsable token names
                // nothing, so ignore it.
                Err(_) if reject_malformed => {
                    return Error::e_explain(
                        InvalidHTTPHeader,
                        "invalid token nominated by the Connection header",
                    );
                }
                Err(_) => continue,
            };

            if matches!(
                name.as_str(),
                "host" | "x-forwarded-for" | "x-forwarded-host" | "x-forwarded-proto"
            ) {
                return Error::e_explain(
                    InvalidHTTPHeader,
                    "protected header cannot be nominated by the Connection header",
                );
            }

            headers[len] = Some(name);
            len += 1;
        }

        Ok(Self { headers, len })
    }

    fn remove_from(self, req: &mut RequestHeader) {
        for name in self.headers.into_iter().take(self.len).flatten() {
            req.remove_header(&name);
        }
    }
}

fn strip_standard_hop_by_hop_headers(req: &mut RequestHeader) {
    req.remove_header(KEEP_ALIVE);
    req.remove_header(PROXY_CONNECTION);
    req.remove_header(&header::PROXY_AUTHENTICATE);
    req.remove_header(&header::PROXY_AUTHORIZATION);
    req.remove_header(&header::TE);
    req.remove_header(&header::TRAILER);
    req.remove_header(&header::TRANSFER_ENCODING);
    req.remove_header(&header::CONNECTION);
    req.remove_header(&header::UPGRADE);
    req.remove_header(HTTP2_SETTINGS);
}

/// Set H1 `Host` from the URI or absolute-form authority.
///
/// A single matching `Host` is preserved; others are replaced ([RFC 9113 section 8.3.1]). Without
/// an authority, `Host` is preserved or inserted empty ([RFC 9112 section 3.2]).
///
/// # Errors
///
/// Returns `InvalidHTTPHeader` when the authority contains userinfo or cannot be represented as a
/// `Host` field value.
///
/// [RFC 9112 section 3.2]: https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2
/// [RFC 9113 section 8.3.1]: https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1
pub(crate) fn set_h1_host_from_authority(req: &mut RequestHeader) -> Result<()> {
    let authority = req
        .uri
        .authority()
        .map(|authority| authority.as_str().as_bytes())
        .or_else(|| raw_target_authority(req.raw_path()).authority());

    let Some(authority) = authority else {
        // No authority, use Host header.
        if req.headers.contains_key(header::HOST) {
            return Ok(());
        }
        // H1.1 requires Host even when the target has no authority; the H1 caller skips this for
        // Host-less HTTP/1.0 origin-form requests.
        return req.insert_header(header::HOST, "");
    };

    if authority.contains(&b'@') {
        return Error::e_explain(InvalidHTTPHeader, "userinfo in request authority");
    }

    // Avoid replacing the header-map entry when exactly one Host already matches the authority.
    let mut hosts = req.headers.get_all(header::HOST).iter();
    if hosts
        .next()
        .is_some_and(|host| host.as_bytes() == authority)
        && hosts.next().is_none()
    {
        return Ok(());
    }

    let host = http::HeaderValue::from_bytes(authority)
        .or_err(InvalidHTTPHeader, "invalid authority for Host header")?;

    req.insert_header(header::HOST, host)
}

/// Preserve the historical Custom behavior by synthesizing Host only when it is absent.
pub(crate) fn set_h1_host_from_authority_if_absent(req: &mut RequestHeader) -> Result<()> {
    if req.headers.contains_key(header::HOST) {
        return Ok(());
    }
    let host = req
        .uri
        .authority()
        .map_or("", |authority| authority.as_str())
        .to_owned();
    req.insert_header(header::HOST, host)
}

/// Apply a filter-selected `Host` to the outbound authority.
///
/// Rewrites URI authority or H1 absolute-form; origin-form is unchanged.
/// Ambiguous targets are also unchanged so final authority validation can reject them.
///
/// # Errors
///
/// Returns `InvalidHTTPHeader` when `Host` contains userinfo or an invalid authority, or when a URI
/// rewrite would discard non-UTF-8 path bytes or produce an invalid URI.
pub(crate) fn reconcile_upstream_authority(req: &mut RequestHeader) -> Result<()> {
    let Some(host) = req.headers.get(header::HOST) else {
        return Ok(());
    };
    if host.as_bytes().contains(&b'@') {
        return Error::e_explain(InvalidHTTPHeader, "userinfo in Host header");
    }

    if let Some(authority) = req.uri.authority() {
        // Rebuilding via set_uri() clears the raw-byte fallback. Fail instead of replacing a
        // non-UTF-8 path with the URI's lossy replacement characters.
        if !req.raw_path_is_utf8() {
            return Error::e_explain(
                InvalidHTTPHeader,
                "non-UTF-8 path cannot be reconciled with URI authority",
            );
        }
        if host.as_bytes() == authority.as_str().as_bytes() {
            return Ok(());
        }
        let authority = parse_host_authority(host)?;
        let mut parts = http::uri::Parts::default();
        parts.scheme = req.uri.scheme().cloned();
        parts.authority = Some(authority);
        parts.path_and_query = req.uri.path_and_query().cloned();
        let uri = http::Uri::from_parts(parts).map_err(|cause| {
            Error::because(
                InvalidHTTPHeader,
                "failed to apply Host override to URI authority",
                cause,
            )
        })?;
        req.set_uri(uri);
        return Ok(());
    }

    match raw_target_authority(req.raw_path()) {
        RawTargetAuthority::None | RawTargetAuthority::AmbiguousAuthority => Ok(()),
        RawTargetAuthority::Absolute {
            scheme,
            authority,
            path_and_query,
        } => {
            if host.as_bytes() == authority {
                return Ok(());
            }
            parse_host_authority(host)?;
            let mut target =
                Vec::with_capacity(scheme.len() + 3 + host.as_bytes().len() + path_and_query.len());
            target.extend_from_slice(scheme);
            target.extend_from_slice(b"://");
            target.extend_from_slice(host.as_bytes());
            target.extend_from_slice(path_and_query);
            req.set_raw_path(&target)
        }
    }
}

fn parse_host_authority(host: &http::HeaderValue) -> Result<http::uri::Authority> {
    http::uri::Authority::try_from(host.as_bytes()).map_err(|cause| {
        Error::because(
            InvalidHTTPHeader,
            "invalid Host override for authority",
            cause,
        )
    })
}

/// Apply automatic request policy before application upstream request filtering.
pub(crate) fn sanitize_h1_upstream_request(
    req: &mut RequestHeader,
    policy: HttpUpstreamRequestPolicy,
    downstream_is_http11: bool,
) -> Result<()> {
    if policy == HttpUpstreamRequestPolicy::preserve() {
        return Ok(());
    }

    let nominations = policy
        .strip_connection_nominated
        .then(|| ConnectionNominations::parse(req, policy.reject_malformed_connection_nominations))
        .transpose()?;

    if policy.h1_upgrade == H1UpgradePolicy::Preserve && req.headers.contains_key(header::UPGRADE) {
        // An arbitrary upgrade may require any of the connection-nominated fields. Preserve the
        // complete request metadata rather than forwarding a partial handshake.
        return Ok(());
    }

    let websocket_upgrade = policy.h1_upgrade == H1UpgradePolicy::WebSocketOnly
        && is_websocket_upgrade_request(req, downstream_is_http11);
    if let Some(nominations) = nominations {
        nominations.remove_from(req);
    }

    if policy.strip_hop_by_hop {
        strip_standard_hop_by_hop_headers(req);
    }

    match policy.h1_upgrade {
        H1UpgradePolicy::WebSocketOnly => {
            req.remove_header(&header::CONNECTION);
            req.remove_header(&header::UPGRADE);
            req.remove_header(HTTP2_SETTINGS);
            if websocket_upgrade {
                req.insert_header(header::CONNECTION, "Upgrade")?;
                req.insert_header(header::UPGRADE, "websocket")?;
            }
        }
        H1UpgradePolicy::Deny => {
            req.remove_header(&header::CONNECTION);
            req.remove_header(&header::UPGRADE);
            req.remove_header(HTTP2_SETTINGS);
        }
        H1UpgradePolicy::Preserve => {}
    }

    Ok(())
}

/// Frame a body-bearing HTTP/1 upstream request after application request filtering.
pub(crate) fn finalize_h1_upstream_request_framing(
    req: &mut RequestHeader,
    downstream_has_body: bool,
) -> Result<()> {
    if downstream_has_body
        && req.headers.get(header::CONTENT_LENGTH).is_none()
        && req.headers.get(header::TRANSFER_ENCODING).is_none()
    {
        req.insert_header(header::TRANSFER_ENCODING, "chunked")?;
    }
    Ok(())
}

/// Remove downstream connection-nominated fields before an HTTP/2 conversion.
pub(crate) fn sanitize_h2_upstream_request(
    req: &mut RequestHeader,
    policy: HttpUpstreamRequestPolicy,
) -> Result<()> {
    if policy.strip_connection_nominated {
        ConnectionNominations::parse(req, policy.reject_malformed_connection_nominations)?
            .remove_from(req);
    }
    if policy.strip_hop_by_hop {
        strip_standard_hop_by_hop_headers(req);
    }
    Ok(())
}

/// Possible downstream states during request multiplexing
#[derive(Debug, Clone, Copy)]
pub(crate) enum DownstreamStateMachine {
    /// more request (body) to read
    Reading,
    /// no more data to read
    ReadingFinished,
    /// downstream is already errored or closed
    Errored,
}

#[allow(clippy::wrong_self_convention)]
impl DownstreamStateMachine {
    pub fn new(finished: bool) -> Self {
        if finished {
            Self::ReadingFinished
        } else {
            Self::Reading
        }
    }

    // Can call read() to read more data or wait on closing
    pub fn can_poll(&self) -> bool {
        !matches!(self, Self::Errored)
    }

    pub fn is_reading(&self) -> bool {
        matches!(self, Self::Reading)
    }

    pub fn is_done(&self) -> bool {
        !matches!(self, Self::Reading)
    }

    pub fn is_errored(&self) -> bool {
        matches!(self, Self::Errored)
    }

    /// Move the state machine to Finished state if `set` is true.
    ///
    /// No-op when the current state is [`Errored`](Self::Errored) — once errored the
    /// downstream connection must not be reused, and late upstream chunks arriving
    /// via `rx.recv()` must not overwrite that decision.
    pub fn maybe_finished(&mut self, set: bool) {
        if set && !self.is_errored() {
            *self = Self::ReadingFinished
        }
    }

    /// Reset to [`Reading`](Self::Reading) for upgraded connections when body mode changes.
    ///
    /// No-op when the current state is [`Errored`](Self::Errored).
    pub fn reset(&mut self) {
        if !self.is_errored() {
            *self = Self::Reading;
        }
    }

    /// Transition to [`Errored`](Self::Errored). This is a terminal state: once entered,
    /// no other state transition is permitted and the connection must not be reused.
    pub fn to_errored(&mut self) {
        *self = Self::Errored
    }
}

/// Possible upstream states during request multiplexing
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResponseStateMachine {
    upstream_response_done: bool,
    cached_response_done: bool,
}

impl ResponseStateMachine {
    pub fn new() -> Self {
        ResponseStateMachine {
            upstream_response_done: false,
            cached_response_done: true, // no cached response by default
        }
    }

    pub fn is_done(&self) -> bool {
        self.upstream_response_done && self.cached_response_done
    }

    pub fn upstream_done(&self) -> bool {
        self.upstream_response_done
    }

    pub fn cached_done(&self) -> bool {
        self.cached_response_done
    }

    pub fn enable_cached_response(&mut self) {
        self.cached_response_done = false;
    }

    pub fn maybe_set_upstream_done(&mut self, done: bool) {
        if done {
            self.upstream_response_done = true;
        }
    }

    pub fn maybe_set_cache_done(&mut self, done: bool) {
        if done {
            self.cached_response_done = true;
        }
    }
}

/// Shared signal from the downstream proxy half to the upstream half: set to
/// [`DownstreamComplete`](Self::DownstreamComplete) right before the downstream
/// half returns successfully, so the upstream half can tell an expected pipe
/// closure (downstream finished the response by its own framing) from an
/// unexpected one.
///
/// Stored in an `AtomicU8` shared via `Arc`: the downstream half stores with
/// [`Release`](std::sync::atomic::Ordering::Release) and the upstream half loads
/// with [`Acquire`](std::sync::atomic::Ordering::Acquire), comparing against
/// `PipeState::DownstreamComplete as u8`.
#[derive(Debug)]
#[repr(u8)]
pub(crate) enum PipeState {
    Active = 0,
    DownstreamComplete = 1,
}

impl PipeState {
    /// Whether `raw` — a value previously read from the shared `AtomicU8` — is
    /// [`DownstreamComplete`](Self::DownstreamComplete). Centralizes the `as u8`
    /// comparison the upstream halves perform on a task-pipe closure.
    pub(crate) fn is_downstream_complete(raw: u8) -> bool {
        raw == PipeState::DownstreamComplete as u8
    }
}
