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

//! HTTP header objects that preserve http header cases
//!
//! Although HTTP header names are supposed to be case-insensitive for compatibility, proxies
//! ideally shouldn't alter the HTTP traffic, especially the headers they don't need to read.
//!
//! This crate provide structs and methods to preserve the headers in order to build a transparent
//! proxy.

#![allow(clippy::new_without_default)]

use bytes::BufMut;
use http::header::{AsHeaderName, HeaderName, HeaderValue};
use http::request::Builder as ReqBuilder;
use http::request::Parts as ReqParts;
use http::response::Builder as RespBuilder;
use http::response::Parts as RespParts;
use http::uri::Uri;
use pingora_error::{ErrorType::*, OrErr, Result};
use std::borrow::Cow;
use std::ops::Deref;

pub use http::method::Method;
pub use http::status::StatusCode;
pub use http::version::Version;
pub use http::HeaderMap as HMap;

pub mod authority;
use authority::{raw_target_authority, RawTargetAuthority};

mod case_header_name;
use case_header_name::CaseHeaderName;
pub use case_header_name::IntoCaseHeaderName;

pub mod prelude {
    pub use crate::RequestHeader;
    pub use crate::ResponseHeader;
}

/* an ordered header map to store the original case of each header name
HMap({
    "foo": ["Foo", "foO", "FoO"]
})
The order how HeaderMap iter over its items is "arbitrary, but consistent".
Hopefully this property makes sure this map of header names always iterates in the
same order of the map of header values.
This idea is inspaired by hyper @nox
*/
type CaseMap = HMap<CaseHeaderName>;

pub enum HeaderNameVariant<'a> {
    Case(&'a CaseHeaderName),
    Titled(&'a str),
}

/// The HTTP request header type.
///
/// This type is similar to [http::request::Parts] but preserves header name case.
/// It also preserves request path even if it is not UTF-8.
///
/// [RequestHeader] implements [Deref] for [http::request::Parts] so it can be used as it in most
/// places. Mutable access to the underlying parts is intentionally not provided because header and
/// URI mutations must use methods on [RequestHeader] to preserve its internal state.
///
/// ```compile_fail
/// use pingora_http::RequestHeader;
///
/// let mut request = RequestHeader::build("GET", b"/", None).unwrap();
/// request.headers.remove("user-agent");
/// ```
#[derive(Debug)]
pub struct RequestHeader {
    base: ReqParts,
    header_name_map: Option<CaseMap>,
    raw_target: RawTarget,
    // whether we send END_STREAM with HEADERS for h2 requests
    send_end_stream: bool,
}

/// How a request-target is stored, and how [`RequestHeader::raw_path`] recovers it.
///
/// Whether the target round-trips through the URI and whether it is valid UTF-8 are two
/// separate questions with only three valid combinations, so they are one value rather
/// than two fields that could disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RawTarget {
    /// The URI round-trips the target, so no separate copy is kept: origin-form,
    /// asterisk-form and query-only targets come back out of it byte-identical, and the
    /// empty target, having no bytes to reproduce, resolves to "/".
    FromUri,
    /// The target is kept verbatim for the wire rather than recovered from the URI, because
    /// the URI is not guaranteed to reproduce it: absolute-form contributes only its path
    /// component. Covers every non-origin-form target, including the authority-form CONNECT
    /// target and opaque or unclassifiable ones, whose bytes the URI happens to hold whole.
    Verbatim(Box<[u8]>),
    /// As [`Self::Verbatim`], but the target is not valid UTF-8, so the URI holds a lossy
    /// rendering of it and [`RequestHeader::raw_path_is_utf8`] reports false.
    Lossy(Box<[u8]>),
}

impl RawTarget {
    /// The stored bytes, or `None` when the URI is the source of truth.
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::FromUri => None,
            Self::Verbatim(target) | Self::Lossy(target) => Some(target.as_ref()),
        }
    }

    /// Whether the target is valid UTF-8, i.e. the URI is not a lossy rendering of it.
    ///
    /// Matched exhaustively: a new variant must state its encoding rather than inherit a
    /// default, because HTTP/2 egress refuses to forward a target this reports as lossy.
    fn is_utf8(&self) -> bool {
        match self {
            Self::FromUri | Self::Verbatim(_) => true,
            Self::Lossy(_) => false,
        }
    }
}

impl AsRef<ReqParts> for RequestHeader {
    fn as_ref(&self) -> &ReqParts {
        &self.base
    }
}

impl Deref for RequestHeader {
    type Target = ReqParts;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl RequestHeader {
    fn new_no_case(size_hint: Option<usize>) -> Self {
        let mut base = ReqBuilder::new().body(()).unwrap().into_parts().0;
        base.headers.reserve(http_header_map_upper_bound(size_hint));
        RequestHeader {
            base,
            header_name_map: None,
            raw_target: RawTarget::FromUri,
            send_end_stream: true,
        }
    }

    /// Create a new [RequestHeader] with the given method and path.
    ///
    /// The `path` can be non UTF-8.
    pub fn build(
        method: impl TryInto<Method>,
        path: &[u8],
        size_hint: Option<usize>,
    ) -> Result<Self> {
        let mut req = Self::build_no_case(method, path, size_hint)?;
        req.header_name_map = Some(CaseMap::with_capacity(http_header_map_upper_bound(
            size_hint,
        )));
        Ok(req)
    }

    /// Create a new [RequestHeader] with the given method and path without preserving header case.
    ///
    /// A [RequestHeader] created from this type is more space efficient than those from [Self::build()].
    ///
    /// Use this method if reading from or writing to HTTP/2 sessions where header case doesn't matter anyway.
    pub fn build_no_case(
        method: impl TryInto<Method>,
        path: &[u8],
        size_hint: Option<usize>,
    ) -> Result<Self> {
        let mut req = Self::new_no_case(size_hint);
        req.base.method = method
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid method")?;
        req.set_raw_path(path)?;
        Ok(req)
    }

    /// Append the header name and value to `self`.
    ///
    /// If there are already some headers under the same name, a new value will be added without
    /// any others being removed.
    pub fn append_header(
        &mut self,
        name: impl IntoCaseHeaderName,
        value: impl TryInto<HeaderValue>,
    ) -> Result<bool> {
        let header_value = value
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid value while append")?;
        append_header_value(
            self.header_name_map.as_mut(),
            &mut self.base.headers,
            name,
            header_value,
        )
    }

    /// Insert the header name and value to `self`.
    ///
    /// Different from [Self::append_header()], this method will replace all other existing headers
    /// under the same name (case-insensitive).
    pub fn insert_header(
        &mut self,
        name: impl IntoCaseHeaderName,
        value: impl TryInto<HeaderValue>,
    ) -> Result<()> {
        let header_value = value
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid value while insert")?;
        insert_header_value(
            self.header_name_map.as_mut(),
            &mut self.base.headers,
            name,
            header_value,
        )
    }

    /// Remove all headers under the name
    pub fn remove_header<'a, N: ?Sized>(&mut self, name: &'a N) -> Option<HeaderValue>
    where
        &'a N: 'a + AsHeaderName,
    {
        remove_header(self.header_name_map.as_mut(), &mut self.base.headers, name)
    }

    /// Write the header to the `buf` in HTTP/1.1 wire format.
    ///
    /// The header case will be preserved.
    pub fn header_to_h1_wire(&self, buf: &mut impl BufMut) {
        header_to_h1_wire(self.header_name_map.as_ref(), &self.base.headers, buf)
    }

    /// If case sensitivity is enabled, returns an iterator to iterate over case-sensitive header names and values.
    /// Otherwise returns an empty iterator.
    ///
    /// Headers of the same name are visited in insertion order.
    pub fn case_header_iter(&self) -> impl Iterator<Item = (&CaseHeaderName, &HeaderValue)> + '_ {
        case_header_iter(self.header_name_map.as_ref(), &self.base.headers)
    }

    /// Returns true if the request has case-sensitive headers.
    pub fn has_case(&self) -> bool {
        self.header_name_map.is_some()
    }

    pub fn map<F: FnMut(HeaderNameVariant, &HeaderValue) -> Result<()>>(
        &self,
        mut f: F,
    ) -> Result<()> {
        let key_map = self.header_name_map.as_ref();
        let value_map = &self.base.headers;

        if let Some(key_map) = key_map {
            let iter = key_map.iter().zip(value_map.iter());
            for ((header, case_header), (header2, val)) in iter {
                if header != header2 {
                    // in case the header iteration order changes in future versions of HMap
                    panic!("header iter mismatch {}, {}", header, header2)
                }
                f(HeaderNameVariant::Case(case_header), val)?;
            }
        } else {
            for (header, value) in value_map {
                let titled_header =
                    case_header_name::titled_header_name_str(header).unwrap_or(header.as_str());
                f(HeaderNameVariant::Titled(titled_header), value)?;
            }
        }

        Ok(())
    }

    /// Return mutable access to the request extensions.
    pub fn extensions_mut(&mut self) -> &mut http::Extensions {
        &mut self.base.extensions
    }

    /// Set the request method
    pub fn set_method(&mut self, method: Method) {
        self.base.method = method;
    }

    /// Set the request URI
    pub fn set_uri(&mut self, uri: http::Uri) {
        self.base.uri = uri;
        // The Uri is now the sole source of the target, so drop any stored bytes: they
        // would otherwise be used when serializing.
        self.raw_target = RawTarget::FromUri;
    }

    /// Set the request target directly via raw bytes.
    ///
    /// Generally prefer [`Self::set_uri()`] to modify the header's URI if able.
    ///
    /// This API is to allow supporting non UTF-8 cases, and request-targets that are not
    /// in origin-form ([RFC 9112 section 3.2]).
    ///
    /// Origin-form and asterisk-form targets round-trip through the URI. Absolute-form and
    /// the authority-form CONNECT target do not, so they are additionally kept verbatim for
    /// [`Self::raw_path()`]. For those two forms the URI carries only the path component,
    /// which means [`http::Uri::path()`] returns a path rather than a whole URL and
    /// [`http::Uri::authority()`] is left unset.
    ///
    /// Any fragment is dropped: it is not part of the request-target and must not be sent
    /// upstream.
    ///
    /// [RFC 9112 section 3.2]: https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2
    pub fn set_raw_path(&mut self, path: &[u8]) -> Result<()> {
        // Everything is computed before anything is stored: a rejected target must
        // leave the existing one intact.
        let parsed = parse_request_target(path)?;
        self.base.uri = parsed.uri;
        // Origin-form and asterisk-form store RawTarget::FromUri, so a reused header
        // (e.g. a CONNECT mutated into a normal request) cannot serialize a stale
        // target.
        self.raw_target = parsed.raw_target;
        Ok(())
    }

    /// Set whether we send an END_STREAM on H2 request HEADERS if body is empty.
    pub fn set_send_end_stream(&mut self, send_end_stream: bool) {
        self.send_end_stream = send_end_stream;
    }

    /// Returns if we support sending an END_STREAM on H2 request HEADERS if body is empty,
    /// returns None if not H2.
    pub fn send_end_stream(&self) -> Option<bool> {
        if self.base.version != Version::HTTP_2 {
            return None;
        }
        Some(self.send_end_stream)
    }

    /// Return the request target in its raw format, as it should appear on the wire.
    ///
    /// For origin-form and asterisk-form this is the path and query. For absolute-form and
    /// the authority-form CONNECT target it is the whole target as received, less any
    /// fragment.
    ///
    /// Non-UTF8 is supported; [`Self::raw_path_is_utf8()`] reports whether these bytes are
    /// valid UTF-8 or were replaced lossily in the URI.
    pub fn raw_path(&self) -> &[u8] {
        self.raw_target.bytes().unwrap_or_else(|| {
            self.base
                .uri
                .path_and_query()
                .map(|path| path.as_str().as_bytes())
                .or_else(|| {
                    self.base
                        .uri
                        .authority()
                        .map(|authority| authority.as_str().as_bytes())
                })
                .unwrap_or_default()
        })
    }

    /// Whether [`Self::raw_path`] is valid UTF-8 without lossy replacement.
    pub fn raw_path_is_utf8(&self) -> bool {
        self.raw_target.is_utf8()
    }

    /// Return the file extension of the path
    pub fn uri_file_extension(&self) -> Option<&str> {
        // get everything after the last '.' in path
        let (_, ext) = self
            .uri
            .path_and_query()
            .and_then(|pq| pq.path().rsplit_once('.'))?;
        Some(ext)
    }

    /// Set http version
    pub fn set_version(&mut self, version: Version) {
        self.base.version = version;
    }

    /// Clone `self` into [http::request::Parts].
    ///
    /// [ReqParts] has nowhere to keep a request-target that does not round-trip through the
    /// URI, so an absolute-form or CONNECT target does not survive the conversion:
    /// rebuilding a [RequestHeader] from the result serializes the URI's origin-form path
    /// instead of the original bytes. [Clone] keeps it; [Self::set_raw_path()] restores it.
    pub fn as_owned_parts(&self) -> ReqParts {
        clone_req_parts(&self.base)
    }
}

impl Clone for RequestHeader {
    fn clone(&self) -> Self {
        Self {
            base: self.as_owned_parts(),
            header_name_map: self.header_name_map.clone(),
            raw_target: self.raw_target.clone(),
            send_end_stream: self.send_end_stream,
        }
    }
}

/// Header case is not recovered, because [ReqParts] keeps none, and neither is a
/// request-target that does not round-trip through the URI: the target is taken from the
/// URI rather than the absolute-form or CONNECT bytes a [RequestHeader] preserves. Set one
/// with [Self::set_raw_path()].
impl From<ReqParts> for RequestHeader {
    fn from(parts: ReqParts) -> RequestHeader {
        Self {
            base: parts,
            header_name_map: None,
            // The Uri is the only target available here, so it is the one that serializes.
            raw_target: RawTarget::FromUri,
            send_end_stream: true,
        }
    }
}

impl From<RequestHeader> for ReqParts {
    fn from(resp: RequestHeader) -> ReqParts {
        resp.base
    }
}

/// The HTTP response header type.
///
/// This type is similar to [http::response::Parts] but preserves header name case.
/// [ResponseHeader] implements [Deref] for [http::response::Parts] so it can be used as it in most
/// places. Mutable access to the underlying parts is intentionally not provided because header
/// mutations must use methods on [ResponseHeader] to preserve its internal state.
///
/// ```compile_fail
/// use pingora_http::ResponseHeader;
///
/// let mut response = ResponseHeader::build(200, None).unwrap();
/// response.headers.remove("server");
/// ```
#[derive(Debug)]
pub struct ResponseHeader {
    base: RespParts,
    // an ordered header map to store the original case of each header name
    header_name_map: Option<CaseMap>,
    // the reason phrase of the response, if unset, a default one will be used
    reason_phrase: Option<String>,
}

impl AsRef<RespParts> for ResponseHeader {
    fn as_ref(&self) -> &RespParts {
        &self.base
    }
}

impl Deref for ResponseHeader {
    type Target = RespParts;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl Clone for ResponseHeader {
    fn clone(&self) -> Self {
        Self {
            base: self.as_owned_parts(),
            header_name_map: self.header_name_map.clone(),
            reason_phrase: self.reason_phrase.clone(),
        }
    }
}

// The `ResponseHeader` will be the no case variant, because `RespParts` keeps no header case
impl From<RespParts> for ResponseHeader {
    fn from(parts: RespParts) -> ResponseHeader {
        Self {
            base: parts,
            header_name_map: None,
            reason_phrase: None,
        }
    }
}

impl From<ResponseHeader> for RespParts {
    fn from(resp: ResponseHeader) -> RespParts {
        resp.base
    }
}

impl From<Box<ResponseHeader>> for Box<RespParts> {
    fn from(resp: Box<ResponseHeader>) -> Box<RespParts> {
        Box::new(resp.base)
    }
}

impl ResponseHeader {
    fn new(size_hint: Option<usize>) -> Self {
        let mut resp_header = Self::new_no_case(size_hint);
        resp_header.header_name_map = Some(CaseMap::with_capacity(http_header_map_upper_bound(
            size_hint,
        )));
        resp_header
    }

    fn new_no_case(size_hint: Option<usize>) -> Self {
        let mut base = RespBuilder::new().body(()).unwrap().into_parts().0;
        base.headers.reserve(http_header_map_upper_bound(size_hint));
        ResponseHeader {
            base,
            header_name_map: None,
            reason_phrase: None,
        }
    }

    /// Create a new [ResponseHeader] with the given status code.
    pub fn build(code: impl TryInto<StatusCode>, size_hint: Option<usize>) -> Result<Self> {
        let mut resp = Self::new(size_hint);
        resp.base.status = code
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid status")?;
        Ok(resp)
    }

    /// Create a new [ResponseHeader] with the given status code without preserving header case.
    ///
    /// A [ResponseHeader] created from this type is more space efficient than those from [Self::build()].
    ///
    /// Use this method if reading from or writing to HTTP/2 sessions where header case doesn't matter anyway.
    pub fn build_no_case(code: impl TryInto<StatusCode>, size_hint: Option<usize>) -> Result<Self> {
        let mut resp = Self::new_no_case(size_hint);
        resp.base.status = code
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid status")?;
        Ok(resp)
    }

    /// Append the header name and value to `self`.
    ///
    /// If there are already some headers under the same name, a new value will be added without
    /// any others being removed.
    pub fn append_header(
        &mut self,
        name: impl IntoCaseHeaderName,
        value: impl TryInto<HeaderValue>,
    ) -> Result<bool> {
        let header_value = value
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid value while append")?;
        append_header_value(
            self.header_name_map.as_mut(),
            &mut self.base.headers,
            name,
            header_value,
        )
    }

    /// Insert the header name and value to `self`.
    ///
    /// Different from [Self::append_header()], this method will replace all other existing headers
    /// under the same name (case insensitive).
    pub fn insert_header(
        &mut self,
        name: impl IntoCaseHeaderName,
        value: impl TryInto<HeaderValue>,
    ) -> Result<()> {
        let header_value = value
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid value while insert")?;
        insert_header_value(
            self.header_name_map.as_mut(),
            &mut self.base.headers,
            name,
            header_value,
        )
    }

    /// Remove all headers under the name
    pub fn remove_header<'a, N: ?Sized>(&mut self, name: &'a N) -> Option<HeaderValue>
    where
        &'a N: 'a + AsHeaderName,
    {
        remove_header(self.header_name_map.as_mut(), &mut self.base.headers, name)
    }

    /// Write the header to the `buf` in HTTP/1.1 wire format.
    ///
    /// The header case will be preserved.
    pub fn header_to_h1_wire(&self, buf: &mut impl BufMut) {
        header_to_h1_wire(self.header_name_map.as_ref(), &self.base.headers, buf)
    }

    /// If case sensitivity is enabled, returns an iterator to iterate over case-sensitive header names and values.
    /// Otherwise returns an empty iterator.
    ///
    /// Headers of the same name are visited in insertion order.
    pub fn case_header_iter(&self) -> impl Iterator<Item = (&CaseHeaderName, &HeaderValue)> + '_ {
        case_header_iter(self.header_name_map.as_ref(), &self.base.headers)
    }

    /// Returns true if the response has case-sensitive headers.
    pub fn has_case(&self) -> bool {
        self.header_name_map.is_some()
    }

    pub fn map<F: FnMut(HeaderNameVariant, &HeaderValue) -> Result<()>>(
        &self,
        mut f: F,
    ) -> Result<()> {
        let key_map = self.header_name_map.as_ref();
        let value_map = &self.base.headers;

        if let Some(key_map) = key_map {
            let iter = key_map.iter().zip(value_map.iter());
            for ((header, case_header), (header2, val)) in iter {
                if header != header2 {
                    // in case the header iteration order changes in future versions of HMap
                    panic!("header iter mismatch {}, {}", header, header2)
                }
                f(HeaderNameVariant::Case(case_header), val)?;
            }
        } else {
            for (header, value) in value_map {
                let titled_header =
                    case_header_name::titled_header_name_str(header).unwrap_or(header.as_str());
                f(HeaderNameVariant::Titled(titled_header), value)?;
            }
        }

        Ok(())
    }

    /// Return mutable access to the response extensions.
    pub fn extensions_mut(&mut self) -> &mut http::Extensions {
        &mut self.base.extensions
    }

    /// Set the status code
    pub fn set_status(&mut self, status: impl TryInto<StatusCode>) -> Result<()> {
        self.base.status = status
            .try_into()
            .explain_err(InvalidHTTPHeader, |_| "invalid status")?;
        Ok(())
    }

    /// Set the HTTP version
    pub fn set_version(&mut self, version: Version) {
        self.base.version = version
    }

    /// Set the HTTP reason phase. If `None`, a default reason phase will be used
    pub fn set_reason_phrase(&mut self, reason_phrase: Option<&str>) -> Result<()> {
        // No need to allocate memory to store the phrase if it is the default one.
        if reason_phrase == self.base.status.canonical_reason() {
            self.reason_phrase = None;
            return Ok(());
        }

        // TODO: validate it "*( HTAB / SP / VCHAR / obs-text )"
        self.reason_phrase = reason_phrase.map(str::to_string);
        Ok(())
    }

    /// Get the HTTP reason phase. If [Self::set_reason_phrase()] is never called
    /// or set to `None`, a default reason phase will be used
    pub fn get_reason_phrase(&self) -> Option<&str> {
        self.reason_phrase
            .as_deref()
            .or_else(|| self.base.status.canonical_reason())
    }

    /// Clone `self` into [http::response::Parts].
    pub fn as_owned_parts(&self) -> RespParts {
        clone_resp_parts(&self.base)
    }

    /// Helper function to set the HTTP content length on the response header.
    pub fn set_content_length(&mut self, len: usize) -> Result<()> {
        self.insert_header(http::header::CONTENT_LENGTH, len)
    }
}

/// Build a [Uri] carrying only a path-and-query component. `target` is the original
/// request-target, used for error context.
fn path_and_query_uri(path_and_query: &str, target: &str) -> Result<Uri> {
    Uri::builder()
        .path_and_query(path_and_query)
        .build()
        .explain_err(InvalidHTTPHeader, |_| format!("invalid uri {target}"))
}

/// A request-target parsed into the pieces a [RequestHeader] stores.
struct ParsedRequestTarget {
    /// The [Uri] to store, carrying at most a path-and-query component.
    uri: Uri,
    /// How the target is recovered for the wire.
    raw_target: RawTarget,
}

/// Parse a request-target (RFC 9112 §3.2) into the pieces to store on the header.
fn parse_request_target(target: &[u8]) -> Result<ParsedRequestTarget> {
    // A fragment is not part of the request-target (§3.2) and is separated from the URI
    // before dereference (RFC 3986 §3.5), so it must not reach the upstream request-line.
    // `#` is ASCII, so stripping it here rather than after the UTF-8 check applies the
    // same rule to targets that are not valid UTF-8, which are forwarded verbatim. Both
    // authority classifiers terminate at `#` as well, so dropping it cannot change the
    // authority they reconcile against `Host`.
    let target = match target.iter().position(|&byte| byte == b'#') {
        Some(fragment_start) => &target[..fragment_start],
        None => target,
    };

    // Forms the Uri round-trips on its own, so they need no separate copy: origin-form
    // (§3.2.1), asterisk-form (§3.2.4) and query-only targets all come back out of the
    // Uri byte-identical, so anything reaching the wire from them is unchanged. A target
    // the fragment strip left empty is the one exception: it has no bytes to reproduce,
    // and path_and_query() renders it as "/".
    if target.is_empty() || matches!(target.first(), Some(b'/' | b'?')) || target == b"*" {
        return Ok(match std::str::from_utf8(target) {
            Ok(target) => ParsedRequestTarget {
                uri: path_and_query_uri(target, target)?,
                raw_target: RawTarget::FromUri,
            },
            // Put a valid UTF-8 rendering into the Uri for read-only access, and keep the
            // original bytes for the wire.
            Err(_) => {
                let lossy = String::from_utf8_lossy(target);
                ParsedRequestTarget {
                    uri: path_and_query_uri(&lossy, &lossy)?,
                    raw_target: RawTarget::Lossy(target.into()),
                }
            }
        });
    }

    // Absolute-form (§3.2.2) and the authority-form CONNECT target (§3.2.3) are kept
    // verbatim for raw_path(). Which bytes reach the Uri depends on the form: an
    // absolute-form target contributes only its path component, so callers reading
    // uri.path() see a path rather than a whole URL, while a target that carries no
    // absolute-form authority has no such component to isolate and reaches the Uri whole.
    //
    // Scheme and authority are deliberately left off the Uri. The proxy layer
    // reconciles the target's authority against `Host` by parsing these raw bytes;
    // populating uri.authority() here would send that reconciliation down its URI
    // branch instead, rewriting the target on egress.
    //
    // For absolute-form, the authority boundary comes from the same classifier the
    // proxy layer reconciles with, so the path extracted here cannot disagree with the
    // authority validated there. A second parser with its own idea of where the
    // authority ends would let targets like `foo:bar://host/admin` yield a path that
    // was never validated.
    // from_utf8_lossy allocates only to substitute replacement characters, so it borrows
    // exactly when the target is already valid UTF-8.
    let lossy_target = String::from_utf8_lossy(target);
    let uri = match raw_target_authority(target) {
        RawTargetAuthority::Absolute { path_and_query, .. } => {
            // The classifier splits on ASCII delimiters only, so this is a suffix of the
            // target and is lossy exactly when the target is.
            let path_and_query = String::from_utf8_lossy(path_and_query);
            match path_and_query.as_ref() {
                "" => Uri::default(),
                // "http://host?q=1" has no path, but origin-form requires at least "/"
                // (§3.2.1), so anchor the component to the root.
                pq if !pq.starts_with('/') => path_and_query_uri(&format!("/{pq}"), &lossy_target)?,
                pq => path_and_query_uri(pq, &lossy_target)?,
            }
        }
        // No absolute-form authority: authority-form CONNECT (§3.2.3), opaque custom
        // schemes, and ambiguous targets. Storing these as path-and-query depends on how
        // permissive the linked http crate is. Rejection prevents header construction,
        // including every CONNECT, which has no other target form.
        //
        // Anchor the Uri to the root. `raw_target` preserves the bytes for the wire, while
        // rooting prevents an unvalidated target fragment from becoming a path; see the
        // security note above and the `://` cases in
        // test_unclassifiable_targets_are_anchored_to_the_root.
        RawTargetAuthority::None | RawTargetAuthority::AmbiguousAuthority => Uri::default(),
    };
    Ok(ParsedRequestTarget {
        uri,
        raw_target: match lossy_target {
            Cow::Borrowed(_) => RawTarget::Verbatim(target.into()),
            Cow::Owned(_) => RawTarget::Lossy(target.into()),
        },
    })
}

fn clone_req_parts(me: &ReqParts) -> ReqParts {
    let mut parts = ReqBuilder::new()
        .method(me.method.clone())
        .uri(me.uri.clone())
        .version(me.version)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    parts.headers = me.headers.clone();
    parts.extensions = me.extensions.clone();
    parts
}

fn clone_resp_parts(me: &RespParts) -> RespParts {
    let mut parts = RespBuilder::new()
        .status(me.status)
        .version(me.version)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    parts.headers = me.headers.clone();
    parts.extensions = me.extensions.clone();
    parts
}

// This function returns an upper bound on the size of the header map used inside the http crate.
// As of version 0.2, there is a limit of 1 << 15 (32,768) items inside the map. There is an
// assertion against this size inside the crate, so we want to avoid panicking by not exceeding this
// upper bound.
fn http_header_map_upper_bound(size_hint: Option<usize>) -> usize {
    // Even though the crate has 1 << 15 as the max size, calls to `with_capacity` invoke a
    // function that returns the size + size / 3.
    //
    // See https://github.com/hyperium/http/blob/34a9d6bdab027948d6dea3b36d994f9cbaf96f75/src/header/map.rs#L3220
    //
    // Therefore we set our max size to be even lower, so we guarantee ourselves we won't hit that
    // upper bound in the crate. Any way you cut it, 4,096 headers is insane.
    const PINGORA_MAX_HEADER_COUNT: usize = 4096;
    const INIT_HEADER_SIZE: usize = 8;

    // We select the size hint or the max size here, ensuring that we pick a value substantially lower
    // than 1 << 15 with room to grow the header map.
    std::cmp::min(
        size_hint.unwrap_or(INIT_HEADER_SIZE),
        PINGORA_MAX_HEADER_COUNT,
    )
}

#[inline]
fn append_header_value<T>(
    name_map: Option<&mut CaseMap>,
    value_map: &mut HMap<T>,
    name: impl IntoCaseHeaderName,
    value: T,
) -> Result<bool> {
    let case_header_name = name.into_case_header_name();
    let header_name: HeaderName = case_header_name
        .as_slice()
        .try_into()
        .or_err(InvalidHTTPHeader, "invalid header name")?;
    // store the original case in the map
    if let Some(name_map) = name_map {
        // Use the non-panicking `try_append`: the infallible `append` calls
        // `.expect("size overflows MAX_SIZE")` internally, which would abort the
        // process if the case map ever exceeded `http`'s `MAX_SIZE` (1 << 15).
        name_map
            .try_append(header_name.clone(), case_header_name)
            .or_err(InvalidHTTPHeader, "header name map size overflows MAX_SIZE")?;
    }

    // Non-panicking `try_append` for the same reason as the case map above.
    value_map.try_append(header_name, value).or_err(
        InvalidHTTPHeader,
        "header value map size overflows MAX_SIZE",
    )
}

#[inline]
fn insert_header_value<T>(
    name_map: Option<&mut CaseMap>,
    value_map: &mut HMap<T>,
    name: impl IntoCaseHeaderName,
    value: T,
) -> Result<()> {
    let case_header_name = name.into_case_header_name();
    let header_name: HeaderName = case_header_name
        .as_slice()
        .try_into()
        .or_err(InvalidHTTPHeader, "invalid header name")?;
    if let Some(name_map) = name_map {
        // store the original case in the map
        name_map.insert(header_name.clone(), case_header_name);
    }
    value_map.insert(header_name, value);
    Ok(())
}

// the &N here is to avoid clone(). None Copy type like String can impl AsHeaderName
#[inline]
fn remove_header<'a, T, N: ?Sized>(
    name_map: Option<&mut CaseMap>,
    value_map: &mut HMap<T>,
    name: &'a N,
) -> Option<T>
where
    &'a N: 'a + AsHeaderName,
{
    let removed = value_map.remove(name);
    if removed.is_some() {
        if let Some(name_map) = name_map {
            name_map.remove(name);
        }
    }
    removed
}

/// Build a [`HeaderValue`] from owned bytes, normalizing the value per RFC
/// 9110 section 5.5 and RFC 9112 section 5.2: obs-fold continuations
/// collapse to a single SP, and any stray CR / LF / NUL is replaced with SP.
/// Zero-copy when the input contains no CR/LF/NUL.
///
/// # Precondition
///
/// Input must come from a conformant HTTP/1.1 parser: bytes must satisfy
/// the `field-content` grammar (SP, HTAB, `%x21-7E`, `obs-text` `%x80-FF`),
/// with CR/LF/NUL only appearing as part of an obs-fold or as invalid bytes
/// that this function will replace with SP. All workspace callers satisfy
/// this via httparse.
///
/// # Panics
///
/// Debug builds panic on precondition violation via the sanity check in
/// [`HeaderValue::from_maybe_shared_unchecked`]. Release builds skip the
/// check; invalid input is undefined behavior per the `http` crate.
pub fn header_value_from_raw(raw: impl Into<bytes::Bytes>) -> HeaderValue {
    let normalized = normalize_field_value(raw.into());
    // SAFETY: `normalize_field_value` replaces all CR/LF/NUL with SP; by
    // precondition the remaining bytes pass the `http` crate's `is_valid`
    // byte-set check (other controls except HTAB are not expected here). The
    // crate's documented safety contract names "valid UTF-8", but its
    // internal use of the bytes never relies on UTF-8 in release. Matches
    // long-standing precedent.
    unsafe { HeaderValue::from_maybe_shared_unchecked(normalized) }
}

/// Build a [`HeaderValue`] from a borrowed slice, normalizing obs-fold per
/// RFC 9112 section 5.2. The slice is copied into an owned buffer.
///
/// Precondition and panic behavior are the same as [`header_value_from_raw`].
pub fn header_value_from_slice(raw: &[u8]) -> HeaderValue {
    header_value_from_raw(bytes::Bytes::copy_from_slice(raw))
}

/// Normalize a header field value per RFC 9110 section 5.5 and RFC 9112
/// section 5.2:
///
/// - Each CRLF + WSP obs-fold continuation collapses to a single SP
///   ([RFC 9112 section 5.2]).
/// - Any standalone CR, LF, or NUL (not part of an obs-fold being collapsed)
///   is replaced with a single SP ([RFC 9110 section 5.5]).
/// - Other CTL characters are retained, as RFC 9110 section 5.5 permits.
///
/// Zero-copy when the input contains no CR, LF, or NUL.
/// Example: `b"obs\r\n fold\r\n\t line"` becomes `b"obs fold line"`.
///
/// [RFC 9112 section 5.2]: https://datatracker.ietf.org/doc/html/rfc9112#section-5.2
/// [RFC 9110 section 5.5]: https://datatracker.ietf.org/doc/html/rfc9110#section-5.5
fn normalize_field_value(raw: bytes::Bytes) -> bytes::Bytes {
    // Fast path: no CR/LF/NUL, nothing to do.
    if !raw.iter().any(|b| matches!(b, b'\r' | b'\n' | b'\0')) {
        return raw;
    }

    // No LF means no obs-fold (which requires CRLF). Replace each stray CR
    // or NUL with SP per RFC 9110 section 5.5.
    let Some(first_nl) = raw.iter().position(|b| *b == b'\n') else {
        let replaced: Vec<u8> = raw
            .iter()
            .map(|&b| if matches!(b, b'\r' | b'\0') { b' ' } else { b })
            .collect();
        return bytes::Bytes::from(replaced);
    };

    // Mid-segment CRs (and NULs) — which boundary trimming can't reach because
    // they're not at a segment boundary — are replaced with SP at copy time
    // per RFC 9110 section 5.5. Empty continuations contribute no SP, so
    // leading/trailing newlines don't introduce spurious whitespace.
    fn push_with_replacement(dst: &mut Vec<u8>, src: &[u8]) {
        dst.extend(
            src.iter()
                .map(|&b| if matches!(b, b'\r' | b'\0') { b' ' } else { b }),
        );
    }

    // Trim ASCII whitespace at segment boundaries (we split on `\n`) so the
    // trailing `\r` of each CRLF is absorbed into the obs-fold collapse along
    // with the fold's SP/HTAB run.
    let head = raw[..first_nl].trim_ascii_end();
    let mut unfolded = Vec::with_capacity(raw.len());
    push_with_replacement(&mut unfolded, head);
    for line in raw[first_nl + 1..].split(|b| *b == b'\n') {
        let line = line.trim_ascii();
        if line.is_empty() {
            continue;
        }
        if !unfolded.is_empty() {
            unfolded.push(b' ');
        }
        push_with_replacement(&mut unfolded, line);
    }
    bytes::Bytes::from(unfolded)
}

#[inline]
fn header_to_h1_wire(key_map: Option<&CaseMap>, value_map: &HMap, buf: &mut impl BufMut) {
    const CRLF: &[u8; 2] = b"\r\n";
    const HEADER_KV_DELIMITER: &[u8; 2] = b": ";

    if let Some(key_map) = key_map {
        case_header_iter(key_map.into(), value_map).for_each(|(case_header, val)| {
            buf.put_slice(case_header.as_slice());
            buf.put_slice(HEADER_KV_DELIMITER);
            buf.put_slice(val.as_ref());
            buf.put_slice(CRLF);
        });
    } else {
        for (header, value) in value_map {
            let titled_header =
                case_header_name::titled_header_name_str(header).unwrap_or(header.as_str());
            buf.put_slice(titled_header.as_bytes());
            buf.put_slice(HEADER_KV_DELIMITER);
            buf.put_slice(value.as_ref());
            buf.put_slice(CRLF);
        }
    }
}

#[inline]
fn case_header_iter<'a>(
    name_map: Option<&'a CaseMap>,
    value_map: &'a HMap,
) -> impl Iterator<Item = (&'a CaseHeaderName, &'a HeaderValue)> + 'a {
    name_map.into_iter().flat_map(|name_map| {
        name_map
            .iter()
            .zip(value_map.iter())
            .map(|((h1, name), (h2, value))| {
                // in case the header iteration order changes in future versions of HMap
                assert_eq!(h1, h2, "header iter mismatch {}, {}", h1, h2);
                (name, value)
            })
    })
}
