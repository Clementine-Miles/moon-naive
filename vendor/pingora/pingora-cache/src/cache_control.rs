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

//! Functions and utilities to help parse Cache-Control headers

use super::*;

use http::header::HeaderName;
use http::HeaderValue;
use indexmap::IndexMap;
use once_cell::sync::Lazy;
use pingora_error::{Error, ErrorType};
use regex::bytes::Regex;
use std::fmt;
use std::num::IntErrorKind;
use std::slice;
use std::str;

/// The max delta-second per [RFC 9111](https://datatracker.ietf.org/doc/html/rfc9111#section-1.2.2)
// "If a cache receives a delta-seconds value
// greater than the greatest integer it can represent, or if any of its
// subsequent calculations overflows, the cache MUST consider the value
// to be 2147483648 (2^31) or the greatest positive integer it can
// conveniently represent.
//
//    |  *Note:* The value 2147483648 is here for historical reasons,
//    |  represents infinity (over 68 years), and does not need to be
//    |  stored in binary form; an implementation could produce it as a
//    |  string if any overflow occurs, even if the calculations are
//    |  performed with an arithmetic type incapable of directly
//    |  representing that number.  What matters here is that an
//    |  overflow be detected and not treated as a negative value in
//    |  later calculations."
//
// We choose to use i32::MAX for our overflow value to stick to the letter of the RFC.
pub const DELTA_SECONDS_OVERFLOW_VALUE: u32 = i32::MAX as u32;
pub const DELTA_SECONDS_OVERFLOW_DURATION: Duration =
    Duration::from_secs(DELTA_SECONDS_OVERFLOW_VALUE as u64);

/// Cache-Control directive key.
///
/// Known RFC 9111 (and common extension) directives are represented as enum variants,
/// avoiding a heap allocation for every parsed directive. Unknown or extension
/// directives are preserved via the [`Unknown`](Self::Unknown) variant.
///
/// Directive keys are always stored in lowercase, matching the case-insensitive
/// comparison required by the HTTP specification.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DirectiveKey {
    /// `max-age`
    MaxAge,
    /// `s-maxage`
    SMaxAge,
    /// `no-cache`
    NoCache,
    /// `no-store`
    NoStore,
    /// `private`
    Private,
    /// `public`
    Public,
    /// `must-revalidate`
    MustRevalidate,
    /// `proxy-revalidate`
    ProxyRevalidate,
    /// `must-understand`
    MustUnderstand,
    /// `no-transform`
    NoTransform,
    /// `immutable`
    Immutable,
    /// `stale-while-revalidate`
    StaleWhileRevalidate,
    /// `stale-if-error`
    StaleIfError,
    /// `only-if-cached`
    OnlyIfCached,
    /// An unknown or extension directive, stored as the original (lowercased) name.
    Unknown(String),
}

impl DirectiveKey {
    /// Return the wire-format name of this directive as a `&str`.
    ///
    /// Known variants return a `&'static str`; [`Unknown`](Self::Unknown)
    /// returns a borrow of the inner `String`.
    pub fn as_str(&self) -> &str {
        match self {
            Self::MaxAge => "max-age",
            Self::SMaxAge => "s-maxage",
            Self::NoCache => "no-cache",
            Self::NoStore => "no-store",
            Self::Private => "private",
            Self::Public => "public",
            Self::MustRevalidate => "must-revalidate",
            Self::ProxyRevalidate => "proxy-revalidate",
            Self::MustUnderstand => "must-understand",
            Self::NoTransform => "no-transform",
            Self::Immutable => "immutable",
            Self::StaleWhileRevalidate => "stale-while-revalidate",
            Self::StaleIfError => "stale-if-error",
            Self::OnlyIfCached => "only-if-cached",
            Self::Unknown(s) => s.as_str(),
        }
    }

    /// Construct a [`DirectiveKey`] from a **lowercase** `&str`.
    ///
    /// Known directive names are mapped to their enum variant (zero allocation).
    /// Anything else produces [`Unknown`](Self::Unknown) with an owned copy of
    /// the string.
    ///
    /// The caller is responsible for lowercasing the input first; this function
    /// does **not** perform case folding.
    ///
    /// See also [`from_lowercase_owned`](Self::from_lowercase_owned) to avoid a
    /// re-allocation when the caller already has an owned `String`.
    pub fn from_lowercase(s: &str) -> Self {
        match s {
            "max-age" => Self::MaxAge,
            "s-maxage" => Self::SMaxAge,
            "no-cache" => Self::NoCache,
            "no-store" => Self::NoStore,
            "private" => Self::Private,
            "public" => Self::Public,
            "must-revalidate" => Self::MustRevalidate,
            "proxy-revalidate" => Self::ProxyRevalidate,
            "must-understand" => Self::MustUnderstand,
            "no-transform" => Self::NoTransform,
            "immutable" => Self::Immutable,
            "stale-while-revalidate" => Self::StaleWhileRevalidate,
            "stale-if-error" => Self::StaleIfError,
            "only-if-cached" => Self::OnlyIfCached,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// Construct a [`DirectiveKey`] from a **lowercase** owned `String`.
    ///
    /// Behaves identically to [`from_lowercase`](Self::from_lowercase) but
    /// takes ownership of the `String`, avoiding a re-allocation when the
    /// input maps to [`Unknown`](Self::Unknown).
    pub fn from_lowercase_owned(s: String) -> Self {
        // Check against known names first (the string is borrowed for matching).
        match s.as_str() {
            "max-age" => Self::MaxAge,
            "s-maxage" => Self::SMaxAge,
            "no-cache" => Self::NoCache,
            "no-store" => Self::NoStore,
            "private" => Self::Private,
            "public" => Self::Public,
            "must-revalidate" => Self::MustRevalidate,
            "proxy-revalidate" => Self::ProxyRevalidate,
            "must-understand" => Self::MustUnderstand,
            "no-transform" => Self::NoTransform,
            "immutable" => Self::Immutable,
            "stale-while-revalidate" => Self::StaleWhileRevalidate,
            "stale-if-error" => Self::StaleIfError,
            "only-if-cached" => Self::OnlyIfCached,
            _ => Self::Unknown(s),
        }
    }
}

impl fmt::Display for DirectiveKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<str> for DirectiveKey {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for DirectiveKey {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

/// Cache control directive value type
#[derive(Debug)]
pub struct DirectiveValue(pub Vec<u8>);

impl AsRef<[u8]> for DirectiveValue {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl DirectiveValue {
    /// A [DirectiveValue] without quotes (`"`).
    pub fn parse_as_bytes(&self) -> &[u8] {
        self.0
            .strip_prefix(b"\"")
            .and_then(|bytes| bytes.strip_suffix(b"\""))
            .unwrap_or(&self.0[..])
    }

    /// A [DirectiveValue] without quotes (`"`) as `str`.
    pub fn parse_as_str(&self) -> Result<&str> {
        str::from_utf8(self.parse_as_bytes()).or_else(|e| {
            Error::e_because(ErrorType::InternalError, "could not parse value as utf8", e)
        })
    }

    /// Parse the [DirectiveValue] as delta seconds
    ///
    /// `"`s are ignored. The value is capped to [DELTA_SECONDS_OVERFLOW_VALUE].
    pub fn parse_as_delta_seconds(&self) -> Result<u32> {
        match self.parse_as_str()?.parse::<u32>() {
            Ok(value) => Ok(value),
            Err(e) => {
                // delta-seconds expect to handle positive overflow gracefully
                if e.kind() == &IntErrorKind::PosOverflow {
                    Ok(DELTA_SECONDS_OVERFLOW_VALUE)
                } else {
                    Error::e_because(ErrorType::InternalError, "could not parse value as u32", e)
                }
            }
        }
    }

    /// Parse the [DirectiveValue] as delta seconds, permitting a fractional component.
    ///
    /// Values with a fractional part are rounded down (floored) to the nearest
    /// non-negative integer: e.g. `1.9` -> `1`, `0.5` -> `0`. This is useful
    /// for compatibility with upstreams that emit fractional ttls (which
    /// RFC 9111 strict integer parsing rejects).
    ///
    /// Integer parsing is attempted first, so strictly-numeric values (including
    /// overflow-capped values and quoted integers) behave identically to
    /// [Self::parse_as_delta_seconds]. Negative, non-finite, or non-numeric
    /// values still return an error.
    ///
    /// `"`s are ignored. The value is capped to [DELTA_SECONDS_OVERFLOW_VALUE].
    pub fn parse_as_delta_seconds_floor(&self) -> Result<u32> {
        // UTF-8 validate once; on non-UTF8 input, propagate the same error as
        // [Self::parse_as_delta_seconds].
        let s = self.parse_as_str()?;
        match s.parse::<u32>() {
            Ok(value) => Ok(value),
            Err(e) if e.kind() == &IntErrorKind::PosOverflow => Ok(DELTA_SECONDS_OVERFLOW_VALUE),
            Err(int_err) => {
                // Fall back to parsing as a non-negative finite float and floor.
                // On any failure, return an error equivalent to the strict
                // [Self::parse_as_delta_seconds] u32-parse error.
                match s.parse::<f64>() {
                    Ok(f) if f.is_finite() && f >= 0.0 => {
                        if f >= DELTA_SECONDS_OVERFLOW_VALUE as f64 {
                            Ok(DELTA_SECONDS_OVERFLOW_VALUE)
                        } else {
                            // Safe cast: `f` is finite, non-negative, and strictly
                            // less than `DELTA_SECONDS_OVERFLOW_VALUE` (i32::MAX),
                            // which fits in `u32` after flooring.
                            Ok(f.floor() as u32)
                        }
                    }
                    _ => Error::e_because(
                        ErrorType::InternalError,
                        "could not parse value as u32",
                        int_err,
                    ),
                }
            }
        }
    }
}

/// An ordered map to store cache control key value pairs.
pub type DirectiveMap = IndexMap<DirectiveKey, Option<DirectiveValue>>;

/// Parsed Cache-Control directives
#[derive(Debug)]
pub struct CacheControl {
    /// The parsed directives
    pub directives: DirectiveMap,
    /// When set, delta-seconds directives (`max-age`, `s-maxage`,
    /// `stale-while-revalidate`, `stale-if-error`) accept fractional values
    /// and round them down to the nearest non-negative integer.
    ///
    /// Defaults to `false`, matching RFC 9111 strict integer parsing. Enable
    /// via [CacheControl::with_float_seconds] (or by assigning the field
    /// directly) for contexts that need to interoperate with upstreams that
    /// emit fractional ttls.
    pub allow_float_seconds: bool,
}

/// Cacheability calculated from cache control.
#[derive(Debug, PartialEq, Eq)]
pub enum Cacheable {
    /// Cacheable
    Yes,
    /// Not cacheable
    No,
    /// No directive found for explicit cacheability
    Default,
}

/// An iter over all the cache control directives
pub struct ListValueIter<'a>(slice::Split<'a, u8, fn(&u8) -> bool>);

impl<'a> ListValueIter<'a> {
    pub fn from(value: &'a DirectiveValue) -> Self {
        ListValueIter(value.parse_as_bytes().split(|byte| byte == &b','))
    }
}

// https://datatracker.ietf.org/doc/html/rfc9110#name-whitespace
// optional whitespace OWS = *(SP / HTAB); SP = 0x20, HTAB = 0x09
fn trim_ows(bytes: &[u8]) -> &[u8] {
    fn not_ows(b: &u8) -> bool {
        b != &b'\x20' && b != &b'\x09'
    }
    // find first non-OWS char from front (head) and from end (tail)
    let head = bytes.iter().position(not_ows).unwrap_or(0);
    let tail = bytes
        .iter()
        .rposition(not_ows)
        .map(|rpos| rpos + 1)
        .unwrap_or(head);
    &bytes[head..tail]
}

impl<'a> Iterator for ListValueIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        Some(trim_ows(self.0.next()?))
    }
}

// Originally from https://github.com/hapijs/wreck which has the following comments:
// Cache-Control   = 1#cache-directive
// cache-directive = token [ "=" ( token / quoted-string ) ]
// token           = [^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+
// quoted-string   = "(?:[^"\\]|\\.)*"
//
// note the `token` implementation excludes disallowed ASCII ranges
// and disallowed delimiters: https://datatracker.ietf.org/doc/html/rfc9110#section-5.6.2
// though it does not forbid `obs-text`: %x80-FF
static RE_CACHE_DIRECTIVE: Lazy<Regex> =
    // to break our version down further:
    // `(?-u)`: unicode support disabled, which puts the regex into "ASCII compatible mode" for specifying literal bytes like \x7F: https://docs.rs/regex/1.10.4/regex/bytes/index.html#syntax
    // `(?:^|(?:\s*[,;]\s*)`: allow either , or ; as a delimiter
    // `([^\x00-\x20\(\)<>@,;:\\"/\[\]\?=\{\}\x7F]+)`: token (directive name capture group)
    // `(?:=((?:[^\x00-\x20\(\)<>@,;:\\"/\[\]\?=\{\}\x7F]+|(?:"(?:[^"\\]|\\.)*"))))`: token OR quoted-string (directive value capture-group)
    Lazy::new(|| {
        Regex::new(r#"(?-u)(?:^|(?:\s*[,;]\s*))([^\x00-\x20\(\)<>@,;:\\"/\[\]\?=\{\}\x7F]+)(?:=((?:[^\x00-\x20\(\)<>@,;:\\"/\[\]\?=\{\}\x7F]+|(?:"(?:[^"\\]|\\.)*"))))?"#).unwrap()
    });

impl CacheControl {
    // Our parsing strategy is more permissive than the RFC in a few ways:
    // - Allows semicolons as delimiters (in addition to commas). See the regex above.
    // - Allows octets outside of visible ASCII in `token`s, and in later RFCs, octets outside of
    //   the `quoted-string` range: https://datatracker.ietf.org/doc/html/rfc9110#section-5.6.2
    //   See the regex above.
    // - Doesn't require no-value for "boolean directives," such as must-revalidate
    // - Allows quoted-string format for numeric values.
    fn from_headers(headers: http::header::GetAll<HeaderValue>) -> Option<Self> {
        let mut directives = IndexMap::new();
        // should iterate in header line insertion order
        for line in headers {
            for captures in RE_CACHE_DIRECTIVE.captures_iter(line.as_bytes()) {
                // directive key
                // header values don't have to be utf-8, but we store keys as
                // strings for case-insensitive matching. Known directive names
                // are mapped to enum variants (zero allocation).
                let key = captures.get(1).and_then(|cap| {
                    str::from_utf8(cap.as_bytes())
                        .ok()
                        .map(|token| DirectiveKey::from_lowercase_owned(token.to_lowercase()))
                });
                if key.is_none() {
                    continue;
                }
                // directive value
                // match token or quoted-string
                let value = captures
                    .get(2)
                    .map(|cap| DirectiveValue(cap.as_bytes().to_vec()));
                directives.insert(key.unwrap(), value);
            }
        }
        Some(CacheControl {
            directives,
            allow_float_seconds: false,
        })
    }

    /// Builder setter: enable fractional delta-seconds parsing.
    ///
    /// See [CacheControl::allow_float_seconds] for semantics. Returns `self`
    /// so it can be chained onto a parser call, e.g.
    /// `CacheControl::from_resp_headers(&resp).map(|cc| cc.with_float_seconds())`.
    pub fn with_float_seconds(mut self) -> Self {
        self.allow_float_seconds = true;
        self
    }

    /// Parse from the given header name in `headers`
    pub fn from_headers_named(header_name: &str, headers: &http::HeaderMap) -> Option<Self> {
        if !headers.contains_key(header_name) {
            return None;
        }

        Self::from_headers(headers.get_all(header_name))
    }

    /// Parse from the given header name in the [ReqHeader]
    pub fn from_req_headers_named(header_name: &str, req_header: &ReqHeader) -> Option<Self> {
        Self::from_headers_named(header_name, &req_header.headers)
    }

    /// Parse `Cache-Control` header name from the [ReqHeader]
    pub fn from_req_headers(req_header: &ReqHeader) -> Option<Self> {
        Self::from_req_headers_named("cache-control", req_header)
    }

    /// Parse from the given header name in the [RespHeader]
    pub fn from_resp_headers_named(header_name: &str, resp_header: &RespHeader) -> Option<Self> {
        Self::from_headers_named(header_name, &resp_header.headers)
    }

    /// Parse `Cache-Control` header name from the [RespHeader]
    pub fn from_resp_headers(resp_header: &RespHeader) -> Option<Self> {
        Self::from_resp_headers_named("cache-control", resp_header)
    }

    /// Whether the given directive is in the cache control.
    ///
    /// Accepts a string for convenience; known directive names are matched
    /// without allocation. Prefer [`has_directive`](Self::has_directive) when
    /// you already have a [`DirectiveKey`].
    ///
    /// **Note:** `key` must already be lowercase (e.g. `"max-age"`, not
    /// `"Max-Age"`). Directive names are stored in wire-format lowercase;
    /// a mixed-case input will silently miss.
    pub fn has_key(&self, key: &str) -> bool {
        self.has_directive(&DirectiveKey::from_lowercase(key))
    }

    /// Whether the given [`DirectiveKey`] is in the cache control.
    pub fn has_directive(&self, key: &DirectiveKey) -> bool {
        self.directives.contains_key(key)
    }

    /// Whether the `public` directive is in the cache control.
    pub fn public(&self) -> bool {
        self.has_directive(&DirectiveKey::Public)
    }

    /// Whether the given directive exists, and it has no value.
    fn has_key_without_value(&self, key: &DirectiveKey) -> bool {
        matches!(self.directives.get(key), Some(None))
    }

    /// Whether the standalone `private` exists in the cache control
    // RFC 7234: using the #field-name versions of `private`
    // means a shared cache "MUST NOT store the specified field-name(s),
    // whereas it MAY store the remainder of the response."
    // It must be a boolean form (no value) to apply to the whole response.
    // https://datatracker.ietf.org/doc/html/rfc7234#section-5.2.2.6
    pub fn private(&self) -> bool {
        self.has_key_without_value(&DirectiveKey::Private)
    }

    fn get_field_names(&self, key: &DirectiveKey) -> Option<ListValueIter<'_>> {
        let value = self.directives.get(key)?.as_ref()?;
        Some(ListValueIter::from(value))
    }

    /// Get the values of `private=`
    pub fn private_field_names(&self) -> Option<ListValueIter<'_>> {
        self.get_field_names(&DirectiveKey::Private)
    }

    /// Whether the standalone `no-cache` exists in the cache control
    pub fn no_cache(&self) -> bool {
        self.has_key_without_value(&DirectiveKey::NoCache)
    }

    /// Get the values of `no-cache=`
    pub fn no_cache_field_names(&self) -> Option<ListValueIter<'_>> {
        self.get_field_names(&DirectiveKey::NoCache)
    }

    /// Whether `no-store` exists.
    pub fn no_store(&self) -> bool {
        self.has_directive(&DirectiveKey::NoStore)
    }

    fn parse_delta_seconds(&self, key: &DirectiveKey) -> Result<Option<u32>> {
        if let Some(Some(dir_value)) = self.directives.get(key) {
            let value = if self.allow_float_seconds {
                dir_value.parse_as_delta_seconds_floor()?
            } else {
                dir_value.parse_as_delta_seconds()?
            };
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// Return the `max-age` seconds
    pub fn max_age(&self) -> Result<Option<u32>> {
        self.parse_delta_seconds(&DirectiveKey::MaxAge)
    }

    /// Return the `s-maxage` seconds
    pub fn s_maxage(&self) -> Result<Option<u32>> {
        self.parse_delta_seconds(&DirectiveKey::SMaxAge)
    }

    /// Return the `stale-while-revalidate` seconds
    pub fn stale_while_revalidate(&self) -> Result<Option<u32>> {
        self.parse_delta_seconds(&DirectiveKey::StaleWhileRevalidate)
    }

    /// Return the `stale-if-error` seconds
    pub fn stale_if_error(&self) -> Result<Option<u32>> {
        self.parse_delta_seconds(&DirectiveKey::StaleIfError)
    }

    /// Whether `must-revalidate` exists.
    pub fn must_revalidate(&self) -> bool {
        self.has_directive(&DirectiveKey::MustRevalidate)
    }

    /// Whether `proxy-revalidate` exists.
    pub fn proxy_revalidate(&self) -> bool {
        self.has_directive(&DirectiveKey::ProxyRevalidate)
    }

    /// Whether `only-if-cached` exists.
    pub fn only_if_cached(&self) -> bool {
        self.has_directive(&DirectiveKey::OnlyIfCached)
    }
}

impl InterpretCacheControl for CacheControl {
    fn is_cacheable(&self) -> Cacheable {
        if self.no_store() || self.private() {
            return Cacheable::No;
        }
        if self.has_directive(&DirectiveKey::SMaxAge)
            || self.has_directive(&DirectiveKey::MaxAge)
            || self.public()
        {
            return Cacheable::Yes;
        }
        Cacheable::Default
    }

    fn allow_caching_authorized_req(&self) -> bool {
        // RFC 7234 https://datatracker.ietf.org/doc/html/rfc7234#section-3
        // "MUST NOT" store requests with Authorization header
        // unless response contains one of these directives
        self.must_revalidate() || self.public() || self.has_directive(&DirectiveKey::SMaxAge)
    }

    fn fresh_duration(&self) -> Option<Duration> {
        if self.no_cache() {
            // always treated as stale
            return Some(Duration::ZERO);
        }
        let seconds = self
            .s_maxage()
            .ok()?
            // s-maxage not present
            .or_else(|| self.max_age().unwrap_or(None))
            .map(|duration| Duration::from_secs(duration as u64))?;
        Some(seconds)
    }

    fn serve_stale_while_revalidate_duration(&self) -> Option<Duration> {
        // RFC 7234: these directives forbid serving stale.
        // https://datatracker.ietf.org/doc/html/rfc7234#section-4.2.4
        if self.must_revalidate()
            || self.proxy_revalidate()
            || self.has_directive(&DirectiveKey::SMaxAge)
        {
            return Some(Duration::ZERO);
        }
        self.stale_while_revalidate()
            .unwrap_or(None)
            .map(|secs| Duration::from_secs(secs as u64))
    }

    fn serve_stale_if_error_duration(&self) -> Option<Duration> {
        if self.must_revalidate()
            || self.proxy_revalidate()
            || self.has_directive(&DirectiveKey::SMaxAge)
        {
            return Some(Duration::ZERO);
        }
        self.stale_if_error()
            .unwrap_or(None)
            .map(|secs| Duration::from_secs(secs as u64))
    }

    // Strip header names listed in `private` or `no-cache` directives from a response.
    fn strip_private_headers(&self, resp_header: &mut ResponseHeader) {
        fn strip_listed_headers(resp: &mut ResponseHeader, field_names: ListValueIter) {
            for name in field_names {
                if let Ok(header) = HeaderName::from_bytes(name) {
                    resp.remove_header(&header);
                }
            }
        }

        if let Some(headers) = self.private_field_names() {
            strip_listed_headers(resp_header, headers);
        }
        // We interpret `no-cache` the same way as `private`,
        // though technically it has a less restrictive requirement
        // ("MUST NOT be sent in the response to a subsequent request
        // without successful revalidation with the origin server").
        // https://datatracker.ietf.org/doc/html/rfc7234#section-5.2.2.2
        if let Some(headers) = self.no_cache_field_names() {
            strip_listed_headers(resp_header, headers);
        }
    }
}

/// `InterpretCacheControl` provides a meaningful interface to the parsed `CacheControl`.
/// These functions actually interpret the parsed cache-control directives to return
/// the freshness or other cache meta values that cache-control is signaling.
///
/// By default `CacheControl` implements an RFC-7234 compliant reading that assumes it is being
/// used with a shared (proxy) cache.
pub trait InterpretCacheControl {
    /// Does cache-control specify this response is cacheable?
    ///
    /// Note that an RFC-7234 compliant cacheability check must also
    /// check if the request contained the Authorization header and
    /// `allow_caching_authorized_req`.
    fn is_cacheable(&self) -> Cacheable;

    /// Does this cache-control allow caching a response to
    /// a request with the Authorization header?
    fn allow_caching_authorized_req(&self) -> bool;

    /// Returns freshness ttl specified in cache-control
    ///
    /// - `Some(_)` indicates cache-control specifies a valid ttl. Some(Duration::ZERO) = always stale.
    /// - `None` means cache-control did not specify a valid ttl.
    fn fresh_duration(&self) -> Option<Duration>;

    /// Returns stale-while-revalidate ttl,
    ///
    /// The result should consider all the relevant cache directives, not just SWR header itself.
    ///
    /// Some(0) means serving such stale is disallowed by directive like `must-revalidate`
    /// or `stale-while-revalidater=0`.
    ///
    /// `None` indicates no SWR ttl was specified.
    fn serve_stale_while_revalidate_duration(&self) -> Option<Duration>;

    /// Returns stale-if-error ttl,
    ///
    /// The result should consider all the relevant cache directives, not just SIE header itself.
    ///
    /// Some(0) means serving such stale is disallowed by directive like `must-revalidate`
    /// or `stale-if-error=0`.
    ///
    /// `None` indicates no SIE ttl was specified.
    fn serve_stale_if_error_duration(&self) -> Option<Duration>;

    /// Strip header names listed in `private` or `no-cache` directives from a response,
    /// usually prior to storing that response in cache.
    fn strip_private_headers(&self, resp_header: &mut ResponseHeader);
}
