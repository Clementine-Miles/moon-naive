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

//! HTTP authority consistency checks shared by protocol versions and proxy egress.
//!
//! The boundary classification these checks act on lives in [`pingora_http::authority`] and
//! is re-exported here.

use http::{header, HeaderValue};
use pingora_error::{Error, ErrorType::InvalidHTTPHeader, Result};
use pingora_http::RequestHeader;

pub use pingora_http::authority::{
    is_http_family_scheme, raw_target_authority, RawTargetAuthority,
};

/// Validate that a request has one unambiguous authority.
///
/// CONNECT handling:
///
/// - A valid authority with a port may omit `Host`; a present `Host` must match.
/// - Malformed authority prefixes require a byte-exact `Host` match.
/// - Other nonstandard forms remain application-defined.
/// - Userinfo and ambiguous bracket or port forms are rejected.
///
/// Other requests reject duplicate `Host` ([RFC 9112 section 3.2]), userinfo
/// ([RFC 9110 section 4.2.4]), inconsistent absolute-form authority, and targets whose authority
/// changes under slash or backslash normalization. This is stricter than
/// [RFC 9112 section 3.2.2], which replaces conflicting `Host`. Userinfo is unsafe because
/// [`http::Uri::host`] strips it.
///
/// Authority bytes otherwise remain opaque. HTTP/1 ingress and standard proxy egress call this;
/// HTTP/2 performs equivalent stream-local checks.
///
/// [RFC 9110 section 4.2.4]: https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.4
/// [RFC 9112 section 3.2]: https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2
/// [RFC 9112 section 3.2.2]: https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2
pub fn validate_request_authority(req: &RequestHeader) -> Result<()> {
    validate_request_authority_fields(req)?;

    let host = req.headers.get(header::HOST);

    if req.method == http::Method::CONNECT {
        return validate_connect_authority(req.raw_path(), host);
    }

    match raw_target_authority(req.raw_path()) {
        RawTargetAuthority::None => {}
        RawTargetAuthority::AmbiguousAuthority => {
            return Error::e_explain(
                InvalidHTTPHeader,
                "ambiguous HTTP absolute-form request target",
            );
        }
        RawTargetAuthority::Absolute {
            scheme, authority, ..
        } => {
            if is_http_family_scheme(scheme) {
                http::uri::Authority::try_from(authority).map_err(|cause| {
                    Error::because(
                        InvalidHTTPHeader,
                        "unparseable absolute-form authority",
                        cause,
                    )
                })?;
            }
            if authority.contains(&b'@') {
                return Error::e_explain(InvalidHTTPHeader, "userinfo in request target");
            }
            if host.is_some_and(|host| host.as_bytes() != authority) {
                return Error::e_explain(
                    InvalidHTTPHeader,
                    "Host header differs from request-target authority",
                );
            }
        }
    }

    Ok(())
}

/// Validate authority fields shared by H1 and H2 ingress.
pub(super) fn validate_request_authority_fields(req: &RequestHeader) -> Result<()> {
    let mut hosts = req.headers.get_all(header::HOST).iter();
    let (host, duplicate_host) = (hosts.next(), hosts.next());

    if duplicate_host.is_some() {
        return Error::e_explain(InvalidHTTPHeader, "multiple Host header fields");
    }

    if host.is_some_and(|host| host.as_bytes().contains(&b'@')) {
        return Error::e_explain(InvalidHTTPHeader, "userinfo in Host header");
    }

    let uri_authority = req.uri.authority().map(|authority| authority.as_str());
    if uri_authority.is_some_and(|authority| authority.contains('@')) {
        return Error::e_explain(InvalidHTTPHeader, "userinfo in URI authority");
    }

    if host
        .zip(uri_authority)
        .is_some_and(|(host, authority)| host.as_bytes() != authority.as_bytes())
    {
        return Error::e_explain(InvalidHTTPHeader, "Host header differs from URI authority");
    }

    Ok(())
}

/// Reconcile authority-like CONNECT targets with `Host` while preserving custom target forms.
fn validate_connect_authority(target: &[u8], host: Option<&HeaderValue>) -> Result<()> {
    let authority_end = target
        .iter()
        .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
        .unwrap_or(target.len());
    let authority_target = &target[..authority_end];

    // For ordinary CONNECT this is `host:port`; for absolute-form it is only the scheme (`http:`),
    // so the fallback classifier below must extract and validate the actual authority separately.
    if authority_target.contains(&b'@') {
        return Error::e_explain(InvalidHTTPHeader, "userinfo in request target");
    }

    if has_ambiguous_port_suffix(authority_target) {
        return Error::e_explain(InvalidHTTPHeader, "ambiguous CONNECT request target");
    }

    // Parse ordinary authority-form (`host:port`) and reconcile by components.
    let parsed_authority = http::uri::Authority::try_from(authority_target);
    if let Ok(authority) = &parsed_authority {
        if authority.port().is_some() {
            let Some(host) = host else {
                return Ok(());
            };
            return reconcile_connect_host(authority_target, authority.host().as_bytes(), host);
        }
    }

    // Handle absolute (`http://host/path`), ambiguous (`http:/\host`), and custom (`unix:/path`)
    // forms when ordinary parsing did not return above.
    match raw_target_authority(target) {
        RawTargetAuthority::Absolute { authority, .. } => {
            if authority.contains(&b'@') {
                return Error::e_explain(InvalidHTTPHeader, "userinfo in request target");
            }
            if has_ambiguous_port_suffix(authority) {
                return Error::e_explain(InvalidHTTPHeader, "ambiguous CONNECT request target");
            }
            let Some(host) = host else {
                return Error::e_explain(
                    InvalidHTTPHeader,
                    "missing Host header for absolute-form CONNECT request target",
                );
            };
            // Reparse the authority extracted from the absolute-form target.
            match http::uri::Authority::try_from(authority) {
                Ok(parsed) => reconcile_connect_host(authority, parsed.host().as_bytes(), host),
                Err(_) => reconcile_connect_host(authority, authority, host),
            }
        }
        RawTargetAuthority::AmbiguousAuthority => {
            Error::e_explain(InvalidHTTPHeader, "ambiguous CONNECT request target")
        }
        // An authority prefix that does not parse cannot be reconciled by component, so require it
        // to match `Host` byte-for-byte: otherwise one malformed byte would escape the reconciliation
        // the same target is subject to without it. An empty prefix carries no authority to disagree
        // about.
        RawTargetAuthority::None if !authority_target.is_empty() && parsed_authority.is_err() => {
            let Some(host) = host else {
                return Error::e_explain(
                    InvalidHTTPHeader,
                    "missing Host header for malformed CONNECT request target",
                );
            };
            reconcile_connect_host(authority_target, authority_target, host)
        }
        RawTargetAuthority::None => Ok(()),
    }
}

/// Accept `Host` only when it names the complete CONNECT authority or its host component.
///
/// The host-only form follows the [RFC 9112 section 3.2.3] example:
/// `CONNECT example.com:80` with `Host: example.com`.
///
/// [RFC 9112 section 3.2.3]: https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.3
fn reconcile_connect_host(
    authority: &[u8],
    authority_host: &[u8],
    host: &HeaderValue,
) -> Result<()> {
    if host.as_bytes() == authority || host.as_bytes() == authority_host {
        Ok(())
    } else {
        Error::e_explain(
            InvalidHTTPHeader,
            "Host header differs from CONNECT request target",
        )
    }
}

/// Detect multiple unbracketed port separators, whose interpretation differs between parsers.
pub(super) fn has_ambiguous_port_suffix(authority: &[u8]) -> bool {
    let mut inside_brackets = authority.first() == Some(&b'[');
    let mut suffix_colon_seen = false;

    for (index, &byte) in authority.iter().enumerate() {
        if inside_brackets {
            if index == 0 {
                continue;
            }
            match byte {
                b'[' => return true,
                b']' => inside_brackets = false,
                _ => {}
            }
            continue;
        }

        match byte {
            b'[' | b']' => return true,
            b':' if suffix_colon_seen => return true,
            b':' => suffix_colon_seen = true,
            _ => {}
        }
    }

    inside_brackets
}
