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

//! Utility functions to help process HTTP headers for caching

use super::*;
use crate::cache_control::{CacheControl, Cacheable, InterpretCacheControl};
use crate::RespCacheable::*;

use cache_control::DELTA_SECONDS_OVERFLOW_VALUE;
use http::{header, HeaderValue};
use httpdate::HttpDate;
use log::debug;
use pingora_http::RequestHeader;

/// Decide if the request can be cacheable
pub fn request_cacheable(req_header: &ReqHeader) -> bool {
    // TODO: the check is incomplete
    matches!(req_header.method, Method::GET | Method::HEAD)
}

/// Decide if the response is cacheable.
///
/// `cache_control` is the parsed [CacheControl] from the response header. It is a standalone
/// argument so that caller has the flexibility to choose to use, change or ignore it.
pub fn resp_cacheable(
    cache_control: Option<&CacheControl>,
    mut resp_header: ResponseHeader,
    authorization_present: bool,
    defaults: &CacheMetaDefaults,
) -> RespCacheable {
    let now = SystemTime::now();
    let expire_time = calculate_fresh_until(
        now,
        cache_control,
        &resp_header,
        authorization_present,
        defaults,
    );
    if let Some(fresh_until) = expire_time {
        let (stale_while_revalidate_duration, stale_if_error_duration) =
            calculate_serve_stale_durations(cache_control, defaults);

        if let Some(cc) = cache_control {
            cc.strip_private_headers(&mut resp_header);
        }
        return Cacheable(CacheMeta::new(
            fresh_until,
            now,
            stale_while_revalidate_duration,
            stale_if_error_duration,
            resp_header,
        ));
    }
    Uncacheable(NoCacheReason::OriginNotCache)
}

/// Calculate the [SystemTime] at which the asset expires
///
/// Return None when not cacheable.
pub fn calculate_fresh_until(
    now: SystemTime,
    cache_control: Option<&CacheControl>,
    resp_header: &RespHeader,
    authorization_present: bool,
    defaults: &CacheMetaDefaults,
) -> Option<SystemTime> {
    fn freshness_ttl_to_time(now: SystemTime, fresh: Duration) -> Option<SystemTime> {
        if fresh.is_zero() {
            // ensure that the response is treated as stale
            now.checked_sub(Duration::from_secs(1))
        } else {
            now.checked_add(fresh)
        }
    }

    // A request with Authorization is normally not cacheable, unless Cache-Control allows it
    if authorization_present {
        let uncacheable = cache_control
            .as_ref()
            .is_none_or(|cc| !cc.allow_caching_authorized_req());
        if uncacheable {
            return None;
        }
    }

    let uncacheable = cache_control
        .as_ref()
        .is_some_and(|cc| cc.is_cacheable() == Cacheable::No);
    if uncacheable {
        return None;
    }

    // For TTL check cache-control first, then expires header, then defaults
    cache_control
        .and_then(|cc| {
            cc.fresh_duration()
                .and_then(|ttl| freshness_ttl_to_time(now, ttl))
        })
        .or_else(|| calculate_expires_header_time(resp_header))
        .or_else(|| {
            defaults
                .fresh_sec(resp_header.status)
                .and_then(|ttl| freshness_ttl_to_time(now, ttl))
        })
}

/// Calculate the expire time from the `Expires` header only
pub fn calculate_expires_header_time(resp_header: &RespHeader) -> Option<SystemTime> {
    // according to RFC 7234:
    // https://datatracker.ietf.org/doc/html/rfc7234#section-4.2.1
    // - treat multiple expires headers as invalid
    // https://datatracker.ietf.org/doc/html/rfc7234#section-5.3
    // - "MUST interpret invalid date formats... as representing a time in the past"
    fn parse_expires_value(expires_value: &HeaderValue) -> Option<SystemTime> {
        let expires = expires_value.to_str().ok()?;
        Some(SystemTime::from(
            expires
                .parse::<HttpDate>()
                .map_err(|e| debug!("Invalid HttpDate in Expires: {}, error: {}", expires, e))
                .ok()?,
        ))
    }

    let mut expires_iter = resp_header.headers.get_all("expires").iter();
    let expires_header = expires_iter.next();
    if expires_header.is_none() || expires_iter.next().is_some() {
        return None;
    }
    parse_expires_value(expires_header.unwrap()).or(Some(SystemTime::UNIX_EPOCH))
}

/// Calculates stale-while-revalidate and stale-if-error seconds from Cache-Control or the [CacheMetaDefaults].
pub fn calculate_serve_stale_durations(
    cache_control: Option<&impl InterpretCacheControl>,
    defaults: &CacheMetaDefaults,
) -> (u32, u32) {
    let serve_stale_while_revalidate = cache_control
        .and_then(|cc| cc.serve_stale_while_revalidate_duration())
        .unwrap_or_else(|| Duration::from_secs(defaults.serve_stale_while_revalidate_sec() as u64));
    let serve_stale_if_error = cache_control
        .and_then(|cc| cc.serve_stale_if_error_duration())
        .unwrap_or_else(|| Duration::from_secs(defaults.serve_stale_if_error_sec() as u64));
    (
        serve_stale_while_revalidate
            .as_secs()
            .try_into()
            .unwrap_or(DELTA_SECONDS_OVERFLOW_VALUE),
        serve_stale_if_error
            .as_secs()
            .try_into()
            .unwrap_or(DELTA_SECONDS_OVERFLOW_VALUE),
    )
}

/// Filters to run when sending requests to upstream
pub mod upstream {
    use super::*;

    /// Adjust the request header for cacheable requests
    ///
    /// This filter does the following in order to fetch the entire response to cache
    /// - Convert HEAD to GET
    /// - `If-*` headers are removed
    /// - `Range` header is removed
    ///
    /// When `meta` is set, this function will inject `If-modified-since` according to the `Last-Modified` header
    /// and inject `If-none-match` according to `Etag` header
    pub fn request_filter(req: &mut RequestHeader, meta: Option<&CacheMeta>) {
        // change HEAD to GET, HEAD itself is not semantically cacheable
        if req.method == Method::HEAD {
            req.set_method(Method::GET);
        }

        // remove downstream precondition headers https://datatracker.ietf.org/doc/html/rfc7232#section-3
        // we'd like to cache the 200 not the 304
        req.remove_header(&header::IF_MATCH);
        req.remove_header(&header::IF_NONE_MATCH);
        req.remove_header(&header::IF_MODIFIED_SINCE);
        req.remove_header(&header::IF_UNMODIFIED_SINCE);
        // see below range header
        req.remove_header(&header::IF_RANGE);

        // remove downstream range header as we'd like to cache the entire response (this might change in the future)
        req.remove_header(&header::RANGE);

        // we have a presumably staled response already, add precondition headers for revalidation
        if let Some(m) = meta {
            // rfc7232: "SHOULD send both validators in cache validation" but
            // there have been weird cases that an origin has matching etag but not Last-Modified
            if let Some(since) = m.headers().get(&header::LAST_MODIFIED) {
                req.insert_header(header::IF_MODIFIED_SINCE, since).unwrap();
            }
            if let Some(etag) = m.headers().get(&header::ETAG) {
                req.insert_header(header::IF_NONE_MATCH, etag).unwrap();
            }
        }
    }
}
