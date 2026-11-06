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

//! CONNECT protocol over http 1.1 via raw Unix domain socket
//!
//! This mod implements the most rudimentary CONNECT client over raw stream.
//! The idea is to yield raw stream once the CONNECT handshake is complete
//! so that the protocol encapsulated can use the stream directly.
//! This idea only works for CONNECT over HTTP 1.1 and localhost (or where the server is close by).

use std::any::Any;

use super::http::v1::client::HttpSession;
use super::http::v1::common::*;
use super::Stream;

use bytes::{BufMut, BytesMut};
use http::request::Parts as ReqHeader;
use http::Version;
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use pingora_http::ResponseHeader;
use tokio::io::AsyncWriteExt;

/// Try to establish a CONNECT proxy via the given `stream`.
///
/// `request_header` should include the necessary request headers for the CONNECT protocol.
///
/// When successful, a [`Stream`] will be returned which is the established CONNECT proxy connection.
pub async fn connect<P>(
    stream: Stream,
    request_header: &ReqHeader,
    peer: &P,
) -> Result<(Stream, ProxyDigest)>
where
    P: crate::upstreams::peer::Peer,
{
    let mut http = HttpSession::new(stream);

    // We write to stream directly because HttpSession doesn't write req header in auth form
    let to_wire = http_req_header_to_wire_auth_form(request_header);
    http.underlying_stream
        .write_all(to_wire.as_ref())
        .await
        .or_err(WriteError, "while writing request headers")?;
    http.underlying_stream
        .flush()
        .await
        .or_err(WriteError, "while flushing request headers")?;

    // TODO: set http.read_timeout
    let resp_header = http.read_resp_header_parts().await?;
    Ok((
        http.underlying_stream,
        validate_connect_response(resp_header, peer, request_header)?,
    ))
}

/// Generate the CONNECT header for the given destination
pub fn generate_connect_header<'a, H, S>(
    host: &str,
    port: u16,
    headers: H,
) -> Result<Box<ReqHeader>>
where
    S: AsRef<[u8]>,
    H: Iterator<Item = (S, &'a Vec<u8>)>,
{
    // TODO: valid that host doesn't have port

    let authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let req = http::request::Builder::new()
        .version(http::Version::HTTP_11)
        .method(http::method::Method::CONNECT)
        .uri(format!("https://{authority}/")) // scheme doesn't matter
        .header(http::header::HOST, &authority);

    let (mut req, _) = match req.body(()) {
        Ok(r) => r.into_parts(),
        Err(e) => {
            return Err(e).or_err(InvalidHTTPHeader, "Invalid CONNECT request");
        }
    };

    for (k, v) in headers {
        let header_name = http::header::HeaderName::from_bytes(k.as_ref())
            .or_err(InvalidHTTPHeader, "Invalid CONNECT request")?;
        let header_value = http::header::HeaderValue::from_bytes(v.as_slice())
            .or_err(InvalidHTTPHeader, "Invalid CONNECT request")?;
        req.headers.insert(header_name, header_value);
    }

    Ok(Box::new(req))
}

/// The information about the CONNECT proxy.
#[derive(Debug)]
pub struct ProxyDigest {
    /// The response header the proxy returns
    pub response: Box<ResponseHeader>,
    /// Optional arbitrary data.
    pub user_data: Option<Box<dyn Any + Send + Sync>>,
}

impl ProxyDigest {
    pub fn new(
        response: Box<ResponseHeader>,
        user_data: Option<Box<dyn Any + Send + Sync>>,
    ) -> Self {
        ProxyDigest {
            response,
            user_data,
        }
    }
}

/// The error returned when the CONNECT proxy fails to establish.
#[derive(Debug)]
pub struct ConnectProxyError {
    /// The response header the proxy returns
    pub response: Box<ResponseHeader>,
}

impl ConnectProxyError {
    pub fn boxed_new(response: Box<ResponseHeader>) -> Box<Self> {
        Box::new(ConnectProxyError { response })
    }
}

impl std::fmt::Display for ConnectProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const PROXY_STATUS: &str = "proxy-status";

        let reason = self
            .response
            .headers
            .get(PROXY_STATUS)
            .and_then(|s| s.to_str().ok())
            .unwrap_or("missing proxy-status header value");
        write!(
            f,
            "Failed CONNECT Response: status {}, proxy-status {reason}",
            self.response.status
        )
    }
}

impl std::error::Error for ConnectProxyError {}

#[inline]
fn http_req_header_to_wire_auth_form(req: &ReqHeader) -> BytesMut {
    let mut buf = BytesMut::with_capacity(512);

    // Request-Line
    let method = req.method.as_str().as_bytes();
    buf.put_slice(method);
    buf.put_u8(b' ');
    // NOTE: CONNECT doesn't need URI path so we just skip that
    if let Some(path) = req.uri.authority() {
        buf.put_slice(path.as_str().as_bytes());
    }
    buf.put_u8(b' ');

    let version = match req.version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        _ => "HTTP/0.9",
    };
    buf.put_slice(version.as_bytes());
    buf.put_slice(CRLF);

    // headers
    let headers = &req.headers;
    for (key, value) in headers.iter() {
        buf.put_slice(key.as_ref());
        buf.put_slice(HEADER_KV_DELIMITER);
        buf.put_slice(value.as_ref());
        buf.put_slice(CRLF);
    }

    buf.put_slice(CRLF);
    buf
}

#[inline]
fn validate_connect_response<P>(
    resp: Box<ResponseHeader>,
    peer: &P,
    req: &ReqHeader,
) -> Result<ProxyDigest>
where
    P: crate::upstreams::peer::Peer,
{
    if !resp.status.is_success() {
        return Error::e_because(
            ConnectProxyFailure,
            "None 2xx code",
            ConnectProxyError::boxed_new(resp),
        );
    }

    // Checking Content-Length and Transfer-Encoding is optional because we already ignore them.
    // We choose to do so because we want to be strict for internal use of CONNECT.
    // Ignore Content-Length header because our internal CONNECT server is coded to send it.
    if resp.headers.get(http::header::TRANSFER_ENCODING).is_some() {
        return Error::e_because(
            ConnectProxyFailure,
            "Invalid Transfer-Encoding presents",
            ConnectProxyError::boxed_new(resp),
        );
    }

    let user_data = peer
        .proxy_digest_user_data_hook()
        .and_then(|hook| hook(req, &resp));
    Ok(ProxyDigest::new(resp, user_data))
}
