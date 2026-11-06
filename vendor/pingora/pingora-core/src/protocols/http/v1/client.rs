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

//! HTTP/1.x client session

use bytes::{BufMut, Bytes, BytesMut};
use http::{header, header::AsHeaderName, HeaderValue, StatusCode, Version};
use log::{debug, trace};
use pingora_error::{Error, ErrorType::*, OrErr, Result, RetryType};
use pingora_http::{HMap, IntoCaseHeaderName, RequestHeader, ResponseHeader};
use pingora_timeout::timeout;
use std::io::ErrorKind;
use std::str;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::body::{BodyReader, BodyWriter};
use super::common::*;
use crate::protocols::http::HttpTask;
use crate::protocols::{Digest, SocketAddr, Stream, UniqueID, UniqueIDType};
use crate::utils::{BufRef, KVRef};

/// The HTTP 1.x client session
pub struct HttpSession {
    buf: Bytes,
    /// In-progress response header bytes, kept on the session so cancelled reads can resume.
    response_header_read_buf: BytesMut,
    pub(crate) underlying_stream: Stream,
    raw_header: Option<BufRef>,
    preread_body: Option<BufRef>,
    body_reader: BodyReader,
    body_writer: BodyWriter,
    // timeouts:
    /// The read timeout, which will be applied to both reading the header and the body.
    /// The timeout is reset on every read. This is not a timeout on the overall duration of the
    /// response.
    pub read_timeout: Option<Duration>,
    /// The write timeout which will be applied to both writing request header and body.
    /// The timeout is reset on every write. This is not a timeout on the overall duration of the
    /// request.
    pub write_timeout: Option<Duration>,
    keepalive_timeout: KeepaliveStatus,
    pub(crate) digest: Box<Digest>,
    response_header: Option<Box<ResponseHeader>>,
    request_written: Option<Box<RequestHeader>>,
    bytes_sent: usize,
    /// Total response body payload bytes received from upstream
    body_recv: usize,
    // Tracks whether upgrade handshake was successfully completed
    upgraded: bool,
    // Tracks whether downstream request body started sending upgraded bytes
    received_upgrade_req_body: bool,
    // Tracks whether the response read was ever close-delimited
    // (even after body complete)
    close_delimited_resp: bool,
    // If allowed, does not fail with error on invalid content-length
    // (treats as close-delimited response).
    allow_h1_response_invalid_content_length: bool,
}

/// HTTP 1.x client session
impl HttpSession {
    /// Create a new http client session from an established (TCP or TLS) [`Stream`].
    pub fn new(stream: Stream) -> Self {
        // TODO: maybe we should put digest in the connection itself
        let digest = Box::new(Digest {
            ssl_digest: stream.get_ssl_digest(),
            timing_digest: stream.get_timing_digest(),
            proxy_digest: stream.get_proxy_digest(),
            socket_digest: stream.get_socket_digest(),
        });
        HttpSession {
            underlying_stream: stream,
            buf: Bytes::new(), // zero size, will be replaced by parsed header later
            response_header_read_buf: BytesMut::new(),
            raw_header: None,
            preread_body: None,
            body_reader: BodyReader::new(true),
            body_writer: BodyWriter::new(),
            keepalive_timeout: KeepaliveStatus::Off,
            response_header: None,
            request_written: None,
            read_timeout: None,
            write_timeout: None,
            digest,
            bytes_sent: 0,
            body_recv: 0,
            upgraded: false,
            received_upgrade_req_body: false,
            close_delimited_resp: false,
            allow_h1_response_invalid_content_length: false,
        }
    }

    /// Create a new http client session and apply peer options
    pub fn new_with_options<P: crate::upstreams::peer::Peer>(stream: Stream, peer: &P) -> Self {
        let mut session = Self::new(stream);
        if let Some(options) = peer.get_peer_options() {
            session.set_allow_h1_response_invalid_content_length(
                options.allow_h1_response_invalid_content_length,
            );
        }
        session
    }

    /// Write the request header to the server
    /// After the request header is sent. The caller can either start reading the response or
    /// sending request body if any.
    pub async fn write_request_header(&mut self, req: Box<RequestHeader>) -> Result<usize> {
        // TODO: make sure this can only be called once
        // init body writer
        self.init_req_body_writer(&req);

        let to_wire = http_req_header_to_wire(&req).ok_or_else(|| {
            Error::explain(
                InvalidHTTPHeader,
                "request-line contains forbidden delimiter bytes or unsupported HTTP version",
            )
        })?;
        trace!("Writing request header: {to_wire:?}");

        let write_fut = self.underlying_stream.write_all(to_wire.as_ref());
        match self.write_timeout {
            Some(t) => match timeout(t, write_fut).await {
                Ok(res) => res,
                Err(_) => Err(std::io::Error::from(ErrorKind::TimedOut)),
            },
            None => write_fut.await,
        }
        .map_err(|e| match e.kind() {
            ErrorKind::TimedOut => {
                Error::because(WriteTimedout, "while writing request headers (timeout)", e)
            }
            _ => Error::because(WriteError, "while writing request headers", e),
        })?;

        self.underlying_stream
            .flush()
            .await
            .or_err(WriteError, "flushing request header")?;

        // write was successful
        self.request_written = Some(req);
        Ok(to_wire.len())
    }

    async fn do_write_body(&mut self, buf: &[u8]) -> Result<Option<usize>> {
        let written = self
            .body_writer
            .write_body(&mut self.underlying_stream, buf)
            .await;

        if let Ok(Some(num_bytes)) = written {
            self.bytes_sent += num_bytes;
        }

        written
    }

    /// Write request body. Return Ok(None) if no more body should be written, either due to
    /// Content-Length or the last chunk is already sent
    pub async fn write_body(&mut self, buf: &[u8]) -> Result<Option<usize>> {
        // TODO: verify that request header is sent already
        match self.write_timeout {
            Some(t) => match timeout(t, self.do_write_body(buf)).await {
                Ok(res) => res,
                Err(_) => Error::e_explain(WriteTimedout, format!("writing body, timeout: {t:?}")),
            },
            None => self.do_write_body(buf).await,
        }
    }

    /// Flush local buffer and notify the server by sending the last chunk if chunked encoding is
    /// used.
    pub fn set_request_trailers(&mut self, trailers: http::HeaderMap) -> Result<()> {
        self.body_writer.set_trailers(trailers)
    }
    pub async fn finish_body(&mut self) -> Result<Option<usize>> {
        let res = self.body_writer.finish(&mut self.underlying_stream).await?;
        self.underlying_stream
            .flush()
            .await
            .or_err(WriteError, "flushing body")?;

        if self.upgraded && self.received_upgrade_req_body {
            self.underlying_stream.shutdown().await.or_err(WriteError,"half-closing upgraded request")?;
        }
        Ok(res)
    }

    // Validate the response header read. This function must be called after the response header
    // read.
    fn validate_response(&self) -> Result<()> {
        let resp_header = self
            .response_header
            .as_ref()
            .expect("response header must be read");

        // Validate/reconcile Content-Length per RFC 9110 section 8.6 (hyper
        // parity): identical duplicates and comma-combined identical values are
        // accepted and collapsed. Conflicting or duplicate values are always an
        // unrecoverable framing error. A peer may opt to tolerate a single,
        // otherwise-invalid value and treat the response as close-delimited.
        // Note: Content-Length is already removed if Transfer-Encoding is present.
        if let Err(e) = super::common::validate_content_length(&resp_header.headers) {
            if self.allow_h1_response_invalid_content_length
                && super::common::content_length_is_single_token(&resp_header.headers)
            {
                debug!(
                    "tolerating invalid Content-Length ({e}); \
                     treating response as close-delimited"
                );
            } else {
                return Err(e);
            }
        }

        Ok(())
    }

    fn clear_response_header_read_state(&mut self) {
        self.response_header_read_buf.clear();
        self.preread_body = None;
    }

    fn fail_response_header_read<T>(&mut self, e: pingora_error::BError) -> Result<T> {
        self.clear_response_header_read_state();
        Err(e)
    }

    /// Read the response header from the server
    /// This function can be called multiple times, if the headers received are just informational
    /// headers.
    pub async fn read_response(&mut self) -> Result<usize> {
        let mut parse_existing_buffer = true;

        if self.response_header_read_buf.is_empty() {
            // preread_body is set after a completed valid response header is read.
            // If read_response() is called multiple times (i.e. after informational
            // responses), already-read bytes after the 1xx header should be parsed as
            // more response headers. (https://datatracker.ietf.org/doc/html/rfc9110#section-15.2
            // "A 1xx response is terminated by the end of the header section;
            // it cannot contain content or trailers.")
            //
            // Move these bytes into response_header_read_buf so that if parsing the
            // next header is cancelled, a future call can resume without dropping the
            // preread bytes.
            if let Some(preread) = self.preread_body.take().filter(|b| !b.is_empty()) {
                self.response_header_read_buf
                    .put_slice(preread.get(&self.buf));
            } else {
                // If this next read_response call completes successfully, self.buf
                // will be reset to the last response + any body.
                self.buf.clear();
                parse_existing_buffer = false;
            }
        }

        loop {
            if parse_existing_buffer {
                let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
                let mut resp = httparse::Response::new(&mut headers);
                let parsed = parse_resp_buffer(&mut resp, &self.response_header_read_buf);
                match parsed {
                    HeaderParseState::Complete(s) => {
                        let total_read = self.response_header_read_buf.len();
                        let base = self.response_header_read_buf.as_ptr() as usize;
                        let mut header_refs = Vec::<KVRef>::with_capacity(resp.headers.len());

                        // Note: resp.headers has the correct number of headers
                        // while header_refs doesn't as it is still empty
                        let _num_headers = populate_headers(base, &mut header_refs, resp.headers);

                        let mut response_header = match ResponseHeader::build(
                            resp.code.unwrap(),
                            Some(resp.headers.len()),
                        ) {
                            Ok(header) => Box::new(header),
                            Err(e) => return self.fail_response_header_read(e),
                        };

                        // TODO: enforce https://datatracker.ietf.org/doc/html/rfc9110#section-15.2
                        // "Since HTTP/1.0 did not define any 1xx status codes,
                        // a server MUST NOT send a 1xx response to an HTTP/1.0 client."
                        response_header.set_version(match resp.version {
                            Some(1) => Version::HTTP_11,
                            Some(0) => Version::HTTP_10,
                            _ => Version::HTTP_09,
                        });

                        if let Err(e) = response_header.set_reason_phrase(resp.reason) {
                            return self.fail_response_header_read(e);
                        }

                        let buf = std::mem::take(&mut self.response_header_read_buf).freeze();

                        for header in header_refs {
                            let header_name = header.get_name_bytes(&buf);
                            let header_name = header_name.into_case_header_name();
                            let value_bytes = header.get_value_bytes(&buf);
                            let header_value = pingora_http::header_value_from_raw(value_bytes);
                            if let Err(e) = response_header
                                .append_header(header_name, header_value)
                                .or_err(InvalidHTTPHeader, "while parsing request header")
                            {
                                return self.fail_response_header_read(e);
                            }
                        }

                        let contains_transfer_encoding = response_header
                            .headers
                            .contains_key(header::TRANSFER_ENCODING);
                        let contains_content_length =
                            response_header.headers.contains_key(header::CONTENT_LENGTH);

                        // Transfer encoding overrides content length, so when
                        // both are present, we MUST remove content length. This is
                        // https://datatracker.ietf.org/doc/html/rfc9112#section-6.3-2.3
                        if contains_content_length && contains_transfer_encoding {
                            response_header.remove_header(&header::CONTENT_LENGTH);
                        }

                        self.raw_header = Some(BufRef(0, s));
                        self.preread_body = Some(BufRef(s, total_read));
                        self.buf = buf;
                        self.response_header = Some(response_header);
                        if let Err(e) = self.validate_response() {
                            return self.fail_response_header_read(e);
                        }
                        // convert to upgrade body type
                        // https://datatracker.ietf.org/doc/html/rfc9110#status.101
                        // as an "informational" header, this cannot have a body
                        self.upgraded = self
                            .is_upgrade(self.response_header.as_deref().expect("init above"))
                            .unwrap_or(false);
                        // init body reader if upgrade status has changed body mode
                        // (read_response_task will immediately try to init body afterwards anyways)
                        // informational headers will automatically avoid initializing body reader
                        self.init_body_reader();
                        // note that the (request) body writer is converted to close delimit
                        // when the upgraded body tasks are received
                        return Ok(s);
                    }
                    HeaderParseState::Partial => { /* read more below */ }
                    HeaderParseState::Invalid(e) => {
                        return self.fail_response_header_read(Error::because(
                            InvalidHTTPHeader,
                            format!("buf: {}", self.response_header_read_buf.escape_ascii()),
                            e,
                        ));
                    }
                }
            }

            let already_read = self.response_header_read_buf.len();
            if already_read > MAX_HEADER_SIZE {
                /* NOTE: this check only blocks second read. The first large read is allowed
                since the buf is already allocated. The goal is to avoid slowly bloating
                this buffer */
                return self.fail_response_header_read(Error::explain(
                    InvalidHTTPHeader,
                    format!("Response header larger than {MAX_HEADER_SIZE}"),
                ));
            }

            if self
                .response_header_read_buf
                .capacity()
                .saturating_sub(self.response_header_read_buf.len())
                < INIT_HEADER_BUF_SIZE
            {
                self.response_header_read_buf.reserve(INIT_HEADER_BUF_SIZE);
            }

            let read_fut = self
                .underlying_stream
                .read_buf(&mut self.response_header_read_buf);
            let read_result = match self.read_timeout {
                Some(t) => match timeout(t, read_fut).await {
                    Ok(res) => res,
                    Err(_) => {
                        return self.fail_response_header_read(Error::explain(
                            ReadTimedout,
                            "while reading response headers",
                        ));
                    }
                },
                None => read_fut.await,
            };

            match read_result {
                Ok(0) => {
                    let mut e = Error::explain(
                        ConnectionClosed,
                        format!(
                            "while reading response headers, bytes already read: {already_read}",
                        ),
                    );
                    e.retry = RetryType::ReusedOnly;
                    return self.fail_response_header_read(e);
                }
                Ok(_) => {
                    parse_existing_buffer = true;
                }
                Err(e) => {
                    let true_io_error = e.raw_os_error().is_some();
                    let mut e = Error::because(
                        ReadError,
                        format!(
                            "while reading response headers, bytes already read: {already_read}",
                        ),
                        e,
                    );
                    // Likely OSError, typical if a previously reused connection drops it
                    if true_io_error {
                        e.retry = RetryType::ReusedOnly;
                    } // else: not safe to retry TLS error
                    return self.fail_response_header_read(e);
                }
            }
        }
    }

    /// Similar to [`Self::read_response()`], read the response header and then return a copy of it.
    pub async fn read_resp_header_parts(&mut self) -> Result<Box<ResponseHeader>> {
        self.read_response().await?;
        // safe to unwrap because it is just read
        Ok(Box::new(self.resp_header().unwrap().clone()))
    }

    /// Return a reference of the [`ResponseHeader`] if the response is read
    pub fn resp_header(&self) -> Option<&ResponseHeader> {
        self.response_header.as_deref()
    }

    /// Get the header value for the given header name from the response header
    /// If there are multiple headers under the same name, the first one will be returned
    /// Use `self.resp_header().header.get_all(name)` to get all the headers under the same name
    /// Always return `None` if the response is not read yet.
    pub fn get_header(&self, name: impl AsHeaderName) -> Option<&HeaderValue> {
        self.response_header
            .as_ref()
            .and_then(|h| h.headers.get(name))
    }

    /// Get the request header as raw bytes, `b""` when the header doesn't exist or response not read
    pub fn get_header_bytes(&self, name: impl AsHeaderName) -> &[u8] {
        self.get_header(name).map_or(b"", |v| v.as_bytes())
    }

    /// Return the status code of the response if read
    pub fn get_status(&self) -> Option<StatusCode> {
        self.response_header.as_ref().map(|h| h.status)
    }

    async fn do_read_body(&mut self) -> Result<Option<BufRef>> {
        self.init_body_reader();
        self.body_reader
            .read_body(&mut self.underlying_stream)
            .await
    }

    /// Read the response body into the internal buffer.
    /// Return `Ok(Some(ref)) after a successful read.
    /// Return `Ok(None)` if there is no more body to read.
    pub async fn read_body_ref(&mut self) -> Result<Option<&[u8]>> {
        let result = match self.read_timeout {
            Some(t) => match timeout(t, self.do_read_body()).await {
                Ok(res) => res,
                Err(_) => Error::e_explain(ReadTimedout, format!("reading body, timeout: {t:?}")),
            },
            None => self.do_read_body().await,
        };

        result.map(|maybe_body| {
            maybe_body.map(|body_ref| {
                let slice = self.body_reader.get_body(&body_ref);
                self.body_recv = self.body_recv.saturating_add(slice.len());
                slice
            })
        })
    }

    /// Similar to [`Self::read_body_ref`] but return `Bytes` instead of a slice reference.
    pub async fn read_body_bytes(&mut self) -> Result<Option<Bytes>> {
        let read = self.read_body_ref().await?;
        Ok(read.map(Bytes::copy_from_slice))
    }

    /// Upstream response body bytes received (payload only; excludes headers/framing).
    pub fn body_bytes_received(&self) -> usize {
        self.body_recv
    }

    /// Request body bytes written to the upstream (payload only; excludes headers/framing).
    ///
    /// Counts what the body writer accepted, not what the caller offered, so it can be
    /// compared against the request `Content-Length` to detect a truncated request body.
    pub fn body_bytes_sent(&self) -> usize {
        self.bytes_sent
    }

    /// Whether there is no more body to read.
    pub fn is_body_done(&mut self) -> bool {
        self.init_body_reader();
        self.body_reader.body_done()
    }

    pub fn set_allow_h1_response_invalid_content_length(&mut self, allow: bool) {
        self.allow_h1_response_invalid_content_length = allow;
    }

    pub(super) fn get_headers_raw(&self) -> &[u8] {
        // TODO: these get_*() could panic. handle them better
        self.raw_header.as_ref().unwrap().get(&self.buf[..])
    }

    /// Get the raw response header bytes
    pub fn get_headers_raw_bytes(&self) -> Bytes {
        self.raw_header.as_ref().unwrap().get_bytes(&self.buf)
    }

    fn set_keepalive(&mut self, seconds: Option<u64>) {
        match seconds {
            Some(sec) => {
                if sec > 0 {
                    self.keepalive_timeout = KeepaliveStatus::Timeout(Duration::from_secs(sec));
                } else {
                    self.keepalive_timeout = KeepaliveStatus::Infinite;
                }
            }
            None => {
                self.keepalive_timeout = KeepaliveStatus::Off;
            }
        }
    }

    /// Apply keepalive settings according to the server's response
    /// For HTTP 1.1, assume keepalive as long as there is no `Connection: Close` request header.
    /// For HTTP 1.0, only keepalive if there is an explicit header `Connection: keep-alive`.
    pub fn respect_keepalive(&mut self) {
        if self.upgraded || self.get_status() == Some(StatusCode::SWITCHING_PROTOCOLS) {
            // make sure the connection is closed at the end when 101/upgrade is used
            self.set_keepalive(None);
            return;
        }
        if self.body_reader.need_init() || self.close_delimited_resp {
            // Defense-in-depth: response body close-delimited (or no body interpretation
            // upon reuse check)
            // explicitly disable reuse
            self.set_keepalive(None);
            return;
        }
        if self.body_reader.has_bytes_overread() {
            // if more bytes sent than expected, there are likely more bytes coming
            // so don't reuse this connection
            self.set_keepalive(None);
            return;
        }

        // Per [RFC 9112 Section 6.1-16](https://datatracker.ietf.org/doc/html/rfc9112#section-6.1-16),
        // if Transfer-Encoding is received in HTTP/1.0 response, connection MUST be closed after processing.
        if self.resp_header().map(|h| h.version) == Some(Version::HTTP_10)
            && self
                .resp_header()
                .and_then(|h| h.headers.get(header::TRANSFER_ENCODING))
                .is_some()
        {
            self.set_keepalive(None);
            return;
        }
        if let Some(keepalive) = self.is_connection_keepalive() {
            if keepalive {
                let (timeout, _max_use) = self.get_keepalive_values();
                // TODO: respect max_use
                match timeout {
                    Some(d) => self.set_keepalive(Some(d)),
                    None => self.set_keepalive(Some(0)), // infinite
                }
            } else {
                self.set_keepalive(None);
            }
        } else if self.resp_header().map(|h| h.version) == Some(Version::HTTP_11) {
            self.set_keepalive(Some(0)); // on by default for http 1.1
        } else {
            self.set_keepalive(None); // off by default for http 1.0
        }
    }

    // Whether this session will be kept alive
    pub fn will_keepalive(&self) -> bool {
        !matches!(self.keepalive_timeout, KeepaliveStatus::Off)
    }

    fn is_connection_keepalive(&self) -> Option<bool> {
        let request_keepalive = self
            .request_written
            .as_ref()
            .and_then(|req| is_buf_keepalive(req.headers.get(header::CONNECTION)));

        match request_keepalive {
            // ignore what the server sends if request disables keepalive explicitly
            Some(false) => Some(false),
            _ => is_buf_keepalive(self.get_header(header::CONNECTION)),
        }
    }

    /// `Keep-Alive: timeout=5, max=1000` => 5, 1000
    /// This is defined in the below spec, this not part of any RFC, so
    /// it's behavior is different on different platforms.
    /// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Keep-Alive
    fn get_keepalive_values(&self) -> (Option<u64>, Option<usize>) {
        let Some(keep_alive_header) = self.get_header("Keep-Alive") else {
            return (None, None);
        };

        let Ok(header_value) = str::from_utf8(keep_alive_header.as_bytes()) else {
            return (None, None);
        };

        let mut timeout = None;
        let mut max = None;

        for param in header_value.split(',') {
            let parts = param.split_once('=').map(|(k, v)| (k.trim(), v));
            match parts {
                Some(("timeout", timeout_value)) => timeout = timeout_value.trim().parse().ok(),
                Some(("max", max_value)) => max = max_value.trim().parse().ok(),
                _ => {}
            }
        }

        (timeout, max)
    }

    /// Close the connection abruptly. This allows to signal the server that the connection is closed
    /// before dropping [`HttpSession`]
    pub async fn shutdown(&mut self) {
        let _ = self.underlying_stream.shutdown().await;
    }

    /// Consume `self`, if the connection can be reused, the underlying stream will be returned.
    /// The returned connection can be kept in a connection pool so that next time the same
    /// server is being contacted. A new client session can be created via [`Self::new()`].
    /// If the connection cannot be reused, the underlying stream will be closed and `None` will be
    /// returned.
    pub async fn reuse(mut self) -> Option<Stream> {
        if !self.body_reader.body_complete() || self.body_reader.has_bytes_overread() {
            self.set_keepalive(None);
        }

        // TODO: this function is unnecessarily slow for keepalive case
        // because that case does not need async
        match self.keepalive_timeout {
            KeepaliveStatus::Off => {
                debug!("HTTP shutdown connection");
                self.shutdown().await;
                None
            }
            _ => Some(self.underlying_stream),
        }
    }

    fn init_body_reader(&mut self) {
        if self.body_reader.need_init() {
            // follow https://datatracker.ietf.org/doc/html/rfc9112#section-6.3
            let preread_body = self.preread_body.as_ref().unwrap().get(&self.buf[..]);

            let upgraded = if let Some(code) = self.get_status() {
                match code.as_u16() {
                    101 => self.is_upgrade_req(),
                    100..=199 => {
                        // informational headers, not enough to init body reader
                        return;
                    }
                    204 | 304 => {
                        // no body by definition
                        self.body_reader.init_content_length(0, preread_body);
                        return;
                    }
                    _ => false,
                }
            } else {
                false
            };

            if let Some(req) = self.request_written.as_ref() {
                if req.method == http::method::Method::HEAD {
                    self.body_reader.init_content_length(0, preread_body);
                    return;
                }
            }

            if upgraded {
                self.body_reader.init_close_delimited(preread_body);
                self.close_delimited_resp = true;
            } else if self.is_chunked_encoding() {
                // if chunked encoding, content-length should be ignored
                self.body_reader.init_chunked(preread_body);
            } else if let Some(cl) = self.get_content_length().unwrap_or(None) {
                self.body_reader.init_content_length(cl, preread_body);
            } else {
                self.body_reader.init_close_delimited(preread_body);
                self.close_delimited_resp = true;
            }
        }
    }

    /// Whether this request is for upgrade
    pub fn is_upgrade_req(&self) -> bool {
        match self.request_written.as_deref() {
            Some(req) => is_upgrade_req(req),
            None => false,
        }
    }

    /// `Some(true)` if the this is a successful upgrade
    /// `Some(false)` if the request is an upgrade but the response refuses it
    /// `None` if the request is not an upgrade.
    fn is_upgrade(&self, header: &ResponseHeader) -> Option<bool> {
        if self.is_upgrade_req() {
            Some(is_upgrade_resp(header))
        } else {
            None
        }
    }

    /// Was this request successfully turned into an upgraded connection?
    ///
    /// Both the request had to have been an `Upgrade` request
    /// and the response had to have been a `101 Switching Protocols`.
    pub fn was_upgraded(&self) -> bool {
        self.upgraded
    }

    /// If upgraded but not yet converted, then body writer will be
    /// converted to http1.0 mode (pass through bytes as-is).
    pub fn maybe_upgrade_body_writer(&mut self) {
        if self.was_upgraded() {
            self.received_upgrade_req_body = true;
            self.body_writer.convert_to_close_delimited();
        }
    }

    fn get_content_length(&self) -> Result<Option<usize>> {
        match self.resp_header() {
            Some(h) => content_length_for_framing(&h.headers),
            None => Ok(None),
        }
    }

    fn is_chunked_encoding(&self) -> bool {
        self.resp_header()
            .map(|h| is_chunked_encoding_from_headers(&h.headers))
            .unwrap_or(false)
    }

    fn init_req_body_writer(&mut self, header: &RequestHeader) {
        self.init_body_writer_comm(&header.headers)
    }

    fn init_body_writer_comm(&mut self, headers: &HMap) {
        if is_chunked_encoding_from_headers(headers) {
            // transfer-encoding takes priority over content-length
            self.body_writer.init_chunked();
            return;
        }
        // Resolve Content-Length through the shared, range-checked helper so the
        // value is reconciled (identical duplicates / comma lists) and never
        // truncated. Per RFC 9112, requests are never close-delimited: an absent
        // or unusable Content-Length means a zero-length body. Headers are
        // expected to be validated on read.
        match content_length_for_framing(headers) {
            Ok(Some(length)) => self.body_writer.init_content_length(length),
            Ok(None) => self.body_writer.init_content_length(0),
            Err(e) => {
                // Headers are validated on read, so this is not expected here;
                // log the fallback to a zero-length body rather than failing
                // silently if validation was somehow bypassed.
                debug!(
                    "invalid Content-Length while writing request; framing zero-length body: {e}"
                );
                self.body_writer.init_content_length(0);
            }
        }
    }

    // should (continue to) try to read response header or start reading response body
    fn should_read_resp_header(&self) -> bool {
        match self.get_status().map(|s| s.as_u16()) {
            Some(101) => false,      // switching protocol successful, no more header to read
            Some(100..=199) => true, // only informational header read
            Some(_) => false,
            None => true, // no response code, no header read yet
        }
    }

    pub async fn read_response_task(&mut self) -> Result<HttpTask> {
        if self.should_read_resp_header() {
            let resp_header = self.read_resp_header_parts().await?;
            let end_of_body = self.is_body_done();
            debug!("Response header: {resp_header:?}");
            trace!(
                "Raw Response header: {:?}",
                str::from_utf8(self.get_headers_raw()).unwrap()
            );
            Ok(HttpTask::Header(resp_header, end_of_body))
        } else if self.is_body_done() {
            // no body
            debug!("Response is done");
            Ok(self
                .body_reader
                .take_trailers()
                .map(|t| HttpTask::Trailer(Some(Box::new(t))))
                .unwrap_or(HttpTask::Done))
        } else {
            /* need to read body */
            let body = self.read_body_bytes().await?;
            let end_of_body = self.is_body_done();
            debug!(
                "Response body: {} bytes, end: {end_of_body}",
                body.as_ref().map_or(0, |b| b.len())
            );
            trace!("Response body: {body:?}, upgraded: {}", self.upgraded);
            if end_of_body && body.as_ref().is_none_or(|b| b.is_empty()) {
                if let Some(trailers) = self.body_reader.take_trailers() {
                    return Ok(HttpTask::Trailer(Some(Box::new(trailers))));
                }
            }
            if self.upgraded {
                Ok(HttpTask::UpgradedBody(body, end_of_body))
            } else {
                Ok(HttpTask::Body(
                    body,
                    end_of_body && !self.body_reader.has_trailers(),
                ))
            }
        }
        // TODO: support h1 trailer
    }

    /// Return the [Digest] of the connection
    ///
    /// For reused connection, the timing in the digest will reflect its initial handshakes
    /// The caller should check if the connection is reused to avoid misuse the timing field.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Return a mutable [Digest] reference for the connection.
    pub fn digest_mut(&mut self) -> &mut Digest {
        &mut self.digest
    }

    /// Return the server (peer) address recorded in the connection digest.
    pub fn server_addr(&self) -> Option<&SocketAddr> {
        self.digest()
            .socket_digest
            .as_ref()
            .map(|d| d.peer_addr())?
    }

    /// Return the client (local) address recorded in the connection digest.
    pub fn client_addr(&self) -> Option<&SocketAddr> {
        self.digest()
            .socket_digest
            .as_ref()
            .map(|d| d.local_addr())?
    }

    /// Get the reference of the [Stream] that this HTTP session is operating upon.
    pub fn stream(&self) -> &Stream {
        &self.underlying_stream
    }

    /// Consume `self`, the underlying [Stream] will be returned and can be used
    /// directly, for example, in the case of HTTP upgrade. It is not flushed
    /// prior to being returned.
    /// Consume an accepted Upgrade without discarding bytes read with the header.
    pub fn into_upgraded_parts(self) -> Result<(Stream, Bytes)> {
        if !self.upgraded {
            return Error::e_explain(InvalidHTTPHeader, "upstream did not upgrade");
        }
        let prefix = self
            .preread_body
            .as_ref()
            .map(|b| Bytes::copy_from_slice(b.get(&self.buf)))
            .unwrap_or_default();
        Ok((self.underlying_stream, prefix))
    }
    pub fn into_inner(self) -> Stream {
        self.underlying_stream
    }
}

#[inline]
fn parse_resp_buffer<'buf>(
    resp: &mut httparse::Response<'_, 'buf>,
    buf: &'buf [u8],
) -> HeaderParseState {
    let mut parser = httparse::ParserConfig::default();
    parser.allow_spaces_after_header_name_in_responses(true);
    parser.allow_obsolete_multiline_headers_in_responses(true);
    let res = match parser.parse_response(resp, buf) {
        Ok(s) => s,
        Err(e) => {
            return HeaderParseState::Invalid(e);
        }
    };
    match res {
        httparse::Status::Complete(s) => HeaderParseState::Complete(s),
        _ => HeaderParseState::Partial,
    }
}

/// Returns `true` if `path` contains a byte that must never appear in an HTTP/1.1
/// request target: NUL (`0x00`), LF (`0x0a`), CR (`0x0d`), or SP (`0x20`).
///
/// See RFC 9112 §3.2 (request-target) and RFC 3986 §2.1 (URI characters).
/// These bytes are also forbidden in HTTP/2 `:path` per RFC 7540 §8.1.2.3.
#[inline]
pub(crate) fn request_target_has_forbidden_byte(path: &[u8]) -> bool {
    path.iter().any(|&b| matches!(b, 0x00 | 0x0a | 0x0d | 0x20))
}

// TODO: change it to to_buf
#[inline]
pub fn http_req_header_to_wire(req: &RequestHeader) -> Option<BytesMut> {
    let mut buf = BytesMut::with_capacity(512);

    // Request-Line
    let method = req.method.as_str().as_bytes();
    buf.put_slice(method);
    buf.put_u8(b' ');

    let path = req.raw_path();
    if request_target_has_forbidden_byte(path) {
        return None;
    }
    buf.put_slice(path);
    buf.put_u8(b' ');

    let version = match req.version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        _ => {
            return None; /*TODO: unsupported version */
        }
    };
    buf.put_slice(version.as_bytes());
    buf.put_slice(CRLF);

    // headers
    req.header_to_h1_wire(&mut buf);
    buf.put_slice(CRLF);
    Some(buf)
}

impl UniqueID for HttpSession {
    fn id(&self) -> UniqueIDType {
        self.underlying_stream.id()
    }
}
