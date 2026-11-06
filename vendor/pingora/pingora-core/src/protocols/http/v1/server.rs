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

//! HTTP/1.x server session

use bstr::ByteSlice;
use bytes::Bytes;
use bytes::{BufMut, BytesMut};
use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::HeaderValue;
use http::{header, header::AsHeaderName, Method, Version};
use log::{debug, trace, warn};
use once_cell::sync::Lazy;
use percent_encoding::{percent_encode, AsciiSet, CONTROLS};
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use pingora_http::{IntoCaseHeaderName, RequestHeader, ResponseHeader};
use pingora_timeout::timeout;
use regex::bytes::Regex;
use std::any::Any;
use std::collections::VecDeque;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::body::{BodyReader, BodyWriter};
use super::common::*;
use super::header::HeaderWriter;
use crate::protocols::http::{
    authority::validate_request_authority, body_buffer::FixedBuffer, date, HttpTask,
    ReusableHttpStream,
};
use crate::protocols::{Digest, SocketAddr, Stream};
use crate::utils::{BufRef, KVRef};

/// Tracks which writer is currently processing a task.
///
/// This enables resuming writes after cancellation. Each variant stores the
/// minimal data needed for cleanup after write completes.
#[derive(Debug)]
enum ProxyTaskWriter {
    /// Currently writing a header task.
    /// Stores: (header for `response_written`, end_stream flag)
    WritingHeader(Box<ResponseHeader>, bool),
    /// Currently writing a body task (`Body` or `UpgradedBody`).
    /// Stores: (end_stream flag)
    WritingBody(bool),
    /// Currently finishing the body (writing last chunk + flush).
    FinishingBody,
}

/// State for the cancel-safe proxy task write API.
#[derive(Default)]
struct ProxyTaskState {
    /// Lazily initialized — `HeaderWriter::new()` heap-allocates.
    header_writer: Option<HeaderWriter>,
    tasks: VecDeque<HttpTask>,
    current_writer: Option<ProxyTaskWriter>,
}

impl ProxyTaskState {
    fn header_writer(&mut self) -> &mut HeaderWriter {
        self.header_writer.get_or_insert_with(HeaderWriter::new)
    }
}

/// The HTTP 1.x server session
pub struct HttpSession {
    underlying_stream: Stream,
    /// The buf that holds the raw request header + possibly a portion of request body
    /// Request body can appear here because they could arrive with the same read() that
    /// sends the request header.
    buf: Bytes,
    /// A slice reference to `buf` which points to the exact range of request header
    raw_header: Option<BufRef>,
    /// Request bytes read beyond the header, owned separately so they can move through the body
    /// reader and into the next pipelined session without copying.
    preread_body: Option<BytesMut>,
    /// A state machine to track how to read the request body
    body_reader: BodyReader,
    /// A state machine to track how to write the response body
    body_writer: BodyWriter,
    /// Cancel-safe proxy task state.
    proxy_task_state: ProxyTaskState,
    /// An internal buffer to buf multiple body writes to reduce the underlying syscalls
    body_write_buf: BytesMut,
    /// Track how many application (not on the wire) body bytes already sent
    body_bytes_sent: usize,
    /// Track how many application (not on the wire) body bytes already read
    body_bytes_read: usize,
    /// Whether to update headers like connection, Date
    update_resp_headers: bool,
    /// timeouts:
    keepalive_timeout: KeepaliveStatus,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    /// How long to wait to make downstream session reusable, if body needs to be drained.
    total_drain_timeout: Option<Duration>,
    /// A copy of the response that is already written to the client
    response_written: Option<Box<ResponseHeader>>,
    /// The parsed request header
    request_header: Option<Box<RequestHeader>>,
    /// An internal buffer that holds a copy of the request body up to a certain size
    retry_buffer: Option<FixedBuffer>,
    /// Whether this session is an upgraded session. This flag is calculated when sending the
    /// response header to the client.
    upgraded: bool,
    /// Digest to track underlying connection metrics
    digest: Box<Digest>,
    /// Minimum send rate to the client
    min_send_rate: Option<usize>,
    /// When this is enabled informational response headers will not be proxied downstream
    ignore_info_resp: bool,
    /// Disable keepalive if response is sent before downstream body is finished
    close_on_response_before_downstream_finish: bool,

    /// Number of times the upstream connection associated with this session can be reused
    /// after this session ends
    keepalive_reuses_remaining: Option<u32>,
    /// User-defined context carried across requests on the same keepalive connection.
    /// Set by [`HttpPersistentSettings::apply_to_session`](crate::apps::HttpPersistentSettings::apply_to_session),
    /// consumed by the proxy layer via [`take_connection_user_context`](Self::take_connection_user_context).
    connection_user_context: Option<Box<dyn Any + Send + Sync>>,
    /// Whether the client has closed the TCP connection (sent FIN / read returned 0).
    half_closed: bool,
    /// When true (default), a client close after the request body is surfaced as a
    /// `ConnectionClosed` error so the proxy aborts immediately. When false, the
    /// close is tolerated and `read_body_or_idle` stays pending so the proxy can
    /// finish delivering the upstream response (RFC 9112 Section 9.6).
    abort_on_close: bool,
    /// Whether the cancel-safe proxy task API is enabled for this session.
    /// Defaults to false. Can be enabled via [`set_proxy_tasks_enabled`](Self::set_proxy_tasks_enabled).
    proxy_tasks_enabled: bool,
    /// Whether HTTP/1.1 request pipelining is enabled for this session.
    /// Defaults to false. Can be enabled via [`set_pipelining_enabled`](Self::set_pipelining_enabled).
    /// See [`Self::set_pipelining_enabled`] for RFC 9112 §9.3.2 semantics.
    pipelining_enabled: bool,
    /// Pipelined bytes from the previous request on the same keep-alive connection,
    /// to be parsed as the start of this session's request. Consumed on the first
    /// call to [`Self::read_request`]. Set via [`Self::set_pipelined_prefix`] after
    /// the previous session's [`BodyReader::take_body_overread`] yielded bytes.
    pipelined_prefix: Option<BytesMut>,
    /// Set once the idle-branch of [`Self::read_body_or_idle`] has read the
    /// first bytes of a pipelined next request and pushed them onto the body
    /// reader's overread surface. Further idle polls on the same request
    /// return pending instead of re-reading the stream, so the body-pump
    /// `tokio::select!` loop can exit via its other branches while the
    /// stashed bytes travel through `reuse()` +
    /// [`super::super::HttpPersistentSettings`] into the next session.
    /// Scoped narrowly so it cannot affect FIN / `abort_on_close` semantics.
    pipelined_idle_bytes_stashed: bool,
}

impl HttpSession {
    /// Create a new http server session from an established (TCP or TLS) [`Stream`].
    /// The created session needs to call [`Self::read_request()`] first before performing
    /// any other operations.
    pub fn new(underlying_stream: Stream) -> Self {
        // TODO: maybe we should put digest in the connection itself
        let digest = Box::new(Digest {
            ssl_digest: underlying_stream.get_ssl_digest(),
            timing_digest: underlying_stream.get_timing_digest(),
            proxy_digest: underlying_stream.get_proxy_digest(),
            socket_digest: underlying_stream.get_socket_digest(),
        });

        HttpSession {
            underlying_stream,
            buf: Bytes::new(), // zero size, with be replaced by parsed header later
            raw_header: None,
            preread_body: None,
            body_reader: BodyReader::new(false),
            body_writer: BodyWriter::new(),
            proxy_task_state: ProxyTaskState::default(),
            body_write_buf: BytesMut::new(),
            keepalive_timeout: KeepaliveStatus::Off,
            update_resp_headers: true,
            response_written: None,
            request_header: None,
            read_timeout: Some(Duration::from_secs(60)),
            write_timeout: None,
            total_drain_timeout: None,
            body_bytes_sent: 0,
            body_bytes_read: 0,
            retry_buffer: None,
            upgraded: false,
            digest,
            min_send_rate: None,
            ignore_info_resp: false,
            // default on to avoid rejecting requests after body as pipelined
            close_on_response_before_downstream_finish: true,
            keepalive_reuses_remaining: None,
            connection_user_context: None,
            half_closed: false,
            abort_on_close: true,
            proxy_tasks_enabled: false,
            pipelining_enabled: false,
            pipelined_prefix: None,
            pipelined_idle_bytes_stashed: false,
        }
    }

    async fn read_request_buf(
        &mut self,
        buf: &mut BytesMut,
        already_read: usize,
    ) -> Result<Option<usize>> {
        let read_result = {
            let read_event = self.underlying_stream.read_buf(buf);
            match self.keepalive_timeout {
                KeepaliveStatus::Timeout(d) => match timeout(d, read_event).await {
                    Ok(res) => res,
                    Err(e) => {
                        debug!("keepalive timeout {d:?} reached, {e}");
                        return Ok(None);
                    }
                },
                KeepaliveStatus::Infinite => {
                    // FIXME: this should only apply to reads between requests
                    read_event.await
                }
                KeepaliveStatus::Off => match self.read_timeout {
                    Some(t) => match timeout(t, read_event).await {
                        Ok(res) => res,
                        Err(e) => {
                            debug!("read timeout {t:?} reached, {e}");
                            return Error::e_explain(ReadTimedout, format!("timeout: {t:?}"));
                        }
                    },
                    None => read_event.await,
                },
            }
        };

        match read_result {
            Ok(n_read) => {
                if n_read == 0 {
                    if already_read > 0 {
                        Error::e_explain(
                            ConnectionClosed,
                            format!(
                                "while reading request headers, bytes already read: {}",
                                already_read
                            ),
                        )
                    } else {
                        /* common when client decides to close a keepalived session */
                        debug!("Client prematurely closed connection with 0 byte sent");
                        Ok(None)
                    }
                } else {
                    Ok(Some(n_read))
                }
            }
            Err(e) => {
                if already_read > 0 {
                    Error::e_because(ReadError, "while reading request headers", e)
                } else {
                    /* nothing harmful since we have not ready any thing yet */
                    Ok(None)
                }
            }
        }
    }

    /// Read the request header. Return `Ok(Some(n))` where the read and parsing are successful.
    /// Return `Ok(None)` when the client closed the connection without sending any data, which
    /// is common on a reused connection.
    pub async fn read_request(&mut self) -> Result<Option<usize>> {
        const MAX_ERR_BUF_LEN: usize = 2048;

        self.buf.clear();
        // Account parsing a fully buffered request against Tokio's cooperative task budget. Do
        // this before taking the prefix so cancellation cannot discard bytes between sessions.
        if self
            .pipelined_prefix
            .as_ref()
            .is_some_and(|prefix| !prefix.is_empty())
        {
            tokio::task::consume_budget().await;
        }

        // If the caller (e.g. the proxy layer completing a pipelined request on
        // a reused keep-alive connection) handed us bytes that were read past
        // the end of the previous request's body, pre-fill our parse buffer so
        // the header parser sees them as the start of this request. The loop
        // below tries to parse first when we already have pipelined bytes —
        // a pipelined prefix can contain a complete request header, in which
        // case we must NOT issue another stream read (which would block).
        let mut buf = self
            .pipelined_prefix
            .take()
            .filter(|prefix| !prefix.is_empty())
            .unwrap_or_else(|| BytesMut::with_capacity(INIT_HEADER_BUF_SIZE));
        let mut already_read = buf.len();
        let mut skip_next_read = already_read != 0;
        let mut detached_suffix = None;
        loop {
            if already_read > MAX_HEADER_SIZE {
                /* NOTE: this check only blocks second read. The first large read is allowed
                since the buf is already allocated. The goal is to avoid slowly bloating
                this buffer */
                return Error::e_explain(
                    InvalidHTTPHeader,
                    format!("Request header larger than {MAX_HEADER_SIZE}"),
                );
            }

            // On the first iteration after a pipelined prefix was injected,
            // attempt to parse what we already have before issuing a stream
            // read. If the prefix contains a complete request header, a
            // subsequent read_buf() would block for data that may never come
            // (the client already pipelined everything it had to send for
            // this request and is waiting for our response).
            if skip_next_read {
                skip_next_read = false;
            } else if let Some(n) = self.read_request_buf(&mut buf, already_read).await? {
                already_read += n;
            } else {
                return Ok(None);
            }

            // Use loop as GOTO to retry escaped request buffer, not a real loop
            loop {
                let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
                let mut req = httparse::Request::new(&mut headers);
                let parsed = parse_req_buffer(&mut req, &buf);
                match parsed {
                    HeaderParseState::Complete(s) => {
                        self.raw_header = Some(BufRef(0, s));

                        // We have the header name and values we parsed to be just 0 copy Bytes
                        // referencing the original buf. That requires we convert the buf from
                        // BytesMut to Bytes. But `req` holds a reference to `buf`. So we use the
                        // `KVRef`s to record the offset of each piece of data, drop `req`, convert
                        // buf, the do the 0 copy update
                        let base = buf.as_ptr() as usize;
                        let mut header_refs = Vec::<KVRef>::with_capacity(req.headers.len());
                        // Note: req.headers has the correct number of headers
                        // while header_refs doesn't as it is still empty
                        let _num_headers = populate_headers(base, &mut header_refs, req.headers);

                        let mut request_header = Box::new(RequestHeader::build(
                            req.method.unwrap_or(""),
                            // we path httparse to allow unsafe bytes in the str
                            req.path.unwrap_or("").as_bytes(),
                            Some(req.headers.len()),
                        )?);

                        request_header.set_version(match req.version {
                            Some(1) => Version::HTTP_11,
                            Some(0) => Version::HTTP_10,
                            _ => Version::HTTP_09,
                        });

                        // Detach bytes beyond the header in O(1). Keeping them as owned BytesMut
                        // allows body parsing and subsequent pipelined sessions to continue
                        // splitting the same allocation instead of copying the shrinking suffix.
                        let preread_body = if s == buf.len() {
                            // Keep the common no-body/no-overread path on BytesMut's Vec-backed
                            // representation. split_off() would promote it to shared storage.
                            detached_suffix.take().unwrap_or_default()
                        } else {
                            let mut rest = buf.split_off(s);
                            if let Some(suffix) = detached_suffix.take() {
                                // The URI-escape path below detaches everything past the first
                                // CRLFCRLF, but httparse also accepts bare LF line endings, so the
                                // header can end before that. Stitch the leftover bytes back in
                                // front of the suffix instead of dropping them.
                                rest.unsplit(suffix);
                            }
                            rest
                        };
                        let buf = buf.freeze();

                        for header in header_refs {
                            let header_name = header.get_name_bytes(&buf);
                            let header_name = header_name.into_case_header_name();
                            let value_bytes = header.get_value_bytes(&buf);
                            // safe because this is from what we parsed
                            let header_value = unsafe {
                                http::HeaderValue::from_maybe_shared_unchecked(value_bytes)
                            };

                            request_header
                                .append_header(header_name, header_value)
                                .or_err(InvalidHTTPHeader, "while parsing request header")?;
                        }

                        let contains_transfer_encoding =
                            request_header.headers.contains_key(TRANSFER_ENCODING);
                        let contains_content_length =
                            request_header.headers.contains_key(CONTENT_LENGTH);

                        // Transfer encoding overrides content length, so when
                        // both are present, we can remove content length. This
                        // is per https://datatracker.ietf.org/doc/html/rfc9112#section-6.3
                        //
                        // RFC 9112 Section 6.1 (https://datatracker.ietf.org/doc/html/rfc9112#section-6.1-15)
                        // also requires us to disable keepalive when both headers are present.
                        let has_both_te_and_cl =
                            contains_content_length && contains_transfer_encoding;
                        if has_both_te_and_cl {
                            request_header.remove_header(&CONTENT_LENGTH);
                        }

                        self.buf = buf;
                        self.preread_body = Some(preread_body);
                        self.request_header = Some(request_header);

                        self.body_reader.reinit();
                        self.pipelined_idle_bytes_stashed = false;
                        self.response_written = None;
                        self.respect_keepalive();

                        // Disable keepalive if both Transfer-Encoding and Content-Length were present
                        if has_both_te_and_cl {
                            self.set_keepalive(None);
                        }
                        self.validate_request()?;

                        return Ok(Some(s));
                    }
                    HeaderParseState::Partial => {
                        break; /* continue the read loop */
                    }
                    HeaderParseState::Invalid(e) => match e {
                        httparse::Error::Token | httparse::Error::Version => {
                            // URI escaping rebuilds the current header. Detach any request body or
                            // pipelined suffix first so normalization never copies queued requests.
                            // `separator_start` is the index of the blank line itself, so the
                            // header ends just past it.
                            if detached_suffix.is_none() {
                                if let Some(header_end) =
                                    buf.find(HEADER_SECTION_END).map(|separator_start| {
                                        separator_start + HEADER_SECTION_END.len()
                                    })
                                {
                                    detached_suffix = Some(buf.split_off(header_end));
                                }
                            }
                            // try to escape URI
                            if let Some(new_buf) = escape_illegal_request_line(&buf) {
                                buf = new_buf;
                                already_read = buf.len();
                            } else {
                                debug!("Invalid request header from {:?}", self.underlying_stream);
                                buf.truncate(MAX_ERR_BUF_LEN);
                                return Error::e_because(
                                    InvalidHTTPHeader,
                                    format!("buf: {}", buf.escape_ascii()),
                                    e,
                                );
                            }
                        }
                        _ => {
                            debug!("Invalid request header from {:?}", self.underlying_stream);
                            buf.truncate(MAX_ERR_BUF_LEN);
                            return Error::e_because(
                                InvalidHTTPHeader,
                                format!("buf: {:?}", buf.as_bstr()),
                                e,
                            );
                        }
                    },
                }
            }
        }
    }

    /// Validate the request header read. This function must be called after the request header
    /// read.
    /// # Panics
    /// this function and most other functions will panic if called before [`Self::read_request()`]
    pub fn validate_request(&self) -> Result<()> {
        let req_header = self.req_header();

        // Reject an ambiguous authority before anything routes on it.
        validate_request_authority(req_header)?;

        // Validate/reconcile Content-Length per RFC 9110 section 8.6 (hyper
        // parity): identical duplicates and comma-combined identical values are
        // accepted and collapsed; differing or unparseable values are rejected.
        // This is a no-op when Transfer-Encoding is present (TE overrides CL).
        super::common::validate_content_length(&req_header.headers)?;

        if req_header.headers.contains_key(TRANSFER_ENCODING) {
            // Per [RFC 9112 Section 6.1-16](https://datatracker.ietf.org/doc/html/rfc9112#section-6.1-16),
            // HTTP/1.0 requests with Transfer-Encoding MUST be treated as having faulty framing.
            // We reject with 400 Bad Request and close the connection.
            if req_header.version == http::Version::HTTP_10 {
                return Error::e_explain(
                    InvalidHTTPHeader,
                    "HTTP/1.0 requests cannot include Transfer-Encoding header",
                );
            }
            // If chunked is not the final Transfer-Encoding, reject request
            // See https://datatracker.ietf.org/doc/html/rfc9112#section-6.3-2.4.3
            if !self.is_chunked_encoding() {
                return Error::e_explain(InvalidHTTPHeader, "non-chunked final Transfer-Encoding");
            }
        }

        Ok(())
    }

    /// Return a reference of the `RequestHeader` this session read
    /// # Panics
    /// this function and most other functions will panic if called before [`Self::read_request()`]
    pub fn req_header(&self) -> &RequestHeader {
        self.request_header
            .as_ref()
            .expect("Request header is not read yet")
    }

    /// Return a mutable reference of the `RequestHeader` this session read
    /// # Panics
    /// this function and most other functions will panic if called before [`Self::read_request()`]
    pub fn req_header_mut(&mut self) -> &mut RequestHeader {
        self.request_header
            .as_mut()
            .expect("Request header is not read yet")
    }

    /// Get the header value for the given header name
    /// If there are multiple headers under the same name, the first one will be returned
    /// Use `self.req_header().header.get_all(name)` to get all the headers under the same name
    pub fn get_header(&self, name: impl AsHeaderName) -> Option<&HeaderValue> {
        self.request_header
            .as_ref()
            .and_then(|h| h.headers.get(name))
    }

    /// Return the method of this request. None if the request is not read yet.
    pub(crate) fn get_method(&self) -> Option<&http::Method> {
        self.request_header.as_ref().map(|r| &r.method)
    }

    /// Return the path of the request (i.e., the `/hello?1` of `GET /hello?1 HTTP1.1`)
    /// An empty slice will be used if there is no path or the request is not read yet
    pub(crate) fn get_path(&self) -> &[u8] {
        self.request_header.as_ref().map_or(b"", |r| r.raw_path())
    }

    /// Return the host header of the request. An empty slice will be used if there is no host header
    pub(crate) fn get_host(&self) -> &[u8] {
        self.request_header
            .as_ref()
            .and_then(|h| h.headers.get(header::HOST))
            .map_or(b"", |h| h.as_bytes())
    }

    /// Return a string `$METHOD $PATH, Host: $HOST`. Mostly for logging and debug purpose
    pub fn request_summary(&self) -> String {
        format!(
            "{} {}, Host: {}",
            self.get_method().map_or("-", |r| r.as_str()),
            String::from_utf8_lossy(self.get_path()),
            String::from_utf8_lossy(self.get_host())
        )
    }

    /// Is the request a upgrade request
    pub fn is_upgrade_req(&self) -> bool {
        match self.request_header.as_deref() {
            Some(req) => is_upgrade_req(req),
            None => false,
        }
    }

    /// Get the request header as raw bytes, `b""` when the header doesn't exist
    pub fn get_header_bytes(&self, name: impl AsHeaderName) -> &[u8] {
        self.get_header(name).map_or(b"", |v| v.as_bytes())
    }

    /// Read the request body. `Ok(None)` when there is no (more) body to read.
    pub async fn read_body_bytes(&mut self) -> Result<Option<Bytes>> {
        let read = self.read_body().await?;
        Ok(read.map(|b| {
            let bytes = Bytes::copy_from_slice(self.get_body(&b));
            self.body_bytes_read += bytes.len();
            if let Some(buffer) = self.retry_buffer.as_mut() {
                buffer.write_to_buffer(&bytes);
            }
            bytes
        }))
    }

    async fn do_read_body(&mut self) -> Result<Option<BufRef>> {
        self.init_body_reader();
        self.body_reader
            .read_body(&mut self.underlying_stream)
            .await
    }

    /// Read the body into the internal buffer
    async fn read_body(&mut self) -> Result<Option<BufRef>> {
        match self.read_timeout {
            Some(t) => match timeout(t, self.do_read_body()).await {
                Ok(res) => res,
                Err(_) => Error::e_explain(ReadTimedout, format!("reading body, timeout: {t:?}")),
            },
            None => self.do_read_body().await,
        }
    }

    async fn do_drain_request_body(&mut self) -> Result<()> {
        loop {
            match self.read_body_bytes().await {
                Ok(Some(_)) => { /* continue to drain */ }
                Ok(None) => return Ok(()), // done
                Err(e) => return Err(e),
            }
        }
    }

    /// Drain the request body. `Ok(())` when there is no (more) body to read.
    pub async fn drain_request_body(&mut self) -> Result<()> {
        if self.is_body_done() {
            return Ok(());
        }
        match self.total_drain_timeout {
            Some(t) => match timeout(t, self.do_drain_request_body()).await {
                Ok(res) => res,
                Err(_) => Error::e_explain(ReadTimedout, format!("draining body, timeout: {t:?}")),
            },
            None => self.do_drain_request_body().await,
        }
    }

    /// Whether there is no (more) body to be read.
    pub fn is_body_done(&mut self) -> bool {
        self.init_body_reader();
        self.body_reader.body_done()
    }

    /// Whether the request has an empty body
    /// Because HTTP 1.1 clients have to send either `Content-Length` or `Transfer-Encoding` in order
    /// to signal the server that it will send the body, this function returns accurate results even
    /// only when the request header is just read.
    pub fn is_body_empty(&mut self) -> bool {
        self.init_body_reader();
        self.body_reader.body_empty()
    }

    /// Write the response header to the client.
    /// This function can be called more than once to send 1xx informational headers excluding 101.
    pub async fn write_response_header(&mut self, mut header: Box<ResponseHeader>) -> Result<()> {
        // Prepare header (handle upgrades, set headers, initialize body writer, serialize to bytes)
        let Some((write_buf, flush)) = self.prepare_response_header(&mut header)? else {
            // Header already sent or should be ignored
            return Ok(());
        };

        match self.underlying_stream.write_all(&write_buf).await {
            Ok(()) => {
                // flush the stream if 1xx header or there is no response body
                if flush || self.body_writer.finished() {
                    self.underlying_stream
                        .flush()
                        .await
                        .or_err(WriteError, "flushing response header")?;
                }
                self.response_written = Some(header);
                Ok(())
            }
            Err(e) => Error::e_because(WriteError, "writing response header", e),
        }
    }

    /// Return the response header if it is already sent.
    pub fn response_written(&self) -> Option<&ResponseHeader> {
        self.response_written.as_deref()
    }

    /// `Some(true)` if the this is a successful upgrade
    /// `Some(false)` if the request is an upgrade but the response refuses it
    /// `None` if the request is not an upgrade.
    pub fn is_upgrade(&self, header: &ResponseHeader) -> Option<bool> {
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

    pub fn get_keepalive_timeout(&self) -> Option<u64> {
        match self.keepalive_timeout {
            KeepaliveStatus::Timeout(d) => Some(d.as_secs()),
            KeepaliveStatus::Infinite => Some(0),
            KeepaliveStatus::Off => None,
        }
    }

    pub fn set_keepalive_reuses_remaining(&mut self, remaining: Option<u32>) {
        self.keepalive_reuses_remaining = remaining;
    }

    pub fn get_keepalive_reuses_remaining(&self) -> Option<u32> {
        self.keepalive_reuses_remaining
    }

    /// Set user-defined context to carry across requests on the same keepalive connection.
    ///
    /// This is typically called by
    /// [`HttpPersistentSettings::apply_to_session`](crate::apps::HttpPersistentSettings::apply_to_session)
    /// during the keepalive reuse loop. The proxy layer consumes it via
    /// [`take_connection_user_context`](Self::take_connection_user_context).
    pub fn set_connection_user_context(&mut self, ctx: Option<Box<dyn Any + Send + Sync>>) {
        self.connection_user_context = ctx;
    }

    /// Take the user-defined context from the previous request on this keepalive connection.
    ///
    /// Returns `None` if this is the first request on the connection or if no context was
    /// persisted by the previous request.
    pub fn take_connection_user_context(&mut self) -> Option<Box<dyn Any + Send + Sync>> {
        self.connection_user_context.take()
    }

    /// Return whether the session will be keepalived for connection reuse.
    pub fn will_keepalive(&self) -> bool {
        !matches!(
            (&self.keepalive_timeout, self.keepalive_reuses_remaining),
            (KeepaliveStatus::Off, _) | (_, Some(0))
        )
    }

    // `Keep-Alive: timeout=5, max=1000` => 5, 1000
    fn get_keepalive_values(&self) -> (Option<u64>, Option<usize>) {
        // TODO: implement this parsing
        (None, None)
    }

    fn ignore_info_resp(&self, status: u16) -> bool {
        // ignore informational response if ignore flag is set and it's not an Upgrade and Expect: 100-continue isn't set
        self.ignore_info_resp && status != 101 && !(status == 100 && self.is_expect_continue_req())
    }

    fn is_expect_continue_req(&self) -> bool {
        match self.request_header.as_deref() {
            Some(req) => is_expect_continue_req(req),
            None => false,
        }
    }

    fn is_connection_keepalive(&self) -> Option<bool> {
        is_buf_keepalive(self.get_header(header::CONNECTION))
    }

    // calculate write timeout from min_send_rate if set, otherwise return write_timeout
    fn write_timeout(&self, buf_len: usize) -> Option<Duration> {
        let Some(min_send_rate) = self.min_send_rate.filter(|r| *r > 0) else {
            return self.write_timeout;
        };

        // min timeout is 1s
        let ms = (buf_len.max(min_send_rate) as f64 / min_send_rate as f64) * 1000.0;
        // truncates unrealistically large values (we'll be out of memory before this happens)
        Some(Duration::from_millis(ms as u64))
    }

    /// Apply keepalive settings according to the client
    /// For HTTP 1.1, assume keepalive as long as there is no `Connection: Close` request header.
    /// For HTTP 1.0, only keepalive if there is an explicit header `Connection: keep-alive`.
    pub fn respect_keepalive(&mut self) {
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
        } else if self.req_header().version == Version::HTTP_11 {
            self.set_keepalive(Some(0)); // on by default for http 1.1
        } else {
            self.set_keepalive(None); // off by default for http 1.0
        }
    }

    /// Prepare response header for writing: handle upgrades, set headers, initialize body writer.
    /// This contains all the synchronous logic that should happen before writing the header.
    /// Returns Ok(Some((bytes, should_flush))) if the header should be written, Ok(None) if should skip.
    fn prepare_response_header(
        &mut self,
        header: &mut ResponseHeader,
    ) -> Result<Option<(Bytes, bool)>> {
        // Check if we should ignore informational responses
        if header.status.is_informational() && self.ignore_info_resp(header.status.into()) {
            debug!("ignoring informational headers");
            return Ok(None);
        }

        // Check if we already sent a response header
        if let Some(ref resp) = self.response_written {
            if !resp.status.is_informational() || self.upgraded {
                warn!("Respond header is already sent, cannot send again");
                return Ok(None);
            }
        }

        // if body unfinished, or request header was not finished reading
        if self.close_on_response_before_downstream_finish
            && (self.request_header.is_none() || !self.is_body_done())
        {
            debug!("set connection close before downstream finish");
            self.set_keepalive(None);
        }

        // no need to add these headers to 1xx responses
        if !header.status.is_informational() && self.update_resp_headers {
            /* update headers */
            header.insert_header(header::DATE, date::get_cached_date())?;

            // TODO: make these lazy static
            let connection_value = if self.will_keepalive() {
                "keep-alive"
            } else {
                "close"
            };
            header.insert_header(header::CONNECTION, connection_value)?;
        }

        if header.status == 101 {
            // make sure the connection is closed at the end when 101/upgrade is used
            self.set_keepalive(None);
        }

        // Allow informational header (excluding 101) to pass through without affecting the state
        // of the request
        if header.status == 101 || !header.status.is_informational() {
            // reset request body to done for incomplete upgrade handshakes
            if let Some(upgrade_ok) = self.is_upgrade(header) {
                if upgrade_ok {
                    debug!("ok upgrade handshake");
                    // For ws we use HTTP1_0 do_read_body_until_closed
                    //
                    // On ws close the initiator sends a close frame and
                    // then waits for a response from the peer, once it receives
                    // a response it closes the conn. After receiving a
                    // control frame indicating the connection should be closed,
                    // a peer discards any further data received.
                    // https://www.rfc-editor.org/rfc/rfc6455#section-1.4
                    self.upgraded = true;
                    // Now that the upgrade was successful, we need to change
                    // how we interpret the rest of the body as pass-through.
                    if self.body_reader.need_init() {
                        self.init_body_reader();
                    } else {
                        // already initialized
                        // immediately start reading the rest of the body as upgraded
                        // (in practice most upgraded requests shouldn't have any body)
                        //
                        // TODO: https://datatracker.ietf.org/doc/html/rfc9110#name-upgrade
                        // the most spec-compliant behavior is to switch interpretation
                        // after sending the former body,
                        // we immediately switch interpretation to match nginx
                        self.body_reader.convert_to_close_delimited();
                    }
                } else {
                    // this was a request that requested Upgrade,
                    // but upstream did not comply
                    debug!("bad upgrade handshake!");
                    // continue to read body as-is, this is now just a regular request
                }
            }
            self.init_body_writer(header);
        }

        // Defense-in-depth: if response body is close-delimited, mark session
        // as un-reusable
        if self.body_writer.is_close_delimited() {
            self.set_keepalive(None);
        }

        // Serialize header to bytes
        let mut write_buf = BytesMut::with_capacity(INIT_HEADER_BUF_SIZE);
        http_resp_header_to_buf(header, &mut write_buf)
            .map_err(|_| Error::explain(WriteError, "serializing response header"))?;

        // Determine if we should flush
        // Don't have to flush response with content length because it is less
        // likely to be real time communication. So do flush when
        // 1. 1xx response: client needs to see it before the rest of response
        // 2. No content length: the response could be generated in real time
        let should_flush = header.status.is_informational()
            || header.headers.get(header::CONTENT_LENGTH).is_none();

        Ok(Some((write_buf.freeze(), should_flush)))
    }

    fn init_body_writer(&mut self, header: &ResponseHeader) {
        use http::StatusCode;
        /* the following responses don't have body 204, 304, and HEAD */
        if matches!(
            header.status,
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
        ) || self.get_method() == Some(&Method::HEAD)
        {
            self.body_writer.init_content_length(0);
            return;
        }

        if header.status.is_informational() && header.status != StatusCode::SWITCHING_PROTOCOLS {
            // 1xx response, not enough to init body
            return;
        }

        if self.is_upgrade(header) == Some(true) {
            self.body_writer.init_close_delimited();
        } else {
            init_body_writer_comm(&mut self.body_writer, &header.headers);
        }
    }

    /// Same as [`Self::write_response_header()`] but takes a reference.
    pub async fn write_response_header_ref(&mut self, resp: &ResponseHeader) -> Result<()> {
        self.write_response_header(Box::new(resp.clone())).await
    }

    async fn do_write_body(&mut self, buf: &[u8]) -> Result<Option<usize>> {
        let written = self
            .body_writer
            .write_body(&mut self.underlying_stream, buf)
            .await;

        if let Ok(Some(num_bytes)) = written {
            self.body_bytes_sent += num_bytes;
        }

        written
    }

    /// Write response body to the client. Return `Ok(None)` when there shouldn't be more body
    /// to be written, e.g., writing more bytes than what the `Content-Length` header suggests
    pub async fn write_body(&mut self, buf: &[u8]) -> Result<Option<usize>> {
        // TODO: check if the response header is written
        match self.write_timeout(buf.len()) {
            Some(t) => match timeout(t, self.do_write_body(buf)).await {
                Ok(res) => res,
                Err(_) => Error::e_explain(WriteTimedout, format!("writing body, timeout: {t:?}")),
            },
            None => self.do_write_body(buf).await,
        }
    }

    /// Whether the cancel-safe proxy task API is enabled for this session.
    pub fn proxy_tasks_enabled(&self) -> bool {
        self.proxy_tasks_enabled
    }

    /// Enable or disable the cancel-safe proxy task API for this session.
    pub fn set_proxy_tasks_enabled(&mut self, enabled: bool) {
        self.proxy_tasks_enabled = enabled;
    }

    /// Whether HTTP/1.1 request pipelining is enabled for this session.
    pub fn pipelining_enabled(&self) -> bool {
        self.pipelining_enabled
    }

    /// Enable or disable HTTP/1.1 request pipelining on this session.
    ///
    /// When enabled, if the client pipelines requests on a single keep-alive
    /// connection (sends request N+1 before reading response N), the proxy will
    /// serve each request sequentially with responses in request order as
    /// required by RFC 9112 §9.3.2. Each pipelined request still goes through
    /// independent upstream selection; only the downstream connection is reused.
    ///
    /// When disabled (default), pipelined bytes received alongside request N
    /// cause the session to be marked un-reusable: response N is still
    /// delivered, the connection closes, and request N+1 is dropped. Clients
    /// are expected to detect the close and retry on a fresh connection per
    /// RFC 9112 §9.3.2.
    ///
    /// Sequential dispatch only: response N must be fully written before
    /// request N+1 begins processing. No parallel pipelining.
    pub fn set_pipelining_enabled(&mut self, enabled: bool) {
        self.pipelining_enabled = enabled;
    }

    /// Set pipelined bytes to be parsed as the start of this session's request.
    ///
    /// Called by the proxy layer when continuing a keep-alive connection whose
    /// previous session yielded overread bytes. The prefix is consumed on the
    /// first [`Self::read_request`] call; the parser treats the prefix + any
    /// further stream reads as the next request's header + body bytes.
    pub fn set_pipelined_prefix(&mut self, prefix: BytesMut) {
        debug_assert!(
            self.pipelined_prefix.is_none(),
            "pipelined prefix already set"
        );
        self.pipelined_prefix = Some(prefix);
    }

    /// Take ownership of bytes read past the end of this session's request
    /// body. When non-empty, those bytes are the start of a pipelined
    /// follow-up request on the same keep-alive connection and should be
    /// fed to the next session via [`Self::set_pipelined_prefix`].
    ///
    /// Returns `None` when no overread is present. After this call, the
    /// session's body-reader no longer holds the bytes.
    pub(crate) fn take_body_overread(&mut self) -> Option<BytesMut> {
        self.body_reader.take_body_overread()
    }

    async fn do_write_body_buf(&mut self) -> Result<Option<usize>> {
        // Don't flush empty chunks, they are considered end of body for chunks
        if self.body_write_buf.is_empty() {
            return Ok(None);
        }

        let written = self
            .body_writer
            .write_body(&mut self.underlying_stream, &self.body_write_buf)
            .await;

        if let Ok(Some(num_bytes)) = written {
            self.body_bytes_sent += num_bytes;
        }

        // make sure this buf is safe to reuse
        self.body_write_buf.clear();

        written
    }

    async fn write_body_buf(&mut self) -> Result<Option<usize>> {
        match self.write_timeout(self.body_write_buf.len()) {
            Some(t) => match timeout(t, self.do_write_body_buf()).await {
                Ok(res) => res,
                Err(_) => Error::e_explain(WriteTimedout, format!("writing body, timeout: {t:?}")),
            },
            None => self.do_write_body_buf().await,
        }
    }

    /// Signal that there is no more body to write.
    /// This call will try to flush the buffer if there is any un-flushed data.
    /// For chunked encoding response, this call will also send the last chunk.
    /// For upgraded sessions, this half-closes the response, retaining the request reader.
    pub async fn finish_body(&mut self) -> Result<Option<usize>> {
        let res = self.body_writer.finish(&mut self.underlying_stream).await?;
        self.underlying_stream
            .flush()
            .await
            .or_err(WriteError, "flushing body")?;

        trace!(
            "finish body (response body writer), upgraded: {}",
            self.upgraded
        );
        if self.upgraded {self.underlying_stream.shutdown().await.or_err(WriteError,"half-closing upgraded response")?;}
        Ok(res)
    }

    /// Return how many response body bytes (application, not wire) already sent downstream
    pub fn body_bytes_sent(&self) -> usize {
        self.body_bytes_sent
    }

    /// Return how many request body bytes (application, not wire) already read from downstream
    pub fn body_bytes_read(&self) -> usize {
        self.body_bytes_read
    }

    fn is_chunked_encoding(&self) -> bool {
        is_chunked_encoding_from_headers(&self.req_header().headers)
    }

    fn get_content_length(&self) -> Result<Option<usize>> {
        content_length_for_framing(&self.req_header().headers)
    }

    fn init_body_reader(&mut self) {
        if self.body_reader.need_init() {
            // reset retry buffer
            if let Some(buffer) = self.retry_buffer.as_mut() {
                buffer.clear();
            }

            // follow https://datatracker.ietf.org/doc/html/rfc9112#section-6.3
            let preread_body = self.preread_body.take().unwrap_or_default();

            if self.was_upgraded() {
                // if upgraded _post_ 101 (and body was not init yet)
                // treat as upgraded body (pass through until closed)
                self.body_reader.init_close_delimited_owned(preread_body);
            } else if self.is_chunked_encoding() {
                // if chunked encoding, content-length should be ignored
                self.body_reader.init_chunked_owned(preread_body);
            } else {
                // At this point, validate_request() should have already been called,
                // so get_content_length() should not return an error for invalid values
                let cl = self.get_content_length().unwrap_or(None);
                match cl {
                    Some(i) => {
                        self.body_reader.init_content_length_owned(i, preread_body);
                    }
                    None => {
                        // https://datatracker.ietf.org/doc/html/rfc9112#section-6.3
                        // "Request messages are never close-delimited because they are
                        // always explicitly framed by length or transfer coding, with the absence of
                        // both implying the request ends immediately after the header section."
                        self.body_reader.init_content_length_owned(0, preread_body);
                    }
                }
            }
        }
    }

    pub fn retry_buffer_truncated(&self) -> bool {
        self.retry_buffer
            .as_ref()
            .map_or_else(|| false, |r| r.is_truncated())
    }

    pub fn enable_retry_buffering(&mut self) {
        if self.retry_buffer.is_none() {
            self.retry_buffer = Some(FixedBuffer::new(BODY_BUF_LIMIT))
        }
    }

    pub fn get_retry_buffer(&self) -> Option<Bytes> {
        self.retry_buffer.as_ref().and_then(|b| {
            if b.is_truncated() {
                None
            } else {
                b.get_buffer()
            }
        })
    }

    fn get_body(&self, buf_ref: &BufRef) -> &[u8] {
        // TODO: these get_*() could panic. handle them better
        self.body_reader.get_body(buf_ref)
    }

    /// This function will (async) block forever until the client closes the connection.
    pub async fn idle(&mut self) -> Result<usize> {
        // OpenSSL read requires a non-empty buffer. Keep this probe at one byte
        // so idle-style reads consume at most one byte before returning control.
        self.read_idle_probe("during HTTP idle state")
            .await
            .map(|(_, read)| read)
    }

    async fn read_idle_probe(&mut self, context: &'static str) -> Result<([u8; 1], usize)> {
        let mut probe = [0; 1];
        let read = self
            .underlying_stream
            .read(&mut probe)
            .await
            .or_err(ReadError, context)?;
        Ok((probe, read))
    }

    /// This function will return body bytes (same as [`Self::read_body_bytes()`]), but after
    /// the client body finishes (`Ok(None)` is returned), calling this function again will block
    /// forever, same as [`Self::idle()`].
    ///
    /// By default (`abort_on_close = true`), if the client closes the connection
    /// (sends TCP FIN, i.e. `read == 0`) after the request body is complete, a
    /// `ConnectionClosed` error is returned.
    ///
    /// When `abort_on_close` is **disabled**, the close is tolerated: the future stays
    /// pending so the proxy can finish delivering the upstream response via the write
    /// path (per RFC 9112 Section 9.6). A true disconnect (RST) will be caught later
    /// when the response write fails.
    ///
    /// Note that this marks the connection as half-closed if FIN is detected. If this function
    /// is called after the connection is already marked half-closed and `abort_on_close` is
    /// **disabled**, then it will pend forever.
    pub async fn read_body_or_idle(&mut self, no_body_expected: bool) -> Result<Option<Bytes>> {
        if no_body_expected || self.is_body_done() {
            if self.half_closed {
                if self.abort_on_close {
                    return Error::e_explain(
                        ConnectionClosed,
                        if self.response_written.is_none() {
                            "Prematurely before response header is sent"
                        } else {
                            "Prematurely before response body is complete"
                        },
                    );
                }
                return std::future::pending().await;
            }
            // When pipelining is enabled and an earlier idle read already
            // stashed the next request's bytes as overread, any further
            // poll of this function on the same request must not read
            // the stream again (the proxy's body-pump `select!` loop
            // will call back into here repeatedly until its other
            // branches resolve the request). Go straight to pending.
            // `abort_on_close` and the FIN handling above stay untouched
            // — this branch is exclusive to the pipelining case where
            // bytes (not FIN) arrived on the idle poll.
            if self.pipelining_enabled && self.pipelined_idle_bytes_stashed {
                return std::future::pending().await;
            }
            // XXX: account for upgraded body reader change, if the read half split from the write half
            let (probe, read) = self
                .read_idle_probe("during HTTP body-or-idle state")
                .await?;
            if read == 0 {
                self.half_closed = true;
                self.set_keepalive(None);
                if self.abort_on_close {
                    Error::e_explain(
                        ConnectionClosed,
                        if self.response_written.is_none() {
                            "Prematurely before response header is sent"
                        } else {
                            "Prematurely before response body is complete"
                        },
                    )
                } else {
                    debug!("downstream closed (FIN), keeping write side open");
                    // If the connection is fully closed, writing the response side
                    // will fail.
                    std::future::pending().await
                }
            } else if self.pipelining_enabled {
                // The read bytes are the start of a pipelined next
                // request on this keep-alive connection (RFC 9112
                // §9.3.2). Stash them on the body reader's overread
                // surface so the existing `take_body_overread` +
                // `HttpPersistentSettings` extraction path picks them
                // up at `reuse()` time and feeds them to the next
                // session via `set_pipelined_prefix`.
                //
                // Returning pending (rather than `Ok(None)` or an
                // error) signals the body-pump `tokio::select!` loop
                // that the downstream has no more body work to do on
                // this request — the loop exits naturally via the
                // upstream-response-done / response-write-done
                // branches, and `finish()` runs its standard pipelining
                // extraction. The read == 0 FIN path above is unchanged; this
                // branch only handles a non-zero idle read that belongs to the
                // next pipelined request, so it leaves `half_closed` and
                // `abort_on_close` untouched.
                // Keep the stash and flag update adjacent and synchronous.
                // Once the prefix byte is handed to the overread path, the
                // flag prevents later idle polls for this request from
                // reading the stream again.
                self.body_reader.push_body_overread(&probe[..read]);
                self.pipelined_idle_bytes_stashed = true;
                debug!("pipelined request bytes stashed as overread ({read} bytes)");
                std::future::pending().await
            } else {
                Error::e_explain(ConnectError, "Sent data after end of body")
            }
        } else {
            self.read_body_bytes().await
        }
    }

    /// Whether the client has half-closed the TCP connection.
    pub fn is_half_closed(&self) -> bool {
        self.half_closed
    }

    /// Return the raw bytes of the request header.
    pub fn get_headers_raw_bytes(&self) -> Bytes {
        self.raw_header.as_ref().unwrap().get_bytes(&self.buf)
    }

    /// Close the connection abruptly. This allows to signal the client that the connection is closed
    /// before dropping [`HttpSession`]
    pub async fn shutdown(&mut self) {
        let _ = self.underlying_stream.shutdown().await;
    }

    /// Set the server keepalive timeout.
    /// `None`: disable keepalive, this session cannot be reused.
    /// `Some(0)`: reusing this session is allowed and there is no timeout.
    /// `Some(>0)`: reusing this session is allowed within the given timeout in seconds.
    /// If the client disallows connection reuse, then `keepalive` will be ignored.
    pub fn set_server_keepalive(&mut self, keepalive: Option<u64>) {
        if let Some(false) = self.is_connection_keepalive() {
            // connection: close is set
            self.set_keepalive(None);
        } else {
            self.set_keepalive(keepalive);
        }
    }

    /// Sets the downstream read timeout. This will trigger if we're unable
    /// to read from the stream after `timeout`.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    /// Gets the downstream read timeout.
    pub fn get_read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    /// Sets the downstream write timeout. This will trigger if we're unable
    /// to write to the stream after `timeout`. If a `min_send_rate` is
    /// configured then the `min_send_rate` calculated timeout has higher priority.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.write_timeout = timeout;
    }

    /// Gets the downstream write timeout.
    pub fn get_write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }

    /// Sets the total drain timeout. For HTTP/1.1, reusing a session requires
    /// ensuring that the request body is consumed. This `timeout` will be used
    /// to determine how long to wait for the entirety of the downstream request
    /// body to finish after the upstream response is completed to return the
    /// session to the reuse pool. If the timeout is exceeded, we will give up
    /// on trying to reuse the session.
    ///
    /// Note that the downstream read timeout still applies between body byte reads.
    pub fn set_total_drain_timeout(&mut self, timeout: Option<Duration>) {
        self.total_drain_timeout = timeout;
    }

    /// Get the total drain timeout.
    pub fn get_total_drain_timeout(&self) -> Option<Duration> {
        self.total_drain_timeout
    }

    /// Sets the minimum downstream send rate in bytes per second. This
    /// is used to calculate a write timeout in seconds based on the size
    /// of the buffer being written. If a `min_send_rate` is configured it
    /// has higher priority over a set `write_timeout`. The minimum send
    /// rate must be greater than zero.
    ///
    /// Calculated write timeout is guaranteed to be at least 1s if `min_send_rate`
    /// is greater than zero, a send rate of zero is equivalent to disabling.
    pub fn set_min_send_rate(&mut self, min_send_rate: Option<usize>) {
        if let Some(rate) = min_send_rate.filter(|r| *r > 0) {
            self.min_send_rate = Some(rate);
        } else {
            self.min_send_rate = None;
        }
    }

    /// Sets whether we ignore writing informational responses downstream.
    ///
    /// This is a noop if the response is Upgrade or Continue and
    /// Expect: 100-continue was set on the request.
    pub fn set_ignore_info_resp(&mut self, ignore: bool) {
        self.ignore_info_resp = ignore;
    }

    /// Sets whether keepalive should be disabled if response is written prior to
    /// downstream body finishing.
    ///
    /// This may be set to avoid draining downstream if the body is no longer necessary.
    pub fn set_close_on_response_before_downstream_finish(&mut self, close: bool) {
        self.close_on_response_before_downstream_finish = close;
    }

    /// Controls behaviour when the client closes the connection after the request body.
    ///
    /// When **enabled** (default), a client close is returned as a `ConnectionClosed`
    /// error so the proxy aborts immediately.
    ///
    /// When **disabled**, `read_body_or_idle` stays pending on a client close so the
    /// proxy can finish delivering the upstream response (RFC 9112 Section 9.6). A true
    /// disconnect (RST) will surface later when the response write fails.
    pub fn set_abort_on_close(&mut self, abort: bool) {
        self.abort_on_close = abort;
    }

    /// Return the [Digest] of the connection.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Return a mutable [Digest] reference for the connection.
    pub fn digest_mut(&mut self) -> &mut Digest {
        &mut self.digest
    }

    /// Return the client (peer) address of the underlying connection.
    pub fn client_addr(&self) -> Option<&SocketAddr> {
        self.digest()
            .socket_digest
            .as_ref()
            .map(|d| d.peer_addr())?
    }

    /// Return the server (local) address of the underlying connection.
    pub fn server_addr(&self) -> Option<&SocketAddr> {
        self.digest()
            .socket_digest
            .as_ref()
            .map(|d| d.local_addr())?
    }

    /// Consume `self`, if the connection can be reused, the underlying stream and any pipelined
    /// prefix bytes will be returned to be fed to the next [`Self::new()`]. This drains any
    /// remaining request body if it hasn't yet been read and the stream is reusable.
    ///
    /// The next session can just call [`Self::read_request()`].
    ///
    /// If the connection cannot be reused, the underlying stream will be closed and `None` will be
    /// returned. If there was an error while draining any remaining request body that error will
    /// be returned.
    pub async fn reuse(mut self) -> Result<Option<ReusableHttpStream>> {
        if !self.will_keepalive() {
            debug!("HTTP shutdown connection");
            self.shutdown().await;
            Ok(None)
        } else {
            self.drain_request_body().await?;
            if self.body_reader.has_bytes_overread() && !self.pipelining_enabled {
                debug!("bytes overread on request, disallowing reuse");
                Ok(None)
            } else {
                let pipelined_prefix = self
                    .pipelining_enabled
                    .then(|| self.take_body_overread())
                    .flatten()
                    .filter(|prefix| !prefix.is_empty());
                Ok(Some(ReusableHttpStream::new(
                    self.underlying_stream,
                    pipelined_prefix,
                )))
            }
        }
    }

    /// Write a `100 Continue` response to the client.
    pub async fn write_continue_response(&mut self) -> Result<()> {
        // only send if we haven't already
        if self.response_written.is_none() {
            // size hint Some(0) because default is 8
            return self
                .write_response_header(Box::new(ResponseHeader::build(100, Some(0)).unwrap()))
                .await;
        }
        Ok(())
    }

    async fn write_non_empty_body(&mut self, data: Option<Bytes>, upgraded: bool) -> Result<()> {
        // Both upstream and downstream should agree on upgrade status.
        // Upgrade can only occur if both downstream and upstream sessions are H1.1
        // and see a 101 response, which logically MUST have been received
        // prior to this task.
        if upgraded != self.upgraded {
            if upgraded {
                panic!("Unexpected UpgradedBody task received on un-upgraded downstream session");
            } else {
                panic!("Unexpected Body task received on upgraded downstream session");
            }
        }
        let Some(d) = data else {
            return Ok(());
        };
        if d.is_empty() {
            return Ok(());
        }
        self.write_body(&d).await.map_err(|e| e.into_down())?;
        Ok(())
    }

    async fn response_duplex(&mut self, task: HttpTask) -> Result<bool> {
        let end_stream = match task {
            HttpTask::Header(header, end_stream) => {
                self.write_response_header(header)
                    .await
                    .map_err(|e| e.into_down())?;
                end_stream
            }
            HttpTask::Body(data, end_stream) => {
                self.write_non_empty_body(data, false).await?;
                end_stream
            }
            HttpTask::UpgradedBody(data, end_stream) => {
                self.write_non_empty_body(data, true).await?;
                end_stream
            }
            HttpTask::Trailer(trailers) => {
                if let Some(trailers) = trailers {
                    self.body_writer.set_trailers(*trailers)?;
                }
                true
            }
            HttpTask::Done => true,
            HttpTask::Failed(e) => return Err(e),
        };
        if end_stream {
            // no-op if body wasn't initialized or is finished already
            self.finish_body().await.map_err(|e| e.into_down())?;
        }
        Ok(end_stream || self.body_writer.finished())
    }

    fn buffer_body_data(&mut self, data: Option<Bytes>, upgraded: bool) {
        if upgraded != self.upgraded {
            if upgraded {
                panic!("Unexpected Body task received on upgraded downstream session");
            } else {
                panic!("Unexpected UpgradedBody task received on un-upgraded downstream session");
            }
        }

        let Some(d) = data else {
            return;
        };
        if !d.is_empty() && !self.body_writer.finished() {
            self.body_write_buf.put_slice(&d);
        }
    }

    // TODO: use vectored write to avoid copying
    pub async fn response_duplex_vec(&mut self, mut tasks: Vec<HttpTask>) -> Result<bool> {
        let n_tasks = tasks.len();
        if n_tasks == 1 {
            // fallback to single operation to avoid copy
            return self.response_duplex(tasks.pop().unwrap()).await;
        }

        let mut end_stream = false;
        for task in tasks.into_iter() {
            end_stream = match task {
                HttpTask::Header(header, end_stream) => {
                    self.write_response_header(header)
                        .await
                        .map_err(|e| e.into_down())?;
                    end_stream
                }
                HttpTask::Body(data, end_stream) => {
                    self.buffer_body_data(data, false);
                    end_stream
                }
                HttpTask::UpgradedBody(data, end_stream) => {
                    self.buffer_body_data(data, true);
                    end_stream
                }
                HttpTask::Trailer(trailers) => {
                    if let Some(trailers) = trailers {
                        self.body_writer.set_trailers(*trailers)?;
                    }
                    true
                }
                HttpTask::Done => true,
                HttpTask::Failed(e) => {
                    // flush the data we have and quit
                    self.write_body_buf().await.map_err(|e| e.into_down())?;
                    self.underlying_stream
                        .flush()
                        .await
                        .or_err(WriteError, "flushing response")?;
                    return Err(e);
                }
            }
        }
        self.write_body_buf().await.map_err(|e| e.into_down())?;
        if end_stream {
            // no-op if body wasn't initialized or is finished already
            self.finish_body().await.map_err(|e| e.into_down())?;
        }
        Ok(end_stream || self.body_writer.finished())
    }

    /// Queue a proxy task for cancel-safe writing with the current write_timeout.
    /// The task will be written when `write_proxy_tasks()` is called.
    ///
    /// A write canceled mid-operation can be resumed via `write_proxy_tasks()`.
    pub fn send_proxy_task(&mut self, task: HttpTask) {
        self.proxy_task_state.tasks.push_back(task);
    }

    /// Check if there are pending proxy tasks queued for writing.
    pub fn has_pending_proxy_tasks(&self) -> bool {
        self.proxy_task_state.current_writer.is_some() || !self.proxy_task_state.tasks.is_empty()
    }

    /// Write all queued proxy tasks (response `HttpTask`s from `send_proxy_task`)
    /// in a cancel-safe manner.
    ///
    /// If cancelled mid-write, the next call will resume the in-progress write.
    ///
    /// Returns `Ok(true)` if this was the end of the response stream.
    // Leverages the cancel-safe `HeaderWriter` and `BodyWriter` primitives.
    // TODO: we can do the same for the non-cancel-safe APIs.
    pub async fn write_proxy_tasks(&mut self) -> Result<bool> {
        let mut end_stream = false;

        // TODO: buffer body data like response_duplex_vec
        loop {
            // - Resume any in-progress write
            if let Some(ref writer_state) = self.proxy_task_state.current_writer {
                match writer_state {
                    ProxyTaskWriter::WritingHeader(_, _) => {
                        let _bytes_written = self
                            .proxy_task_state
                            .header_writer()
                            .write_current_header_task(&mut self.underlying_stream)
                            .await
                            .map_err(|e| e.into_down())?;
                    }
                    ProxyTaskWriter::WritingBody(_) => {
                        let written = self
                            .body_writer
                            .write_current_body_task(&mut self.underlying_stream)
                            .await
                            .map_err(|e| e.into_down())?;
                        if let Some(n) = written {
                            self.body_bytes_sent += n;
                        }
                    }
                    ProxyTaskWriter::FinishingBody => {
                        self.body_writer
                            .write_current_finish_task(&mut self.underlying_stream)
                            .await
                            .map_err(|e| e.into_down())?;
                    }
                }

                match self
                    .proxy_task_state
                    .current_writer
                    .take()
                    .expect("writer state present")
                {
                    ProxyTaskWriter::WritingHeader(header, end) => {
                        self.response_written = Some(header);
                        end_stream = end;
                    }
                    ProxyTaskWriter::WritingBody(end) => {
                        end_stream = end;
                    }
                    ProxyTaskWriter::FinishingBody => {
                        end_stream = true;
                        if self.upgraded {self.underlying_stream.shutdown().await.or_err(WriteError,"half-closing upgraded response")?;}
                        break; // fine to break after finish, no tasks should be queued after
                    }
                }
                continue;
            }

            // - Send tasks, set state.
            // Pop next task
            let Some(task) = self.proxy_task_state.tasks.pop_front() else {
                if end_stream {
                    self.body_writer.send_finish_task();
                    self.proxy_task_state.current_writer = Some(ProxyTaskWriter::FinishingBody);
                    continue;
                }
                break;
            };

            match task {
                HttpTask::Header(mut header, end) => {
                    let Some((write_buf, should_flush)) =
                        self.prepare_response_header(&mut header)?
                    else {
                        end_stream = end;
                        continue;
                    };
                    // header only responses will want to flush
                    let flush = should_flush || self.body_writer.finished();
                    self.proxy_task_state
                        .header_writer()
                        .send_header_task(write_buf, flush, None);
                    self.proxy_task_state.current_writer =
                        Some(ProxyTaskWriter::WritingHeader(header, end));
                }
                HttpTask::Body(ref data, end) => {
                    if self.upgraded {
                        panic!("Unexpected Body task received on upgraded downstream session");
                    }
                    if let Some(d) = data.as_ref() {
                        if !d.is_empty() {
                            let body_timeout = self.write_timeout(d.len());
                            self.body_writer.send_body_task(d.clone(), body_timeout);
                            self.proxy_task_state.current_writer =
                                Some(ProxyTaskWriter::WritingBody(end));
                            continue;
                        }
                    }
                    end_stream = end;
                }
                HttpTask::UpgradedBody(ref data, end) => {
                    if !self.upgraded {
                        panic!("Unexpected UpgradedBody task received on un-upgraded downstream session");
                    }
                    if let Some(d) = data.as_ref() {
                        if !d.is_empty() {
                            let body_timeout = self.write_timeout(d.len());
                            self.body_writer.send_body_task(d.clone(), body_timeout);
                            self.proxy_task_state.current_writer =
                                Some(ProxyTaskWriter::WritingBody(end));
                            continue;
                        }
                    }
                    end_stream = end;
                }
                HttpTask::Trailer(trailers) => {
                    if let Some(trailers) = trailers {
                        self.body_writer.set_trailers(*trailers)?;
                    }
                    end_stream = true;
                }
                HttpTask::Done => {
                    end_stream = true;
                }
                HttpTask::Failed(e) => {
                    return Err(e);
                }
            }
        }

        Ok(end_stream || self.body_writer.finished())
    }

    /// Get the reference of the [Stream] that this HTTP session is operating upon.
    pub fn take_request_trailers(&mut self) -> Option<http::HeaderMap> {
        self.body_reader.take_trailers()
    }
    pub async fn write_trailers(&mut self, trailers: http::HeaderMap) -> Result<()> {
        self.body_writer.set_trailers(trailers)?;
        self.finish_body().await?;
        Ok(())
    }
    pub fn stream(&self) -> &Stream {
        &self.underlying_stream
    }

    /// Consume `self`, the underlying stream will be returned and can be used
    /// directly, for example, in the case of HTTP upgrade. The stream is not
    /// flushed prior to being returned.
    pub fn into_inner(self) -> Stream {
        self.underlying_stream
    }
}

// Regex to parse request line that has illegal chars in it
static REQUEST_LINE_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\w+ (?P<uri>.+) HTTP/\d(?:\.\d)?").unwrap());

// the chars httparse considers illegal in URL
// Almost https://url.spec.whatwg.org/#query-percent-encode-set + {}
const URI_ESC_CHARSET: &AsciiSet = &CONTROLS.add(b' ').add(b'<').add(b'>').add(b'"');

fn escape_illegal_request_line(buf: &BytesMut) -> Option<BytesMut> {
    if let Some(captures) = REQUEST_LINE_REGEX.captures(buf) {
        // return if nothing matches: not a request line at all
        let uri = captures.name("uri")?;

        let escaped_uri = percent_encode(uri.as_bytes(), URI_ESC_CHARSET);

        // rebuild the entire request buf in a new buffer
        // TODO: this might be able to be done in place

        // need to be slightly bigger than the current buf;
        let mut new_buf = BytesMut::with_capacity(buf.len() + 32);
        new_buf.extend_from_slice(&buf[..uri.start()]);

        for s in escaped_uri {
            new_buf.extend_from_slice(s.as_bytes());
        }

        if new_buf.len() == uri.end() {
            // buf unchanged, nothing is escaped, return None to avoid loop
            return None;
        }

        new_buf.extend_from_slice(&buf[uri.end()..]);

        Some(new_buf)
    } else {
        None
    }
}

#[inline]
fn parse_req_buffer<'buf>(
    req: &mut httparse::Request<'_, 'buf>,
    buf: &'buf [u8],
) -> HeaderParseState {
    use httparse::Result;

    #[cfg(feature = "patched_http1")]
    fn parse<'buf>(req: &mut httparse::Request<'_, 'buf>, buf: &'buf [u8]) -> Result<usize> {
        req.parse_unchecked(buf)
    }

    #[cfg(not(feature = "patched_http1"))]
    fn parse<'buf>(req: &mut httparse::Request<'_, 'buf>, buf: &'buf [u8]) -> Result<usize> {
        req.parse(buf)
    }

    let res = match parse(req, buf) {
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

#[inline]
fn http_resp_header_to_buf(
    resp: &ResponseHeader,
    buf: &mut BytesMut,
) -> std::result::Result<(), ()> {
    // Status-Line
    let version = match resp.version {
        Version::HTTP_09 => "HTTP/0.9 ",
        Version::HTTP_10 => "HTTP/1.0 ",
        Version::HTTP_11 => "HTTP/1.1 ",
        _ => {
            return Err(()); /*TODO: unsupported version */
        }
    };
    buf.put_slice(version.as_bytes());
    let status = resp.status;
    buf.put_slice(status.as_str().as_bytes());
    buf.put_u8(b' ');
    let reason = resp.get_reason_phrase();
    if let Some(reason_buf) = reason {
        buf.put_slice(reason_buf.as_bytes());
    }
    buf.put_slice(CRLF);

    // headers
    // TODO: style: make sure Server and Date headers are the first two
    resp.header_to_h1_wire(buf);

    buf.put_slice(CRLF);
    Ok(())
}
