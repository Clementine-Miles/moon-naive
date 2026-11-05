//! H3 adapts to Pingora's H2 session over bounded memory, never a public listener.
use super::{Input, Proxy, Result};
use bytes::Bytes;
use pingora_core::{
    apps::HttpServerApp,
    protocols::{
        Digest,
        http::{
            HttpTask, ServerSession,
            v2::server::{self, H2Accept, HttpSession},
        },
        l4::{
            stream::Stream as L4,
            virt::{VirtualSockOpt, VirtualSocket, VirtualSocketStream},
        },
    },
};
use pingora_http::{RequestHeader, ResponseHeader};
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    sync::{Notify, mpsc, watch},
    task::JoinHandle,
};

pub(super) struct Bridge {
    health: watch::Receiver<bool>,
    sender: h2::client::SendRequest<Bytes>,
    client: JoinHandle<()>,
    server: JoinHandle<()>,
}
impl Drop for Bridge {
    fn drop(&mut self) {
        self.client.abort();
        self.server.abort();
    }
}
/// Validate before forwarding DATA to the shared H2 connection. A mismatch
/// resets only this stream and must not reach its connection-level parser.
struct BodyLength(Option<u64>);
impl BodyLength {
    fn new(request: &RequestHeader) -> Result<Self> {
        let value = request
            .headers
            .get("content-length")
            .map(|v| -> Result<u64> { Ok(v.to_str()?.parse()?) })
            .transpose()?;
        Ok(Self(value))
    }
    fn data(&mut self, bytes: usize) -> Result<()> {
        if let Some(remaining) = &mut self.0 {
            *remaining = remaining
                .checked_sub(u64::try_from(bytes)?)
                .ok_or("bridge content length exceeded")?;
        }
        Ok(())
    }
    fn finish(&self) -> Result<()> {
        if self.0.is_some_and(|remaining| remaining != 0) {
            Err("bridge content length incomplete".into())
        } else {
            Ok(())
        }
    }
}

struct DriverHealth(watch::Sender<bool>);
impl Drop for DriverHealth {
    fn drop(&mut self) {
        self.0.send_replace(false);
    }
}
impl Bridge {
    pub fn healthy(&self) -> bool {
        *self.health.borrow() && !self.client.is_finished() && !self.server.is_finished()
    }
    pub async fn new(proxy: Arc<Proxy>, max_streams: u32) -> Result<Self> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server: pingora_core::protocols::Stream = Box::new(L4::from(VirtualSocketStream::new(
            Box::new(MemorySocket(server)),
        )));
        let mut options = server::default_h2_options();
        options
            .max_concurrent_streams(max_streams)
            .max_header_list_size(32768)
            .initial_window_size(64 * 1024)
            .initial_connection_window_size(1024 * 1024)
            .max_send_buffer_size(super::super::CHUNK * 2);
        let mut client_options = h2::client::Builder::new();
        client_options
            .initial_window_size(64 * 1024)
            .initial_connection_window_size(1024 * 1024)
            .max_header_list_size(32768)
            .max_send_buffer_size(super::super::CHUNK * 2);
        let (client, server) = tokio::join!(
            client_options.handshake(client),
            server::handshake(server, Some(options))
        );
        let (sender, connection) = client?;
        let mut connection_server = server?;
        let (health_send, health) = watch::channel(true);
        let client_health = DriverHealth(health_send.clone());
        let server_health = DriverHealth(health_send);
        let client = tokio::spawn(async move {
            let _health = client_health;
            let _ = connection.await;
        });
        let server = tokio::spawn(async move {
            let _health = server_health;
            let mut tasks = tokio::task::JoinSet::new();
            let (_send, stop) = watch::channel(false);
            let digest = Arc::new(Digest::default());
            loop {
                tokio::select! {
                    Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
                    accepted=HttpSession::from_h2_conn(&mut connection_server,digest.clone())=>match accepted {
                        Ok(Some(H2Accept::Session(session)))=>{let proxy=proxy.clone();let stop=stop.clone();tasks.spawn(async move {proxy.process_new_http(ServerSession::new_http2(session),&stop).await;});},
                        Ok(Some(H2Accept::Rejected))=>{},_=>break,
                    }
                }
            }
            // Dropping JoinSet aborts requests when the memory connection ends.
        });
        Ok(Self {
            health,
            sender,
            client,
            server,
        })
    }
    pub async fn exchange(
        &self,
        request: RequestHeader,
        end: bool,
        input: mpsc::Receiver<Input>,
        output: mpsc::Sender<HttpTask>,
        wake: Arc<Notify>,
    ) -> Result<()> {
        let mut health = self.health.clone();
        if !self.healthy() {
            return Err("bridge generation terminated".into());
        }
        tokio::select! {
            biased;
            _ = health.changed() => Err("bridge generation terminated".into()),
            result = self.exchange_inner(request, end, input, output, wake) => result,
        }
    }
    async fn exchange_inner(
        &self,
        request: RequestHeader,
        end: bool,
        mut input: mpsc::Receiver<Input>,
        output: mpsc::Sender<HttpTask>,
        wake: Arc<Notify>,
    ) -> Result<()> {
        let mut length = BodyLength::new(&request)?;
        if end {
            length.finish()?;
        }
        let uri: http::Uri = if request.method == http::Method::CONNECT {
            request
                .headers
                .get("host")
                .ok_or("website Host missing")?
                .to_str()?
                .parse()?
        } else {
            let host = request
                .headers
                .get("host")
                .ok_or("website Host missing")?
                .to_str()?;
            let mut parts = request.uri.clone().into_parts();
            parts.scheme = Some(http::uri::Scheme::HTTPS);
            parts.authority = Some(host.parse()?);
            http::Uri::from_parts(parts)?
        };
        let mut wire = http::Request::builder()
            .method(request.method.clone())
            .uri(uri)
            .version(http::Version::HTTP_2)
            .body(())?;
        *wire.headers_mut() = request.headers.clone();
        let mut sender = self.sender.clone().ready().await?;
        let (mut response, mut body) = sender.send_request(wire, end)?;
        let upload = async {
            if end {
                return Ok::<_, crate::acme::Error>(());
            }
            while let Some(event) = input.recv().await {
                wake.notify_one();
                match event {
                    Input::Data(mut bytes) => {
                        if let Err(error) = length.data(bytes.len()) {
                            body.send_reset(h2::Reason::PROTOCOL_ERROR);
                            return Err(error);
                        }
                        while !bytes.is_empty() {
                            body.reserve_capacity(bytes.len());
                            let capacity = std::future::poll_fn(|cx| body.poll_capacity(cx))
                                .await
                                .ok_or("website upload closed")??;
                            if capacity > 0 {
                                let part = bytes.split_to(bytes.len().min(capacity));
                                body.send_data(part, false)?;
                            }
                        }
                    }
                    Input::Trailers(headers) => {
                        if let Err(error) = length.finish() {
                            body.send_reset(h2::Reason::PROTOCOL_ERROR);
                            return Err(error);
                        }
                        body.send_trailers(headers)?;
                        return Ok::<_, crate::acme::Error>(());
                    }
                }
            }
            if let Err(error) = length.finish() {
                body.send_reset(h2::Reason::PROTOCOL_ERROR);
                return Err(error);
            }
            body.send_data(Bytes::new(), true)?;
            Ok(())
        };
        let response_started = AtomicBool::new(false);
        let download = async {
            while let Some(info) = std::future::poll_fn(|cx| response.poll_informational(cx)).await
            {
                let (parts, _) = info?.into_parts();
                output
                    .send(HttpTask::Header(
                        Box::new(ResponseHeader::from(parts)),
                        false,
                    ))
                    .await?;
                wake.notify_one();
            }
            let (parts, mut body) = response.await?.into_parts();
            response_started.store(true, Ordering::Relaxed);
            let mut header = ResponseHeader::from(parts);
            header.set_version(http::Version::HTTP_2);
            let empty = body.is_end_stream();
            output
                .send(HttpTask::Header(Box::new(header), empty))
                .await?;
            wake.notify_one();
            if !empty {
                while let Some(bytes) = body.data().await {
                    let bytes = bytes?;
                    let len = bytes.len();
                    output.send(HttpTask::Body(Some(bytes), false)).await?;
                    // Capacity follows consumption into a bounded queue.
                    body.flow_control().release_capacity(len)?;
                    wake.notify_one();
                }
                if let Some(trailers) = body.trailers().await? {
                    output
                        .send(HttpTask::Trailer(Some(Box::new(trailers))))
                        .await?;
                } else {
                    output.send(HttpTask::Done).await?;
                }
                wake.notify_one();
            }
            Ok::<_, crate::acme::Error>(())
        };
        complete_exchange(upload, download, &response_started).await
    }
}
// Request EOF is a half-close, while an upload failure must not leave a
// pending response holding this exchange indefinitely. Prefer an already
// completed response: HTTP origins may reply before consuming the request.
async fn complete_exchange(
    upload: impl std::future::Future<Output = Result<()>>,
    download: impl std::future::Future<Output = Result<()>>,
    response_started: &AtomicBool,
) -> Result<()> {
    tokio::pin!(upload, download);
    tokio::select! {
        biased;
        result = &mut download => result,
        result = &mut upload => {
            // A final HTTP response may close the request side while its
            // body is still draining through the bounded output queue.
            if !response_started.load(Ordering::Relaxed) {
                result?;
            }
            download.await
        }
    }
}

#[cfg(test)]
mod completion_tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn terminated_driver_is_replaced_without_replaying_post() {
        use super::super::{Site, generation::Generations};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = moon_naive_core::config::Config::parse(
            &include_str!("../../../config.example.toml")
                .replace("127.0.0.1:8080", &addr.to_string()),
        )
        .unwrap();
        let site = Site::load(&config).unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = requests.clone();
        let origin = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                loop {
                    bytes.push(socket.read_u8().await.unwrap());
                    if bytes.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                assert!(bytes.starts_with(b"POST "));
                seen.fetch_add(1, Ordering::Relaxed);
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            }
        });
        let generations = Generations::new(8);
        let mut previous: Option<std::sync::Weak<Bridge>> = None;
        for _ in 0..3 {
            let bridge = generations
                .get(Bridge::healthy, || Bridge::new(site.proxy.clone(), 8))
                .await
                .unwrap();
            if let Some(old) = previous.take() {
                assert!(old.upgrade().is_none());
            }
            let mut request = RequestHeader::build("POST", b"/", None).unwrap();
            request
                .insert_header("host", config.domain.clone())
                .unwrap();
            let (input, receive) = mpsc::channel(2);
            drop(input);
            let (send, mut output) = mpsc::channel(8);
            let exchange = bridge.exchange(request, true, receive, send, Arc::new(Notify::new()));
            let consume = async {
                let mut status = None;
                while let Some(task) = output.recv().await {
                    if let HttpTask::Header(header, _) = task {
                        status = Some(header.status);
                    }
                }
                assert_eq!(status, Some(http::StatusCode::OK));
            };
            let (result, ()) = tokio::join!(exchange, consume);
            result.unwrap();
            bridge.client.abort();
            while !bridge.client.is_finished() {
                tokio::task::yield_now().await;
            }
            assert!(!bridge.healthy());
            previous = Some(Arc::downgrade(&bridge));
            drop(bridge);
            tokio::time::advance(std::time::Duration::from_secs(1)).await;
        }
        assert_eq!(requests.load(Ordering::Relaxed), 3);
        generations.close();
        origin.abort();
    }
    use std::{future::pending, time::Duration};

    #[test]
    fn content_length_rejects_overflow_underflow_and_invalid_values() {
        let mut request = RequestHeader::build("POST", b"/", None).unwrap();
        request.insert_header("content-length", "3").unwrap();
        let mut length = BodyLength::new(&request).unwrap();
        assert!(length.finish().is_err());
        length.data(2).unwrap();
        assert!(length.data(2).is_err());
        length.data(1).unwrap();
        length.finish().unwrap();
        for invalid in ["-1", "abc", "18446744073709551616"] {
            request.insert_header("content-length", invalid).unwrap();
            assert!(BodyLength::new(&request).is_err());
        }
    }

    #[tokio::test]
    async fn failed_upload_cancels_pending_response_and_releases_its_state() {
        let (held, released) = tokio::sync::oneshot::channel::<()>();
        let download = async move {
            let _held = held;
            pending::<Result<()>>().await
        };
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            complete_exchange(
                async { Err("upload failed".into()) },
                download,
                &AtomicBool::new(false),
            ),
        )
        .await
        .expect("upload failure must not wait for a response timeout");
        assert_eq!(result.unwrap_err().to_string(), "upload failed");
        assert!(released.await.is_err());
    }

    #[tokio::test]
    async fn upload_eof_waits_for_delayed_response() {
        let (send, receive) = tokio::sync::oneshot::channel();
        let started = AtomicBool::new(false);
        let mut exchange = Box::pin(complete_exchange(
            async { Ok(()) },
            async { receive.await.map_err(Into::into) },
            &started,
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut exchange)
                .await
                .is_err()
        );
        send.send(()).unwrap();
        exchange.await.unwrap();
    }

    #[tokio::test]
    async fn early_response_cancels_unfinished_upload() {
        let (held, released) = tokio::sync::oneshot::channel::<()>();
        let upload = async move {
            let _held = held;
            pending::<Result<()>>().await
        };
        complete_exchange(upload, async { Ok(()) }, &AtomicBool::new(false))
            .await
            .unwrap();
        assert!(released.await.is_err());
        complete_exchange(
            async { Err("upload closed".into()) },
            async { Ok(()) },
            &AtomicBool::new(false),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn early_response_body_survives_request_side_close() {
        let started = AtomicBool::new(false);
        let (send, receive) = tokio::sync::oneshot::channel();
        let mut exchange = Box::pin(complete_exchange(
            async { Err("request side closed".into()) },
            async {
                started.store(true, Ordering::Relaxed);
                receive.await.map_err(Into::into)
            },
            &started,
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut exchange)
                .await
                .is_err()
        );
        send.send(()).unwrap();
        exchange.await.unwrap();
    }

    #[tokio::test]
    async fn failed_response_cancels_upload() {
        let (held, released) = tokio::sync::oneshot::channel::<()>();
        let upload = async move {
            let _held = held;
            pending::<Result<()>>().await
        };
        let error = complete_exchange(
            upload,
            async { Err("response failed".into()) },
            &AtomicBool::new(false),
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "response failed");
        assert!(released.await.is_err());
    }
}

#[derive(Debug)]
struct MemorySocket(DuplexStream);
impl VirtualSocket for MemorySocket {
    fn set_socket_option(&self, _opt: VirtualSockOpt) -> std::io::Result<()> {
        Ok(())
    }
}
impl AsyncRead for MemorySocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}
impl AsyncWrite for MemorySocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}
