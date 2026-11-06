use super::{
    App, Bytes, CHUNK, Head, Plan, Reply, Result,
    tls::Slot,
    tunnel::{Activity, TunnelDecoder, TunnelDownload},
};
use h2::Reason;
use pingora_core::protocols::{
    Digest, GetSocketDigest, SocketDigest, Ssl,
    http::v2::server::{self, H2Accept, HttpSession},
    l4::stream::Stream as L4,
};
use std::{sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::watch};

pub(super) async fn serve(
    socket: TcpStream,
    app: Arc<App>,
    tls: Slot,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    if *stop.borrow() {
        return Ok(());
    }
    let peer_ip = socket.peer_addr()?.ip();
    let generation = tls.current()?;
    super::congestion::apply(&socket, app.tcp_congestion)?;
    socket.set_nodelay(true)?;
    // We bypass Pingora's listener, so initialize the trusted socket metadata
    // before TLS. H1 website forwarding reads this digest on every keepalive use.
    let mut socket = L4::from(socket);
    use std::os::fd::AsRawFd;
    let digest = SocketDigest::from_raw_fd(socket.as_raw_fd());
    socket.set_socket_digest(digest);
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        pingora_core::protocols::tls::server::handshake(&generation.h2, socket),
    )
    .await??;
    // ALPN callback is not invoked if absent; only the configured website may fall back to H1.
    if !matches!(
        stream.selected_alpn_proto(),
        Some(pingora_core::protocols::ALPN::H2)
    ) {
        if app.h1 {
            return app.site.h1(Box::new(stream), stop).await;
        }
        return Err("strict H2 ALPN required".into());
    }
    let ssl = stream.get_ssl().ok_or("missing TLS state")?;
    let exporter = if ssl.version2() == Some(boring::ssl::SslVersion::TLS1_3) {
        Some(super::exporter(ssl)?)
    } else {
        None
    };
    // H1 and incomplete TLS handshakes do not use H2 receive credit. The
    // listener's connection permit and TLS deadline still bound their lifetime.
    let _window = app
        .resources
        .receive
        .clone()
        .try_acquire_many_owned(app.profile.connection_window())
        .map_err(|_| "H2 receive window budget exhausted")?;
    let digest = Arc::new(Digest {
        ssl_digest: stream.get_ssl_digest(),
        ..Digest::default()
    });
    let mut options = server::default_h2_options();
    options.enable_connect_protocol();
    options
        .max_header_list_size(32768)
        .max_concurrent_reset_streams(50)
        .max_pending_accept_reset_streams(20)
        .max_local_error_reset_streams(Some(128))
        .max_concurrent_streams(app.profile.max_streams())
        .initial_window_size(app.profile.stream_window().min(app.early))
        .initial_connection_window_size(app.profile.connection_window())
        .max_send_buffer_size(CHUNK * 2);
    let stream: pingora_core::protocols::Stream = Box::new(write_buffer::WriteBuffer::new(stream));
    let mut conn = tokio::time::timeout(
        Duration::from_secs(10),
        server::handshake(stream, Some(options)),
    )
    .await??;
    let mut tasks = tokio::task::JoinSet::new();
    app.stats
        .h2_connections
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut rejected = 0;
    let local = moon_naive_core::policy::Budget::new(app.profile.max_streams() as usize)?;
    let mut draining = false;
    loop {
        tokio::select! {
            _=stop.changed(),if !draining=>{conn.graceful_shutdown();draining=true;},
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            accepted=server::HttpSession::from_h2_conn(&mut conn,digest.clone())=>{
                match accepted? {
                    Some(H2Accept::Session(mut session))=>{
                        let Some(permit)=local.acquire() else {session.shutdown_with_reason(Reason::REFUSED_STREAM);continue;};
                        let Some(global)=app.resources.requests.acquire() else {session.shutdown_with_reason(Reason::REFUSED_STREAM);continue;};
                        let app=app.clone();
                        tasks.spawn(async move {let _permit=permit;let _global=global;let _active=super::Active::new(app.stats.clone());let _=process(session,&app,peer_ip,exporter).await;});
                    }
                    Some(H2Accept::Rejected)=>{rejected+=1;if rejected>=32 {break;}},None=>break,
                }
            }
            _=tokio::time::sleep(app.idle),if tasks.is_empty()=>break,
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
async fn process(
    mut session: HttpSession,
    app: &App,
    peer_ip: std::net::IpAddr,
    exporter: Option<[u8; 32]>,
) -> Result<()> {
    session.set_write_timeout(Some(app.idle));
    let head = {
        let req = session.req_header();
        Head {
            binding: exporter.map(|exporter| moon_naive_core::auth::Binding {
                exporter,
                stream_id: session.stream_id(),
            }),
            client_ip: Some(peer_ip),
            method: req.method.as_str().into(),
            authority: req.uri.authority().map(|a| a.as_str()).unwrap_or("").into(),
            scheme: req.uri.scheme_str().map(str::to_owned),
            path: if req.method == http::Method::CONNECT {
                req.uri.path_and_query().map(|p| p.as_str().to_owned())
            } else {
                Some(
                    req.uri
                        .path_and_query()
                        .map(|p| p.as_str())
                        .unwrap_or("/")
                        .into(),
                )
            },
            protocol: req
                .extensions
                .get::<h2::ext::Protocol>()
                .map(|p| p.as_str().into()),
            headers: req
                .headers
                .iter()
                .map(|(k, v)| (k.as_str().into(), v.as_bytes().to_vec()))
                .collect(),
        }
    };
    // No reads before admission. H2 receive windows bound already-arrived DATA.
    // Monitor resets while DNS/connect is pending, without reading request DATA
    // or granting extra flow-control credit.
    let plan = admit_until_closed(app.prepare(&head), session.idle()).await?;
    match plan {
        Plan::Website(head) => return app.site.h2(session, head).await,
        Plan::Forward(head, site) => return site.h2(session, head).await,
        Plan::Site(reply) => {
            write_header(&mut session, &reply, reply.body.is_empty())?;
            if !reply.body.is_empty() {
                session.write_body(reply.body, true).await?;
            }
        }
        Plan::Tunnel {
            target,
            framed,
            response,
            _permit,
        } => {
            let reply = response;
            write_header(&mut session, &reply, false)?;
            let mut writer = session
                .take_response_body_writer()
                .ok_or("H2 response stream unavailable")?;
            let (mut read, mut write) = tokio::io::split(target);
            let activity = Activity::new();
            let upload = async {
                let mut decoder = TunnelDecoder::new(framed);
                while let Some(data) = session.read_body_bytes().await? {
                    if !data.is_empty() {
                        activity.touch();
                    }
                    let data = app.resources.buffers.charge(data).await?;
                    decoder.write_to(&mut write, &data, &activity).await?;
                }
                if session.take_request_trailers().is_some() {
                    return Err("CONNECT trailers unsupported".into());
                }
                decoder.finish()?;
                write.shutdown().await?;
                activity.touch();
                Ok::<_, crate::acme::Error>(())
            };
            let download = async {
                let mut download = TunnelDownload::new(framed)?;
                while let Some(bytes) = download.read_next(&mut read).await? {
                    activity.touch();
                    let bytes = app.resources.buffers.charge(bytes).await?;
                    send_body(&mut writer, bytes, false, &activity).await?;
                }
                send_body(&mut writer, Bytes::new(), true, &activity).await?;
                Ok::<_, crate::acme::Error>(())
            };
            activity
                .run(app.idle, async {
                    tokio::try_join!(upload, download)?;
                    Ok(())
                })
                .await?;
            drop(_permit);
        }
    }
    Ok(())
}

async fn admit_until_closed(
    prepare: impl std::future::Future<Output = Result<Plan>>,
    closed: impl std::future::Future,
) -> Result<Plan> {
    // If both are ready, observe a known reset before polling admission. This
    // avoids starting DNS/connect or returning a plan for an already closed
    // stream. Dropping a pending prepare also releases its tunnel permit.
    tokio::select! {
        biased;
        _ = closed => Err("H2 request cancelled during admission".into()),
        plan = prepare => plan,
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use moon_naive_core::policy::Budget;
    use std::{cell::Cell, future};

    #[tokio::test]
    async fn known_reset_prevents_admission_side_effects() {
        let started = Cell::new(false);
        let prepare = async {
            started.set(true);
            Ok(Plan::Site(Reply::tunnel()))
        };
        assert!(
            admit_until_closed(prepare, future::ready(()))
                .await
                .is_err()
        );
        assert!(!started.get());
    }

    #[tokio::test]
    async fn reset_drops_pending_admission_and_releases_budget() {
        let budget = Budget::new(1).unwrap();
        let (started, wait_started) = tokio::sync::oneshot::channel();
        let prepare = async {
            let _permit = budget.acquire().unwrap();
            started.send(()).unwrap();
            future::pending::<Result<Plan>>().await
        };
        let closed = async {
            wait_started.await.unwrap();
            assert_eq!(budget.active(), 1);
        };
        assert!(admit_until_closed(prepare, closed).await.is_err());
        assert_eq!(budget.active(), 0);
    }
}

// Account for each partial flow-control grant. Never re-encode a padded chunk
// while it waits for capacity, and never count an empty DATA frame as activity.
async fn send_body(
    writer: &mut h2::SendStream<Bytes>,
    mut bytes: Bytes,
    fin: bool,
    activity: &Activity,
) -> Result<()> {
    if bytes.is_empty() {
        writer.send_data(bytes, fin)?;
        if fin {
            activity.touch();
        }
        return Ok(());
    }
    while !bytes.is_empty() {
        writer.reserve_capacity(bytes.len());
        let capacity = std::future::poll_fn(|cx| writer.poll_capacity(cx))
            .await
            .ok_or("H2 response capacity closed")??;
        if capacity == 0 {
            continue;
        }
        let part = bytes.split_to(bytes.len().min(capacity));
        writer.send_data(part, fin && bytes.is_empty())?;
        activity.touch();
    }
    Ok(())
}
fn write_header(session: &mut HttpSession, reply: &Reply, end: bool) -> Result<()> {
    let mut header = pingora_http::ResponseHeader::build(reply.status, None)?;
    for (name, value) in &reply.headers {
        let mut value = http::HeaderValue::from_str(value)?;
        // Keep the connection-bound proof out of the dynamic table.
        if name.eq_ignore_ascii_case("proxy-authentication-info") {
            value.set_sensitive(true);
        }
        header.insert_header(
            http::header::HeaderName::from_bytes(name.as_bytes())?,
            value,
        )?;
    }
    session.write_response_header(Box::new(header), end)?;
    Ok(())
}

// Coalesce only bytes already supplied by H2, before the TLS record layer.
// The inner Pingora BoringSSL stream advertises vectored writes, but its TLS
// adapter falls back to writing one slice. Do not delegate vectored writes.
// H2's normal flush drains short responses immediately; there is no timer or
// wait for another frame. One bounded buffer belongs to the entire connection.
mod write_buffer {
    use pingora_core::protocols::{
        ALPN, GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
        TimingDigest, UniqueID, UniqueIDType,
        raw_connect::ProxyDigest,
        tls::{SslDigest, TlsRef},
    };
    use std::{
        io::{self, IoSlice},
        pin::Pin,
        sync::Arc,
        task::{Context, Poll, ready},
        time::Duration,
    };
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

    const CAPACITY: usize = 16 * 1024;

    #[derive(Debug)]
    pub(super) struct WriteBuffer<S> {
        inner: S,
        bytes: Vec<u8>,
        written: usize,
        flushing: bool,
    }
    impl<S> WriteBuffer<S> {
        pub(super) fn new(inner: S) -> Self {
            Self {
                inner,
                bytes: Vec::with_capacity(CAPACITY),
                written: 0,
                flushing: false,
            }
        }
    }
    impl<S: AsyncWrite + Unpin> WriteBuffer<S> {
        fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            // Retain both the contents and the exact remaining slice across
            // Pending, including when no bytes have yet been accepted by TLS.
            // A cancelled flush must not permit appending to an SSL_write retry.
            self.flushing = true;
            while self.written < self.bytes.len() {
                let n =
                    ready!(Pin::new(&mut self.inner).poll_write(cx, &self.bytes[self.written..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                self.written += n;
            }
            self.bytes.clear();
            self.written = 0;
            self.flushing = false;
            Poll::Ready(Ok(()))
        }
        fn prepare(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.flushing || self.bytes.len() == CAPACITY {
                ready!(self.drain(cx))?;
            }
            Poll::Ready(Ok(()))
        }
    }
    impl<S: AsyncWrite + Unpin> AsyncWrite for WriteBuffer<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if bytes.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let this = self.get_mut();
            ready!(this.prepare(cx))?;
            let n = bytes.len().min(CAPACITY - this.bytes.len());
            this.bytes.extend_from_slice(&bytes[..n]);
            Poll::Ready(Ok(n))
        }
        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            slices: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            if slices.iter().all(|slice| slice.is_empty()) {
                return Poll::Ready(Ok(0));
            }
            let this = self.get_mut();
            ready!(this.prepare(cx))?;
            let before = this.bytes.len();
            for slice in slices {
                let n = slice.len().min(CAPACITY - this.bytes.len());
                this.bytes.extend_from_slice(&slice[..n]);
                if this.bytes.len() == CAPACITY {
                    break;
                }
            }
            Poll::Ready(Ok(this.bytes.len() - before))
        }
        fn is_write_vectored(&self) -> bool {
            true
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            ready!(this.drain(cx))?;
            Pin::new(&mut this.inner).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            ready!(this.drain(cx))?;
            Pin::new(&mut this.inner).poll_shutdown(cx)
        }
    }
    impl<S: AsyncRead + Unpin> AsyncRead for WriteBuffer<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, bytes)
        }
    }
    #[async_trait::async_trait]
    impl<S: AsyncWrite + Unpin + Send> Shutdown for WriteBuffer<S> {
        async fn shutdown(&mut self) {
            let _ = AsyncWriteExt::shutdown(self).await;
        }
    }
    impl<S: UniqueID> UniqueID for WriteBuffer<S> {
        fn id(&self) -> UniqueIDType {
            self.inner.id()
        }
    }
    impl<S: Ssl> Ssl for WriteBuffer<S> {
        fn get_ssl(&self) -> Option<&TlsRef> {
            self.inner.get_ssl()
        }
        fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> {
            self.inner.get_ssl_digest()
        }
        fn selected_alpn_proto(&self) -> Option<ALPN> {
            self.inner.selected_alpn_proto()
        }
    }
    impl<S: GetTimingDigest> GetTimingDigest for WriteBuffer<S> {
        fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
            self.inner.get_timing_digest()
        }
        fn get_read_pending_time(&self) -> Duration {
            self.inner.get_read_pending_time()
        }
        fn get_write_pending_time(&self) -> Duration {
            self.inner.get_write_pending_time()
        }
    }
    impl<S: GetProxyDigest> GetProxyDigest for WriteBuffer<S> {
        fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
            self.inner.get_proxy_digest()
        }
        fn set_proxy_digest(&mut self, digest: ProxyDigest) {
            self.inner.set_proxy_digest(digest);
        }
    }
    impl<S: GetSocketDigest> GetSocketDigest for WriteBuffer<S> {
        fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
            self.inner.get_socket_digest()
        }
        fn set_socket_digest(&mut self, digest: SocketDigest) {
            self.inner.set_socket_digest(digest);
        }
    }
    #[async_trait::async_trait]
    impl<S: Peek + Send> Peek for WriteBuffer<S> {
        async fn try_peek(&mut self, bytes: &mut [u8]) -> io::Result<bool> {
            self.inner.try_peek(bytes).await
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{collections::VecDeque, future::Future, task::Waker};

        #[derive(Debug)]
        enum Action {
            Accept(usize),
            Pending,
            Error(io::ErrorKind),
        }
        #[derive(Debug, Default)]
        struct Writer {
            actions: VecDeque<Action>,
            output: Vec<u8>,
            writes: Vec<usize>,
            retry: Option<(usize, Vec<u8>)>,
            flushes: usize,
            closed: bool,
        }
        impl AsyncWrite for Writer {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                if let Some((pointer, previous)) = self.retry.take() {
                    assert_eq!(bytes.as_ptr() as usize, pointer);
                    assert_eq!(bytes, previous);
                }
                match self
                    .actions
                    .pop_front()
                    .unwrap_or(Action::Accept(bytes.len()))
                {
                    Action::Accept(limit) => {
                        let n = limit.min(bytes.len());
                        self.output.extend_from_slice(&bytes[..n]);
                        self.writes.push(n);
                        Poll::Ready(Ok(n))
                    }
                    Action::Pending => {
                        self.retry = Some((bytes.as_ptr() as usize, bytes.to_vec()));
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Action::Error(kind) => Poll::Ready(Err(kind.into())),
                }
            }
            fn poll_write_vectored(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &[IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                panic!("TLS must receive one contiguous slice");
            }
            fn is_write_vectored(&self) -> bool {
                true
            }
            fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.flushes += 1;
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                self.closed = true;
                Poll::Ready(Ok(()))
            }
        }

        #[tokio::test]
        async fn vectored_header_and_payload_flush_as_one_short_write() {
            let mut io = WriteBuffer::new(Writer::default());
            let payload = [7; 8192];
            let slices = [
                IoSlice::new(&[]),
                IoSlice::new(b"123456789"),
                IoSlice::new(&payload),
            ];
            assert_eq!(io.write_vectored(&slices).await.unwrap(), 8201);
            assert!(io.inner.output.is_empty());
            io.flush().await.unwrap();
            assert_eq!(io.inner.writes, [8201]);
            assert_eq!(&io.inner.output[..9], b"123456789");
            assert_eq!(&io.inner.output[9..], payload);
            assert_eq!(io.inner.flushes, 1);
            assert_eq!(io.write_vectored(&[IoSlice::new(&[])]).await.unwrap(), 0);
            assert_eq!(io.write(&[]).await.unwrap(), 0);
        }

        #[tokio::test]
        async fn cancelled_flush_keeps_exact_pending_slice_before_new_data() {
            for prefix in [0, 7] {
                let mut inner = Writer::default();
                if prefix != 0 {
                    inner.actions.push_back(Action::Accept(prefix));
                }
                inner.actions.push_back(Action::Pending);
                let mut io = WriteBuffer::new(inner);
                io.write_all(b"abcdefghijkl").await.unwrap();
                let mut cx = Context::from_waker(Waker::noop());
                {
                    let mut flushing = std::pin::pin!(io.flush());
                    assert!(flushing.as_mut().poll(&mut cx).is_pending());
                }
                // The pinned future and its hidden storage were dropped;
                // resuming via write must finish the previous SSL_write first.
                io.write_all(b"XYZ").await.unwrap();
                io.flush().await.unwrap();
                assert_eq!(io.inner.output, b"abcdefghijklXYZ");
                assert!(!io.flushing);
                assert!(io.bytes.is_empty());
            }
        }

        #[tokio::test]
        async fn full_buffer_and_partial_vectored_writes_remain_bounded() {
            let mut io = WriteBuffer::new(Writer::default());
            let payload = vec![9; CAPACITY * 2 + 19];
            let slices = [IoSlice::new(b"head"), IoSlice::new(&payload)];
            assert_eq!(io.write_vectored(&slices).await.unwrap(), CAPACITY);
            assert_eq!(io.bytes.len(), CAPACITY);
            assert!(io.inner.output.is_empty());
            io.write_all(&payload[CAPACITY - 4..]).await.unwrap();
            AsyncWriteExt::shutdown(&mut io).await.unwrap();
            assert!(io.inner.closed);
            assert_eq!(io.inner.writes, [CAPACITY, CAPACITY, 23]);
            assert_eq!(&io.inner.output[..4], b"head");
            assert_eq!(&io.inner.output[4..], payload);
        }

        #[tokio::test]
        async fn shutdown_preserves_pending_bytes_and_flush_reports_errors() {
            let mut io = WriteBuffer::new(Writer {
                actions: [Action::Pending].into(),
                ..Writer::default()
            });
            io.write_all(b"last response").await.unwrap();
            AsyncWriteExt::shutdown(&mut io).await.unwrap();
            assert_eq!(io.inner.output, b"last response");
            assert!(io.inner.closed);
            for (action, kind) in [
                (Action::Accept(0), io::ErrorKind::WriteZero),
                (
                    Action::Error(io::ErrorKind::BrokenPipe),
                    io::ErrorKind::BrokenPipe,
                ),
            ] {
                let mut io = WriteBuffer::new(Writer {
                    actions: [action].into(),
                    ..Writer::default()
                });
                io.write_all(b"retained").await.unwrap();
                assert_eq!(io.flush().await.unwrap_err().kind(), kind);
                assert_eq!(io.bytes, b"retained");
                assert!(!io.inner.closed);
            }
        }
    }
}
