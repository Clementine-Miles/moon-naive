//! HTTP/3 transport: one QUIC connection owned by a single driver task.
//!
//! Tunnels exchange data with the driver through bounded channels, so a slow
//! local peer stops `recv_body`, which in turn stops QUIC flow-control credit:
//! memory per stream is bounded by the channel depth. Proofs bind the actual
//! request stream ID (0, 4, 8, ...), which the driver predicts and verifies.
use crate::{
    config::Settings,
    tls,
    tunnel::{self, Framer, OpenError, READ_CHUNK, Unframer},
};
use bytes::Bytes;
use moon_naive_core::{auth::Binding, codec::Mode};
use quiche::h3::NameValue;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{Mutex, Notify, mpsc, oneshot},
};

const H3_NO_ERROR: u64 = 0x100;
const H3_REQUEST_CANCELLED: u64 = 0x10c;
/// Messages buffered per direction per stream (each at most one record).
const CHANNEL_DEPTH: usize = 8;
const DATAGRAM: usize = 1350;

#[derive(Clone)]
struct Handle {
    commands: mpsc::Sender<Request>,
    closed: Arc<AtomicBool>,
    wake: Arc<Notify>,
}
struct Request {
    authority: String,
    reply: oneshot::Sender<Result<Tunnel, OpenError>>,
}
pub struct Pool {
    settings: Arc<Settings>,
    current: Mutex<Option<Handle>>,
}
enum Up {
    Data(Bytes),
    Fin,
}
enum Down {
    Data(Bytes),
    Fin,
    Reset,
}
/// Wakes the driver when dropped so it notices closed channels promptly.
struct Waker(Arc<Notify>);
impl Drop for Waker {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}
pub struct Tunnel {
    mode: Mode,
    up: mpsc::Sender<Up>,
    down: mpsc::Receiver<Down>,
    waker: Waker,
}

impl Pool {
    pub fn new(settings: Arc<Settings>) -> Self {
        Self {
            settings,
            current: Mutex::new(None),
        }
    }
    async fn handle(&self) -> Result<Handle, OpenError> {
        let mut current = self.current.lock().await;
        if let Some(handle) = current.as_ref()
            && !handle.closed.load(Ordering::Acquire)
        {
            return Ok(handle.clone());
        }
        let handle = tokio::time::timeout(self.settings.connect_timeout, connect(&self.settings))
            .await
            .map_err(|_| OpenError::Timeout)??;
        *current = Some(handle.clone());
        Ok(handle)
    }
    pub async fn open(&self, authority: &str) -> Result<Tunnel, OpenError> {
        let handle = self.handle().await?;
        let (reply, response) = oneshot::channel();
        let request = Request {
            authority: authority.to_owned(),
            reply,
        };
        if handle.commands.send(request).await.is_err() {
            handle.closed.store(true, Ordering::Release);
            return Err(OpenError::Connection("QUIC connection closed".into()));
        }
        handle.wake.notify_one();
        // Dropping `response` on timeout makes the driver cancel the stream.
        tokio::time::timeout(self.settings.connect_timeout, response)
            .await
            .map_err(|_| OpenError::Timeout)?
            .map_err(|_| OpenError::Connection("QUIC connection closed".into()))?
    }
}

async fn connect(settings: &Arc<Settings>) -> Result<Handle, OpenError> {
    let failed = |e: String| OpenError::Connection(e);
    let peer = tokio::net::lookup_host((settings.host.as_str(), settings.port))
        .await
        .map_err(|e| failed(format!("resolve server: {e}")))?
        .next()
        .ok_or_else(|| failed("server name has no address".into()))?;
    let bind: SocketAddr = if peer.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| failed(format!("UDP bind: {e}")))?;
    socket
        .connect(peer)
        .await
        .map_err(|e| failed(format!("UDP connect: {e}")))?;
    let local = socket.local_addr().map_err(|e| failed(e.to_string()))?;
    let context = tls::quic_context(settings).map_err(failed)?;
    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, context)
        .map_err(|e| failed(format!("QUIC setup: {e}")))?;
    config.verify_peer(true);
    config
        .set_application_protos(&[b"h3"])
        .map_err(|e| failed(e.to_string()))?;
    config.set_max_idle_timeout(settings.quic_idle_timeout.as_millis() as u64);
    config.set_max_recv_udp_payload_size(DATAGRAM);
    config.set_max_send_udp_payload_size(DATAGRAM);
    // Bounded receive credit sized for a few concurrent tunnels.
    config.set_initial_max_data(4 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(512 * 1024);
    config.set_initial_max_stream_data_bidi_remote(0);
    config.set_initial_max_stream_data_uni(64 * 1024);
    // HTTP/3 servers never open bidirectional streams (RFC 9114, 6.1).
    config.set_initial_max_streams_bidi(0);
    config.set_initial_max_streams_uni(16);
    config.set_disable_active_migration(true);
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    boring::rand::rand_bytes(&mut scid).map_err(|e| failed(e.to_string()))?;
    let scid = quiche::ConnectionId::from_ref(&scid);
    let mut conn = quiche::connect(Some(&settings.server_name), &scid, local, peer, &mut config)
        .map_err(|e| failed(format!("QUIC connect: {e}")))?;
    tls::apply_ech(settings, conn.as_mut()).map_err(failed)?;
    let mut buffer = vec![0u8; 65535];
    let mut out = vec![0u8; DATAGRAM];
    while !conn.is_established() {
        flush(&mut conn, &socket, &mut out)
            .await
            .map_err(|e| failed(format!("UDP send: {e}")))?;
        if conn.is_closed() {
            let reason = conn
                .peer_error()
                .or(conn.local_error())
                .map_or("closed".into(), |e| format!("error {:#x}", e.error_code));
            return Err(failed(format!("QUIC handshake failed ({reason})")));
        }
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));
        tokio::select! {
            received = socket.recv(&mut buffer) => {
                let n = received.map_err(|e| failed(format!("UDP receive: {e}")))?;
                let _ = conn.recv(&mut buffer[..n], quiche::RecvInfo { from: peer, to: local });
            }
            _ = tokio::time::sleep(timeout) => conn.on_timeout(),
        }
    }
    let exporter = tls::exporter(settings, conn.as_mut()).map_err(failed)?;
    if conn.application_proto() != b"h3" {
        return Err(failed("server did not negotiate h3".into()));
    }
    let h3 = quiche::h3::Connection::with_transport(
        &mut conn,
        &quiche::h3::Config::new().map_err(|e| failed(e.to_string()))?,
    )
    .map_err(|e| failed(format!("HTTP/3 setup: {e}")))?;
    let (commands, receiver) = mpsc::channel(64);
    let handle = Handle {
        commands,
        closed: Arc::new(AtomicBool::new(false)),
        wake: Arc::new(Notify::new()),
    };
    let driver = Driver {
        settings: settings.clone(),
        conn,
        h3,
        socket,
        peer,
        local,
        exporter,
        next_id: 0,
        pending: VecDeque::new(),
        streams: HashMap::new(),
        wake: handle.wake.clone(),
        goaway: false,
    };
    tokio::spawn(driver.run(receiver, handle.closed.clone()));
    Ok(handle)
}

fn shutdown(conn: &mut quiche::Connection, id: u64) {
    let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, H3_REQUEST_CANCELLED);
    let _ = conn.stream_shutdown(id, quiche::Shutdown::Write, H3_REQUEST_CANCELLED);
}

async fn flush(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    out: &mut [u8],
) -> std::io::Result<()> {
    loop {
        match conn.send(out) {
            Ok((n, _)) => {
                socket.send(&out[..n]).await?;
            }
            Err(quiche::Error::Done) => return Ok(()),
            Err(_) => return Ok(()), // quiche closes the connection itself.
        }
    }
}

struct Stream {
    authority: String,
    binding: Binding,
    /// Present until the final response is handled.
    reply: Option<oneshot::Sender<Result<Tunnel, OpenError>>>,
    status: Option<u16>,
    up: mpsc::Receiver<Up>,
    down: mpsc::Sender<Down>,
    /// Handed to the tunnel on success.
    ends: Option<(mpsc::Sender<Up>, mpsc::Receiver<Down>)>,
    pending: Option<(Bytes, bool)>,
    fin_sent: bool,
    readable: bool,
    peer_fin: bool,
    fin_delivered: bool,
}
struct Driver {
    settings: Arc<Settings>,
    conn: quiche::Connection,
    h3: quiche::h3::Connection,
    socket: UdpSocket,
    peer: SocketAddr,
    local: SocketAddr,
    exporter: [u8; 32],
    next_id: u64,
    pending: VecDeque<Request>,
    streams: HashMap<u64, Stream>,
    wake: Arc<Notify>,
    goaway: bool,
}
enum Attempt {
    Opened,
    Blocked,
    Failed(OpenError),
}

impl Driver {
    async fn run(mut self, mut commands: mpsc::Receiver<Request>, closed: Arc<AtomicBool>) {
        let mut buffer = vec![0u8; 65535];
        let mut out = vec![0u8; DATAGRAM];
        let mut accepting = true;
        loop {
            let progressed = self.service();
            if self.goaway {
                // No new streams on this connection; the pool reconnects.
                closed.store(true, Ordering::Release);
            }
            if flush(&mut self.conn, &self.socket, &mut out).await.is_err() || self.conn.is_closed()
            {
                break;
            }
            if !accepting && self.streams.is_empty() && self.pending.is_empty() {
                let _ = self.conn.close(true, H3_NO_ERROR, b"");
                let _ = flush(&mut self.conn, &self.socket, &mut out).await;
                break;
            }
            if progressed {
                tokio::task::yield_now().await;
                continue;
            }
            let timeout = self.conn.timeout().unwrap_or(Duration::from_secs(3600));
            tokio::select! {
                received = self.socket.recv(&mut buffer) => {
                    let Ok(n) = received else { break };
                    self.receive(&mut buffer[..n]);
                    while let Ok(n) = self.socket.try_recv(&mut buffer) {
                        self.receive(&mut buffer[..n]);
                    }
                }
                request = commands.recv(), if accepting => match request {
                    Some(request) => self.pending.push_back(request),
                    None => accepting = false,
                },
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(timeout) => self.conn.on_timeout(),
            }
        }
        closed.store(true, Ordering::Release);
        for request in self.pending.drain(..) {
            let _ = request
                .reply
                .send(Err(OpenError::Connection("QUIC connection closed".into())));
        }
        for (_, stream) in self.streams.drain() {
            if let Some(reply) = stream.reply {
                let _ = reply.send(Err(OpenError::Connection("QUIC connection closed".into())));
            }
            let _ = stream.down.try_send(Down::Reset);
        }
        crate::log(
            &self.settings,
            crate::LogLevel::Debug,
            "event=h3_connection_closed",
        );
    }
    fn receive(&mut self, datagram: &mut [u8]) {
        let info = quiche::RecvInfo {
            from: self.peer,
            to: self.local,
        };
        let _ = self.conn.recv(datagram, info);
    }
    fn reset(&mut self, id: u64) {
        shutdown(&mut self.conn, id);
        self.streams.remove(&id);
    }
    /// Returns whether any work happened, so the caller loops again promptly.
    fn service(&mut self) -> bool {
        let mut progressed = false;
        loop {
            match self.h3.poll(&mut self.conn) {
                Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                    progressed = true;
                    self.on_headers(id, &list);
                }
                Ok((id, quiche::h3::Event::Data)) => {
                    if let Some(stream) = self.streams.get_mut(&id) {
                        stream.readable = true;
                    }
                }
                Ok((id, quiche::h3::Event::Finished)) => {
                    if let Some(stream) = self.streams.get_mut(&id) {
                        stream.peer_fin = true;
                        if stream.reply.is_some() {
                            // A response that ends before its final headers.
                            self.fail_stream(id, OpenError::Status(502));
                        }
                    }
                }
                Ok((id, quiche::h3::Event::Reset(_))) => {
                    progressed = true;
                    if let Some(stream) = self.streams.remove(&id) {
                        if let Some(reply) = stream.reply {
                            let _ = reply.send(Err(OpenError::Status(502)));
                        }
                        let _ = stream.down.try_send(Down::Reset);
                    }
                }
                Ok((_, quiche::h3::Event::GoAway)) => self.goaway = true,
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(_) => {
                    let _ = self.conn.close(true, 0x101, b"");
                    return false;
                }
            }
        }
        while let Some(request) = self.pending.pop_front() {
            if request.reply.is_closed() {
                continue;
            }
            if self.goaway {
                let _ = request
                    .reply
                    .send(Err(OpenError::Connection("server is going away".into())));
                continue;
            }
            match self.try_open(&request.authority) {
                Attempt::Opened => {
                    progressed = true;
                    let id = self.next_id - 4;
                    if let Some(stream) = self.streams.get_mut(&id) {
                        stream.reply = Some(request.reply);
                    }
                }
                Attempt::Blocked => {
                    self.pending.push_front(request);
                    break;
                }
                Attempt::Failed(error) => {
                    let _ = request.reply.send(Err(error));
                }
            }
        }
        let ids: Vec<u64> = self.streams.keys().copied().collect();
        for id in ids {
            progressed |= self.service_stream(id);
        }
        progressed
    }
    fn try_open(&mut self, authority: &str) -> Attempt {
        let binding = Binding {
            exporter: self.exporter,
            stream_id: self.next_id,
        };
        let proof = tunnel::authorization(&self.settings.credentials, &binding, authority);
        let headers = [
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":authority", authority.as_bytes()),
            quiche::h3::Header::new(b"proxy-authorization", proof.as_bytes()),
        ];
        match self.h3.send_request(&mut self.conn, &headers, false) {
            Ok(id) if id == binding.stream_id => {
                self.next_id += 4;
                let (up_tx, up_rx) = mpsc::channel(CHANNEL_DEPTH);
                let (down_tx, down_rx) = mpsc::channel(CHANNEL_DEPTH);
                self.streams.insert(
                    id,
                    Stream {
                        authority: authority.to_owned(),
                        binding,
                        reply: None,
                        status: None,
                        up: up_rx,
                        down: down_tx,
                        ends: Some((up_tx, down_rx)),
                        pending: None,
                        fin_sent: false,
                        readable: false,
                        peer_fin: false,
                        fin_delivered: false,
                    },
                );
                Attempt::Opened
            }
            Ok(id) => {
                // The proof is bound to a different stream: never usable.
                self.reset(id);
                let _ = self.conn.close(true, 0x101, b"");
                Attempt::Failed(OpenError::Connection(
                    "HTTP/3 stream ID diverged from the signed ID".into(),
                ))
            }
            Err(quiche::h3::Error::StreamBlocked)
            | Err(quiche::h3::Error::TransportError(quiche::Error::StreamLimit)) => {
                Attempt::Blocked
            }
            Err(e) => Attempt::Failed(OpenError::Connection(format!("HTTP/3 request: {e}"))),
        }
    }
    fn on_headers(&mut self, id: u64, list: &[quiche::h3::Header]) {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        if stream.reply.is_none() || stream.status.is_some() {
            // Trailers or unexpected fields after the final response.
            return self.reset(id);
        }
        let mut status = None;
        let mut confirmations = Vec::new();
        for field in list {
            match field.name() {
                b":status" => {
                    status = std::str::from_utf8(field.value())
                        .ok()
                        .and_then(|v| v.parse::<u16>().ok());
                }
                b"proxy-authentication-info" => {
                    if let Ok(value) = std::str::from_utf8(field.value()) {
                        confirmations.push(value.to_owned());
                    }
                }
                _ => {}
            }
        }
        let Some(status) = status else {
            return self.fail_stream(id, OpenError::Status(502));
        };
        if (100..200).contains(&status) {
            return; // Informational; wait for the final response.
        }
        stream.status = Some(status);
        let refs: Vec<&str> = confirmations.iter().map(String::as_str).collect();
        let outcome = tunnel::confirm(
            &self.settings.credentials,
            &stream.binding,
            &stream.authority,
            status,
            &refs,
        );
        let mode = match outcome {
            Ok(mode) => mode,
            Err(error) => return self.fail_stream(id, error),
        };
        let reply = stream.reply.take().expect("checked above");
        let (up, down) = stream.ends.take().expect("ends retained until success");
        let tunnel = Tunnel {
            mode,
            up,
            down,
            waker: Waker(self.wake.clone()),
        };
        if reply.send(Ok(tunnel)).is_err() {
            self.reset(id);
        }
    }
    fn fail_stream(&mut self, id: u64, error: OpenError) {
        if let Some(reply) = self.streams.get_mut(&id).and_then(|s| s.reply.take()) {
            let _ = reply.send(Err(error));
        }
        self.reset(id);
    }
    fn service_stream(&mut self, id: u64) -> bool {
        let Self {
            conn, h3, streams, ..
        } = self;
        let Some(stream) = streams.get_mut(&id) else {
            return false;
        };
        let (progressed, keep) = step(conn, h3, stream, id);
        if !keep {
            streams.remove(&id);
        }
        progressed
    }
}

/// Advance one stream. Returns (progressed, keep).
fn step(
    conn: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    stream: &mut Stream,
    id: u64,
) -> (bool, bool) {
    let mut progressed = false;
    if stream.reply.as_ref().is_some_and(|r| r.is_closed()) {
        shutdown(conn, id);
        return (true, false);
    }
    if stream.reply.is_some() {
        return (false, true); // Awaiting the response: no payload before confirmation.
    }
    // Upload: local bytes, already framed by the tunnel task.
    while !stream.fin_sent {
        if stream.pending.is_none() {
            stream.pending = match stream.up.try_recv() {
                Ok(Up::Data(data)) => Some((data, false)),
                Ok(Up::Fin) => Some((Bytes::new(), true)),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    shutdown(conn, id);
                    return (true, false);
                }
            };
        }
        let (data, fin) = stream.pending.take().expect("filled above");
        match h3.send_body(conn, id, &data, fin) {
            Ok(n) if n == data.len() => {
                progressed = true;
                stream.fin_sent = fin;
            }
            Ok(n) => {
                progressed |= n > 0;
                stream.pending = Some((data.slice(n..), fin));
                break;
            }
            Err(quiche::h3::Error::Done) => {
                stream.pending = Some((data, fin));
                break;
            }
            Err(_) => {
                shutdown(conn, id);
                return (true, false);
            }
        }
    }
    // Download: only read while the tunnel has room (backpressure).
    while stream.readable {
        let permit = match stream.down.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => break,
            Err(mpsc::error::TrySendError::Closed(())) => {
                shutdown(conn, id);
                return (true, false);
            }
        };
        let mut buffer = vec![0u8; READ_CHUNK];
        match h3.recv_body(conn, id, &mut buffer) {
            Ok(n) => {
                buffer.truncate(n);
                permit.send(Down::Data(Bytes::from(buffer)));
                progressed = true;
            }
            Err(quiche::h3::Error::Done) => stream.readable = false,
            Err(_) => {
                shutdown(conn, id);
                return (true, false);
            }
        }
    }
    if stream.peer_fin && !stream.readable && !stream.fin_delivered {
        match stream.down.try_send(Down::Fin) {
            Ok(()) => {
                stream.fin_delivered = true;
                progressed = true;
            }
            Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                shutdown(conn, id);
                return (true, false);
            }
        }
    }
    (progressed, !(stream.fin_sent && stream.fin_delivered))
}

impl Tunnel {
    pub async fn relay(self, local: TcpStream) -> Result<(), String> {
        let Self {
            mode,
            up,
            mut down,
            waker,
        } = self;
        let wake = waker.0.clone();
        let (mut reader, mut writer) = local.into_split();
        let upload_wake = wake.clone();
        let upload = async move {
            let mut framer = Framer::new(mode);
            let mut buffer = vec![0u8; READ_CHUNK];
            loop {
                let n = reader.read(&mut buffer).await.map_err(|e| e.to_string())?;
                let message = if n == 0 {
                    Up::Fin
                } else {
                    Up::Data(framer.frame(&buffer[..n])?)
                };
                up.send(message).await.map_err(|_| "QUIC stream closed")?;
                upload_wake.notify_one();
                if n == 0 {
                    return Ok::<_, String>(up);
                }
            }
        };
        let download = async move {
            let mut unframer = Unframer::new(mode);
            loop {
                let message = down.recv().await;
                // A slot freed: let the driver read more from QUIC.
                wake.notify_one();
                match message {
                    Some(Down::Data(data)) => writer
                        .write_all(unframer.feed(&data)?)
                        .await
                        .map_err(|e| e.to_string())?,
                    Some(Down::Fin) => {
                        unframer.finish()?;
                        writer.shutdown().await.map_err(|e| e.to_string())?;
                        return Ok::<_, String>(());
                    }
                    Some(Down::Reset) | None => return Err("stream reset by server".into()),
                }
            }
        };
        tokio::pin!(upload, download);
        let (mut uploaded, mut downloaded) = (None, false);
        while uploaded.is_none() || !downloaded {
            tokio::select! {
                result = &mut upload, if uploaded.is_none() => uploaded = Some(result?),
                result = &mut download, if !downloaded => { result?; downloaded = true; }
            }
        }
        drop((uploaded, waker));
        Ok(())
    }
}

/// Reports whether an instant is in the past; used for fallback cool-down.
pub(crate) fn expired(until: Option<Instant>) -> bool {
    until.is_none_or(|t| Instant::now() >= t)
}
