//! Single-owner QUIC driver. Bounded channels bridge to shared async egress.
//! Retry tokens are MACed, address/CID-bound and expire; no unauthenticated
//! connection allocation. 0-RTT and active migration are not enabled.
use super::site::forbidden_trailer;
use super::{
    Active, App, Bytes, CHUNK, Head, Plan, Reply, Result,
    tls::{Generation, Slot},
    tunnel::{Activity, TunnelDecoder, TunnelDownload},
};
use bytes::BytesMut;
use moon_naive_core::policy::{Budget, Permit};
use pingora_core::protocols::http::HttpTask;
use quiche::h3::NameValue;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{Notify, mpsc, oneshot, watch},
    task::JoinHandle,
};

const NO_ERROR: u64 = 0x100;
const CANCEL: u64 = 0x10c;

// One high-resolution timer for the whole driver, not one timer per packet or
// connection. Tokio's time wheel rounds sub-millisecond QUIC pacing deadlines.
struct DriverTimer {
    #[cfg(target_os = "linux")]
    fd: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
}
impl DriverTimer {
    fn new() -> Result<Self> {
        // Tokio 1.53 deprecated the generic safe constructor: arbitrary AsRawFd
        // implementations may return a closed or changing descriptor. Here the
        // concrete OwnedFd owns a fresh timerfd until AsyncFd drops it; it is
        // never replaced, closed externally, or exposed as mutable/raw state.
        // Keep forbid(unsafe_code) rather than call the new unsafe generic API.
        #[cfg(target_os = "linux")]
        #[expect(
            deprecated,
            reason = "private OwnedFd preserves Tokio's FD lifetime invariant"
        )]
        let fd = tokio::io::unix::AsyncFd::with_interest(
            rustix::time::timerfd_create(
                rustix::time::TimerfdClockId::Monotonic,
                rustix::time::TimerfdFlags::NONBLOCK | rustix::time::TimerfdFlags::CLOEXEC,
            )?,
            tokio::io::Interest::READABLE,
        )?;
        Ok(Self {
            #[cfg(target_os = "linux")]
            fd,
        })
    }
    async fn wait(&self, deadline: Instant) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            rustix::time::timerfd_settime(
                self.fd.get_ref(),
                rustix::time::TimerfdTimerFlags::empty(),
                &rustix::time::Itimerspec {
                    it_interval: rustix::time::Timespec::default(),
                    it_value: remaining.try_into()?,
                },
            )?;
            self.fd
                .async_io(tokio::io::Interest::READABLE, |fd| {
                    // read consumes the expiration counter. If a previous select
                    // was cancelled, stale readiness returns EAGAIN and is cleared.
                    rustix::io::read(fd, &mut [0u8; 8]).map_err(std::io::Error::from)
                })
                .await?;
        }
        #[cfg(not(target_os = "linux"))]
        tokio::time::sleep_until(deadline.into()).await;
        Ok(())
    }
}
struct Abort<T>(JoinHandle<T>);
impl<T> Drop for Abort<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Wake(Arc<Notify>);
impl Drop for Wake {
    fn drop(&mut self) {
        self.0.notify_one();
    }
}
struct Packet {
    data: Vec<u8>,
    to: SocketAddr,
    at: Instant,
}
#[derive(Debug, PartialEq, Eq)]
enum TransmitWait {
    Idle,
    Pacing(Instant),
    Writable,
    Budget,
}

// quiche reports edge-triggered path events even with active migration disabled
// (e.g. NAT port rebinding). Consume them throughout a long-lived connection.
// Path validation/migration remains quiche's responsibility, not this queue.
fn drain_path_events(conn: &mut quiche::Connection) -> usize {
    let mut count = 0;
    while count < 64 && conn.path_event_next().is_some() {
        count += 1;
    }
    count
}
// Keep exactly one packet when pacing or socket backpressure defers it. QUIC
// has already assigned its packet number and charged congestion control.
fn transmit(
    pending: &mut Option<Packet>,
    mut next: impl FnMut() -> std::result::Result<Packet, quiche::Error>,
    mut send: impl FnMut(&Packet) -> std::io::Result<usize>,
    mut now: impl FnMut() -> Instant,
) -> Result<TransmitWait> {
    for _ in 0..64 {
        if pending.is_none() {
            match next() {
                Ok(packet) => *pending = Some(packet),
                Err(quiche::Error::Done) => return Ok(TransmitWait::Idle),
                Err(error) => return Err(error.into()),
            }
        }
        let packet = pending.as_ref().unwrap();
        if packet.at > now() {
            return Ok(TransmitWait::Pacing(packet.at));
        }
        match send(packet) {
            Ok(n) if n == packet.data.len() => *pending = None,
            Ok(_) => return Err("partial UDP datagram send".into()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(TransmitWait::Writable);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    // A fairness limit is not a pacing deadline. Resume on the next task turn,
    // even if there is no incoming ACK or application notification to wake us.
    Ok(TransmitWait::Budget)
}
struct Client {
    conn: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    exporter: Option<[u8; 32]>,
    streams: HashMap<u64, Stream>,
    tx: Option<Packet>,
    handshake_deadline: Instant,
    _permit: Permit,
    _window: tokio::sync::OwnedSemaphorePermit,
    _generation: Arc<Generation>,
}
struct Stream {
    website: Option<Website>,
    request_trailers: Option<http::HeaderMap>,
    plan: Option<oneshot::Receiver<Result<Plan>>>,
    _prepare: Option<Abort<()>>,
    reply: Option<Reply>,
    sent_headers: bool,
    site: bool,
    input: Option<mpsc::Sender<Bytes>>,
    output: Option<mpsc::Receiver<Bytes>>,
    pending: Bytes,
    input_done: bool,
    output_done: bool,
    sent_fin: bool,
    task: Option<Abort<()>>,
    completion: Option<oneshot::Receiver<Result<()>>>,
    bridge_done: bool,
    _active: Active,
    _admission: Permit,
    activity: Activity,
}
struct Website {
    input: Option<mpsc::Sender<super::site::Input>>,
    output: mpsc::Receiver<HttpTask>,
    header: Option<Box<pingora_http::ResponseHeader>>,
    headers_started: bool,
    trailers: Option<Box<http::HeaderMap>>,
}
impl Stream {
    fn new(app: Arc<App>, head: Head, wake: Arc<Notify>, admission: Permit) -> Self {
        let (tx, rx) = oneshot::channel();
        let active = Active::new(app.stats.clone());
        let task = tokio::spawn(async move {
            let _wake = Wake(wake);
            let _ = tx.send(app.prepare(&head).await);
        });
        Self {
            website: None,
            request_trailers: None,
            plan: Some(rx),
            _prepare: Some(Abort(task)),
            reply: None,
            sent_headers: false,
            site: false,
            input: None,
            output: None,
            pending: Bytes::new(),
            input_done: false,
            output_done: false,
            sent_fin: false,
            task: None,
            completion: None,
            bridge_done: false,
            _active: active,
            _admission: admission,
            activity: Activity::new(),
        }
    }
    fn plan(&mut self, plan: Plan, app: &App, wake: Arc<Notify>) -> Result<()> {
        match plan {
            Plan::Website(head) => {
                let exchange = app.site.start(
                    head,
                    self.input_done && self.request_trailers.is_none(),
                    wake,
                );
                self.website = Some(Website {
                    input: Some(exchange.input),
                    output: exchange.output,
                    header: None,
                    headers_started: false,
                    trailers: None,
                });
                self.task = Some(Abort(exchange.task));
                self.completion = Some(exchange.completion);
            }
            Plan::Forward(head, site) => {
                let exchange = site.start(
                    head,
                    self.input_done && self.request_trailers.is_none(),
                    wake,
                );
                self.website = Some(Website {
                    input: Some(exchange.input),
                    output: exchange.output,
                    header: None,
                    headers_started: false,
                    trailers: None,
                });
                self.task = Some(Abort(exchange.task));
                self.completion = Some(exchange.completion);
            }
            Plan::Site(mut reply) => {
                self.pending = std::mem::take(&mut reply.body);
                self.reply = Some(reply);
                self.site = true;
                self.output_done = true;
                self.input_done = true;
                self.bridge_done = true;
            }
            Plan::Tunnel {
                target,
                framed,
                response,
                _permit,
            } => {
                if self.request_trailers.is_some() {
                    return Err("CONNECT trailers unsupported".into());
                }
                self.reply = Some(response);
                let (input, receive) = mpsc::channel(2);
                let (send, output) = mpsc::channel(2);
                // FIN can arrive while authentication/DNS/connect is pending.
                // Preserve that half-close instead of retaining a sender whose
                // receiver would otherwise wait forever after admission.
                if !self.input_done {
                    self.input = Some(input);
                }
                self.output = Some(output);
                let idle = app.idle;
                let activity = self.activity.clone();
                let (result, completion) = oneshot::channel();
                self.completion = Some(completion);
                self.task = Some(Abort(tokio::spawn(async move {
                    let _permit = _permit;
                    let _wake = Wake(wake.clone());
                    let _ = result
                        .send(bridge(target, framed, receive, send, idle, wake, activity).await);
                })));
            }
        }
        self.plan = None;
        self._prepare = None;
        self.activity.touch();
        Ok(())
    }
}
pub(super) async fn bridge(
    target: super::outbound::Stream,
    framed: Option<moon_naive_core::codec::Mode>,
    mut incoming: mpsc::Receiver<Bytes>,
    outgoing: mpsc::Sender<Bytes>,
    idle: Duration,
    wake: Arc<Notify>,
    activity: Activity,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let (mut read, mut write) = tokio::io::split(target);
    let notify = wake.clone();
    let upload = async {
        let mut decoder = TunnelDecoder::new(framed);
        while let Some(data) = incoming.recv().await {
            notify.notify_one();
            decoder.write_to(&mut write, &data, &activity).await?;
        }
        decoder.finish()?;
        write.shutdown().await?;
        activity.touch();
        Ok::<_, crate::acme::Error>(())
    };
    let download = async {
        let mut download = TunnelDownload::new(framed)?;
        while let Some(data) = download.read_next(&mut read).await? {
            activity.touch();
            outgoing.send(data).await?;
            wake.notify_one();
        }
        drop(outgoing);
        wake.notify_one();
        Ok::<_, crate::acme::Error>(())
    };
    activity
        .run(idle, async {
            tokio::try_join!(upload, download)?;
            Ok(())
        })
        .await?;
    Ok(())
}

pub(super) async fn serve(
    socket: UdpSocket,
    app: Arc<App>,
    tls: Slot,
    connections: Budget,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    if *stop.borrow() {
        return Ok(());
    }
    let mut clients: HashMap<Vec<u8>, Client> = HashMap::new();
    let mut buffer = vec![0; 65535];
    // Shared initialized scratch survives quiche Done without allocating once
    // per idle stream. Successful reads transfer only their initialized bytes.
    let mut body_buffer = BytesMut::new();
    let mut key = [0; 32];
    boring::rand::rand_bytes(&mut key)?;
    let mut h3_config = quiche::h3::Config::new()?;
    h3_config.enable_extended_connect(true);
    h3_config.set_max_field_section_size(32768);
    let wake = Arc::new(Notify::new());
    let timer = DriverTimer::new()?;
    let local = socket.local_addr()?;
    let mut draining: Option<Instant> = None;
    loop {
        #[cfg(test)]
        app.stats
            .h3_driver_iterations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = Instant::now();
        // Sleep until actual transport/application work is due. A fixed 50 ms
        // sweep keeps every idle connection needlessly active for its lifetime.
        let mut deadline = draining.unwrap_or(now + app.idle);
        let mut send_blocked = false;
        let mut send_again = false;
        // Retry proves address ownership, not completion of TLS. Do not allow
        // half-open handshakes to retain connection/window quotas for the much
        // longer application idle timeout. Established connections are exempt.
        clients.retain(|_, client| client.conn.is_established() || now < client.handshake_deadline);
        for client in clients.values_mut() {
            if !client.conn.is_established() {
                deadline = deadline.min(client.handshake_deadline);
            }
            if client.conn.timeout_instant().is_some_and(|t| t <= now) {
                client.conn.on_timeout();
            }
            if client.conn.is_established() && client.h3.is_none() {
                if client.conn.application_proto() != b"h3" {
                    let _ = client.conn.close(true, 0x100, b"");
                    continue;
                }
                match quiche::h3::Connection::with_transport(&mut client.conn, &h3_config) {
                    Ok(h3) => {
                        app.stats
                            .h3_connections
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        client.exporter = Some(super::exporter(client.conn.as_mut())?);
                        client.h3 = Some(h3);
                    }
                    Err(_) => {
                        let _ = client.conn.close(true, 0x102, b"");
                        continue;
                    }
                }
            }
            if let Some(h3) = &mut client.h3 {
                let ids: Vec<_> = client.streams.keys().copied().collect();
                for id in ids {
                    let stream = client.streams.get_mut(&id).unwrap();
                    if drive_stream(
                        &mut client.conn,
                        h3,
                        id,
                        stream,
                        &app,
                        wake.clone(),
                        &mut body_buffer,
                    )
                    .is_err()
                    {
                        let _ = client
                            .conn
                            .stream_shutdown(id, quiche::Shutdown::Read, CANCEL);
                        let _ = client
                            .conn
                            .stream_shutdown(id, quiche::Shutdown::Write, CANCEL);
                        client.streams.remove(&id);
                    }
                }
                let mut poll_budget_exhausted = true;
                for _ in 0..128 {
                    match h3.poll(&mut client.conn) {
                        Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                            if let Some(stream) = client.streams.get_mut(&id) {
                                match parse_trailers(&list) {
                                    Ok(headers) if stream.request_trailers.is_none() => {
                                        stream.request_trailers = Some(headers);
                                    }
                                    _ => {
                                        let _ = client.conn.stream_shutdown(
                                            id,
                                            quiche::Shutdown::Read,
                                            CANCEL,
                                        );
                                        let _ = client.conn.stream_shutdown(
                                            id,
                                            quiche::Shutdown::Write,
                                            CANCEL,
                                        );
                                        client.streams.remove(&id);
                                    }
                                }
                                continue;
                            }
                            if draining.is_some()
                                || client.streams.len() >= app.profile.max_streams() as usize
                            {
                                let _ =
                                    client
                                        .conn
                                        .stream_shutdown(id, quiche::Shutdown::Read, CANCEL);
                                let _ = client.conn.stream_shutdown(
                                    id,
                                    quiche::Shutdown::Write,
                                    CANCEL,
                                );
                                continue;
                            }
                            match parse_head(&list) {
                                Ok(mut head) => {
                                    head.binding = client.exporter.map(|exporter| {
                                        moon_naive_core::auth::Binding {
                                            exporter,
                                            stream_id: id,
                                        }
                                    });
                                    head.client_ip = client
                                        .conn
                                        .path_stats()
                                        .find(|path| path.active)
                                        .map(|path| path.peer_addr.ip());
                                    if let Some(permit) = app.requests.acquire() {
                                        client.streams.insert(
                                            id,
                                            Stream::new(app.clone(), head, wake.clone(), permit),
                                        );
                                    } else {
                                        let _ = client.conn.stream_shutdown(
                                            id,
                                            quiche::Shutdown::Read,
                                            0x10b,
                                        );
                                        let _ = client.conn.stream_shutdown(
                                            id,
                                            quiche::Shutdown::Write,
                                            0x10b,
                                        );
                                    }
                                }
                                Err(_) => {
                                    let _ = client.conn.stream_shutdown(
                                        id,
                                        quiche::Shutdown::Read,
                                        0x10e,
                                    );
                                    let _ = client.conn.stream_shutdown(
                                        id,
                                        quiche::Shutdown::Write,
                                        0x10e,
                                    );
                                }
                            }
                        }
                        Ok((id, quiche::h3::Event::Data)) => {
                            if let Some(stream) = client.streams.get_mut(&id)
                                && drive_stream(
                                    &mut client.conn,
                                    h3,
                                    id,
                                    stream,
                                    &app,
                                    wake.clone(),
                                    &mut body_buffer,
                                )
                                .is_err()
                            {
                                client.streams.remove(&id);
                                let _ =
                                    client
                                        .conn
                                        .stream_shutdown(id, quiche::Shutdown::Read, CANCEL);
                                let _ = client.conn.stream_shutdown(
                                    id,
                                    quiche::Shutdown::Write,
                                    CANCEL,
                                );
                            }
                            // poll can report the same unread DATA repeatedly.
                            // The bounded stream scan retries when queue space opens.
                            poll_budget_exhausted = false;
                            break;
                        }
                        Ok((id, quiche::h3::Event::Finished)) => {
                            if let Some(stream) = client.streams.get_mut(&id) {
                                stream.input_done = true;
                                stream.input = None;
                            }
                        }
                        Ok((id, quiche::h3::Event::Reset(_))) => {
                            client.streams.remove(&id);
                        }
                        Ok((_, quiche::h3::Event::GoAway))
                        | Ok((_, quiche::h3::Event::PriorityUpdate)) => {}
                        Err(quiche::h3::Error::Done) => {
                            poll_budget_exhausted = false;
                            break;
                        }
                        Err(_) => {
                            let _ = client.conn.close(true, 0x102, b"");
                            poll_budget_exhausted = false;
                            break;
                        }
                    }
                }
                send_again |= poll_budget_exhausted;
                client.streams.retain(|_, stream| {
                    !(stream.sent_fin && stream.input_done && stream.bridge_done)
                });
                for stream in client.streams.values() {
                    if stream.plan.is_none() {
                        deadline = deadline.min(stream.activity.deadline(app.idle).into_std());
                    }
                }
                if draining.is_some() && client.streams.is_empty() {
                    let _ = client.conn.close(true, NO_ERROR, b"");
                }
            }
            let progress = transmit(
                &mut client.tx,
                || {
                    let mut out = vec![0; 1350];
                    let (n, info) = client.conn.send(&mut out)?;
                    out.truncate(n);
                    Ok(Packet {
                        data: out,
                        to: info.to,
                        at: info.at,
                    })
                },
                |packet| socket.try_send_to(&packet.data, packet.to),
                Instant::now,
            );
            match progress {
                Ok(TransmitWait::Idle) => {}
                Ok(TransmitWait::Pacing(at)) => deadline = deadline.min(at),
                Ok(TransmitWait::Writable) => send_blocked = true,
                Ok(TransmitWait::Budget) => send_again = true,
                Err(_) => {
                    client.tx = None;
                    let _ = client.conn.close(false, 1, b"");
                }
            }
            let path_events = drain_path_events(&mut client.conn);
            send_again |= path_events == 64;
            #[cfg(test)]
            app.stats
                .h3_path_events
                .fetch_add(path_events, std::sync::atomic::Ordering::Relaxed);
            if let Some(t) = client.conn.timeout_instant() {
                deadline = deadline.min(t);
            }
        }
        clients.retain(|_, client| !client.conn.is_closed());
        if draining.is_some_and(|end| Instant::now() >= end || clients.is_empty()) {
            break;
        }
        tokio::select! {
            _=stop.changed(),if draining.is_none()=>{
                draining=Some(Instant::now()+app.graceful);
                for client in clients.values_mut() {if let Some(h3)=&mut client.h3 {let _=h3.send_goaway(&mut client.conn,(1u64<<62)-4);}}
            },
            _=wake.notified()=>{},
            ready=socket.writable(),if send_blocked=>{ready?;},
            _=tokio::task::yield_now(),if send_again=>{},
            result=timer.wait(deadline)=>{result?;},
            packet=socket.recv_from(&mut buffer)=>{
                let (n,from)=packet?;
                let header=match quiche::Header::from_slice(&mut buffer[..n],quiche::MAX_CONN_ID_LEN){Ok(h)=>h,Err(_)=>continue};
                let cid=header.dcid.to_vec();
                if !clients.contains_key(&cid) {
                    if draining.is_some() || n<1200 || header.ty!=quiche::Type::Initial {continue;}
                    let mut out=[0;1350];
                    if !quiche::version_is_supported(header.version) {
                        if let Ok(n)=quiche::negotiate_version(&header.scid,&header.dcid,&mut out){let _=socket.try_send_to(&out[..n],from);}continue;
                    }
                    let token=header.token.as_deref().unwrap_or(&[]);
                    if token.is_empty() {
                        let mut server_id=[0;quiche::MAX_CONN_ID_LEN];boring::rand::rand_bytes(&mut server_id)?;
                        let server_id=quiche::ConnectionId::from_ref(&server_id);
                        let token=mint(&key,from,&header.dcid,&server_id);
                        if let Ok(n)=quiche::retry(&header.scid,&header.dcid,&server_id,&token,header.version,&mut out){let _=socket.try_send_to(&out[..n],from);}continue;
                    }
                    let Some(original)=validate(&key,from,&cid,token) else {continue;};
                    let Some(permit)=connections.acquire() else {continue;};
                    let Ok(window)=app.receive.clone().try_acquire_many_owned(app.profile.connection_window()) else {continue;};
                    let generation=match tls.current(){Ok(g)=>g,Err(_)=>continue};
                    let conn={let mut config=generation.h3.lock().map_err(|_|"H3 config lock poisoned")?;quiche::accept(&header.dcid,Some(&quiche::ConnectionId::from_ref(&original)),local,from,&mut config)};
                    let Ok(conn)=conn else {continue;};
                    clients.insert(cid.clone(),Client {conn,h3:None,exporter:None,streams:HashMap::new(),tx:None,handshake_deadline:Instant::now()+super::HEADER_TIMEOUT,_permit:permit,_window:window,_generation:generation});
                }
                let client=clients.get_mut(&cid).unwrap();
                if client.conn.recv(&mut buffer[..n],quiche::RecvInfo {from,to:local}).is_err(){continue;}
            }
        }
    }
    Ok(())
}
fn recv_body(
    conn: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    id: u64,
    buffer: &mut BytesMut,
) -> Result<Option<Bytes>> {
    buffer.resize(CHUNK, 0);
    match h3.recv_body(conn, id, buffer) {
        Ok(0) | Err(quiche::h3::Error::Done) => Ok(None),
        Ok(n) => Ok(Some(buffer.split_to(n).freeze())),
        Err(e) => Err(e.into()),
    }
}

fn drive_stream(
    conn: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    id: u64,
    stream: &mut Stream,
    app: &App,
    wake: Arc<Notify>,
    body_buffer: &mut BytesMut,
) -> Result<()> {
    // An unread DATA frame can leave quiche H3 in its Data state, where poll()
    // alone won't consume/report a later reset. Check terminal transport state
    // even while admission/queues are blocked, without reading any DATA bytes.
    if !stream.sent_fin
        && matches!(
            conn.stream_capacity(id),
            Err(quiche::Error::StreamStopped(_))
        )
    {
        return Err("H3 peer stopped response".into());
    }
    if !stream.input_done && conn.stream_finished(id) && conn.stream_readable(id) {
        match conn.stream_recv(id, &mut []) {
            Err(quiche::Error::StreamReset(_)) => return Err("H3 peer reset request".into()),
            Ok((0, true)) => {
                // Only an EOF marker was consumed; all DATA was already read.
                // Carry the clean half-close through pending admission.
                stream.input_done = true;
                stream.input = None;
            }
            _ => {}
        }
    }
    if stream.plan.is_none() && stream.activity.is_idle(app.idle) {
        return Err("H3 stream idle deadline".into());
    }
    if let Some(completion) = &mut stream.completion {
        match completion.try_recv() {
            Ok(result) => {
                result?;
                stream.bridge_done = true;
                stream.completion = None;
            }
            Err(oneshot::error::TryRecvError::Empty) => {}
            Err(_) => return Err("H3 tunnel task cancelled".into()),
        }
    }
    if let Some(receiver) = &mut stream.plan {
        match receiver.try_recv() {
            Ok(plan) => stream.plan(plan?, app, wake)?,
            Err(oneshot::error::TryRecvError::Empty) => {}
            Err(_) => return Err("H3 admission task cancelled".into()),
        }
    }
    if stream.website.is_some() {
        return drive_website(conn, h3, id, stream, body_buffer);
    }
    if let Some(reply) = &stream.reply
        && !stream.sent_headers
    {
        let mut headers = vec![
            quiche::h3::Header::new(b":status", reply.status.to_string().as_bytes()),
            quiche::h3::Header::new(
                b"date",
                pingora_core::protocols::http::date::get_cached_date().as_bytes(),
            ),
        ];
        for (name, value) in &reply.headers {
            headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
        }
        let fin = stream.site && stream.pending.is_empty();
        match h3.send_response(conn, id, &headers, fin) {
            Ok(()) => {
                stream.sent_headers = true;
                stream.sent_fin = fin;
                stream.activity.touch();
            }
            Err(quiche::h3::Error::StreamBlocked) | Err(quiche::h3::Error::Done) => {
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        if stream.site {
            let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, NO_ERROR);
        }
    }
    if stream.sent_headers && !stream.site && !stream.input_done {
        if let Some(input) = &stream.input {
            for _ in 0..4 {
                if input.capacity() == 0 {
                    break;
                }
                let Some(bytes) = recv_body(conn, h3, id, body_buffer)? else {
                    break;
                };
                input
                    .try_send(bytes)
                    .map_err(|_| "H3 upload queue closed")?;
                stream.activity.touch();
            }
        }
        if conn.stream_finished(id) {
            stream.input_done = true;
            stream.input = None;
        }
    }
    if !stream.sent_headers {
        return Ok(());
    }
    for _ in 0..4 {
        if stream.pending.is_empty()
            && !stream.output_done
            && let Some(output) = &mut stream.output
        {
            match output.try_recv() {
                Ok(data) => stream.pending = data,
                Err(mpsc::error::TryRecvError::Disconnected) => stream.output_done = true,
                Err(mpsc::error::TryRecvError::Empty) => break,
            }
        }
        if stream.sent_fin {
            break;
        }
        if stream.pending.is_empty() && !stream.output_done {
            break;
        }
        let fin = stream.output_done;
        match h3.send_body(conn, id, &stream.pending, fin) {
            Ok(n) => {
                let _ = stream.pending.split_to(n);
                if n > 0 || (fin && stream.pending.is_empty()) {
                    stream.activity.touch();
                }
                if fin && stream.pending.is_empty() {
                    stream.sent_fin = true;
                }
            }
            Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => break,
            Err(e) => return Err(e.into()),
        }
    }
    if stream.activity.is_idle(app.idle) {
        return Err("H3 stream idle deadline".into());
    }
    Ok(())
}
fn drive_website(
    conn: &mut quiche::Connection,
    h3: &mut quiche::h3::Connection,
    id: u64,
    stream: &mut Stream,
    body_buffer: &mut BytesMut,
) -> Result<()> {
    let web = stream.website.as_mut().expect("website stream");
    if let Some(input) = &web.input {
        if input.is_closed() {
            web.input = None;
        } else if !stream.input_done {
            for _ in 0..4 {
                if input.capacity() == 0 {
                    break;
                }
                let Some(bytes) = recv_body(conn, h3, id, body_buffer)? else {
                    break;
                };
                input.try_send(super::site::Input::Data(bytes))?;
                stream.activity.touch();
            }
        }
    }
    if stream.input_done
        && let Some(input) = &web.input
    {
        if let Some(trailers) = stream.request_trailers.take() {
            match input.try_send(super::site::Input::Trailers(trailers)) {
                Ok(()) => web.input = None,
                Err(mpsc::error::TrySendError::Full(super::site::Input::Trailers(trailers))) => {
                    stream.request_trailers = Some(trailers)
                }
                Err(_) => web.input = None,
            }
        } else {
            web.input = None;
        }
    }
    for _ in 0..4 {
        if stream.pending.is_empty()
            && web.header.is_none()
            && web.trailers.is_none()
            && !stream.output_done
        {
            match web.output.try_recv() {
                Ok(HttpTask::Header(header, end)) => {
                    web.header = Some(header);
                    stream.output_done = end;
                }
                Ok(HttpTask::Body(bytes, end)) => {
                    stream.pending = bytes.unwrap_or_default();
                    stream.output_done = end;
                }
                Ok(HttpTask::Trailer(trailers)) => {
                    web.trailers = trailers;
                    stream.output_done = true;
                }
                Ok(HttpTask::Done) => stream.output_done = true,
                Ok(HttpTask::Failed(e)) => return Err(e.into()),
                Ok(HttpTask::UpgradedBody(..)) => return Err("website upgrade unsupported".into()),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    return Err("website response truncated".into());
                }
            }
        }
        if let Some(header) = &web.header {
            let mut headers = vec![quiche::h3::Header::new(
                b":status",
                header.status.as_str().as_bytes(),
            )];
            for (name, value) in &header.headers {
                headers.push(quiche::h3::Header::new(
                    name.as_str().as_bytes(),
                    value.as_bytes(),
                ));
            }
            let informational = header.status.is_informational();
            let result = if web.headers_started {
                h3.send_additional_headers(conn, id, &headers, false, stream.output_done)
            } else {
                h3.send_response(conn, id, &headers, stream.output_done)
            };
            match result {
                Ok(()) => {
                    web.headers_started = true;
                    stream.sent_headers = !informational;
                    stream.sent_fin = stream.output_done;
                    web.header = None;
                    if informational {
                        continue;
                    }
                    stream.activity.touch();
                }
                Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => break,
                Err(e) => return Err(e.into()),
            }
        }
        if stream.sent_fin {
            break;
        }
        if !stream.sent_headers {
            return Err("website body before headers".into());
        }
        if let Some(trailers) = &web.trailers {
            let headers = trailers
                .iter()
                .filter(|(name, _)| !forbidden_trailer(name.as_str()))
                .map(|(name, value)| {
                    quiche::h3::Header::new(name.as_str().as_bytes(), value.as_bytes())
                })
                .collect::<Vec<_>>();
            match h3.send_additional_headers(conn, id, &headers, true, true) {
                Ok(()) => {
                    web.trailers = None;
                    stream.sent_fin = true;
                    stream.activity.touch();
                }
                Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => break,
                Err(e) => return Err(e.into()),
            }
            break;
        }
        if stream.pending.is_empty() && !stream.output_done {
            continue;
        }
        match h3.send_body(conn, id, &stream.pending, stream.output_done) {
            Ok(n) => {
                let _ = stream.pending.split_to(n);
                if n > 0 {
                    stream.activity.touch();
                }
                if stream.output_done && stream.pending.is_empty() {
                    stream.sent_fin = true;
                    stream.activity.touch();
                }
            }
            Err(quiche::h3::Error::Done | quiche::h3::Error::StreamBlocked) => break,
            Err(e) => return Err(e.into()),
        }
    }
    if stream.sent_fin {
        // A final response may precede request EOF (e.g. 405 or 413).
        let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, NO_ERROR);
        web.input = None;
        stream.input_done = true;
    }
    Ok(())
}
fn parse_trailers(headers: &[quiche::h3::Header]) -> Result<http::HeaderMap> {
    if headers.len() > 128
        || headers
            .iter()
            .map(|h| h.name().len() + h.value().len() + 32)
            .sum::<usize>()
            > 32768
    {
        return Err("H3 trailer limit".into());
    }
    let mut result = http::HeaderMap::new();
    for header in headers {
        let name = std::str::from_utf8(header.name())?;
        if name.bytes().any(|b| b.is_ascii_uppercase()) || forbidden_trailer(name) {
            return Err("forbidden H3 trailer".into());
        }
        result.append(
            http::header::HeaderName::from_bytes(header.name())?,
            http::HeaderValue::from_bytes(header.value())?,
        );
    }
    Ok(result)
}
fn parse_head(headers: &[quiche::h3::Header]) -> Result<Head> {
    if headers.len() > 128 {
        return Err("H3 header count limit".into());
    }
    let mut head = Head {
        binding: None,
        client_ip: None,
        method: String::new(),
        authority: String::new(),
        scheme: None,
        path: None,
        protocol: None,
        headers: Vec::new(),
    };
    let mut ordinary = false;
    let mut pseudo = std::collections::HashSet::new();
    for field in headers {
        let name = std::str::from_utf8(field.name())?;
        if name.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err("H3 uppercase header name".into());
        }
        if name.starts_with(':') {
            if ordinary || !pseudo.insert(name) {
                return Err("H3 duplicate/out-of-order pseudo-header".into());
            }
            let value = std::str::from_utf8(field.value())?.to_owned();
            match name {
                ":method" => head.method = value,
                ":authority" => head.authority = value,
                ":scheme" => head.scheme = Some(value),
                ":path" => head.path = Some(value),
                ":protocol" => head.protocol = Some(value),
                _ => return Err("H3 unknown pseudo-header".into()),
            }
        } else {
            ordinary = true;
            let _ = http::header::HeaderName::from_bytes(name.as_bytes())?;
            let _ = http::HeaderValue::from_bytes(field.value())?;
            head.headers.push((name.into(), field.value().to_vec()));
        }
    }
    if head.method.is_empty() || head.authority.is_empty() || !head.valid() {
        return Err("H3 malformed request".into());
    }
    Ok(head)
}
fn mint(key: &[u8], from: SocketAddr, original: &[u8], server: &[u8]) -> Vec<u8> {
    let mut token = crate::acme::now().to_be_bytes().to_vec();
    token.push(original.len() as u8);
    token.extend(original);
    token.extend(server);
    let mut message = token.clone();
    message.extend(from.to_string().bytes());
    token.extend(boring::hash::hmac_sha256(key, &message).expect("HMAC-SHA256 available"));
    token
}
fn validate(key: &[u8], from: SocketAddr, server: &[u8], token: &[u8]) -> Option<Vec<u8>> {
    if token.len() < 62 || server.len() != quiche::MAX_CONN_ID_LEN {
        return None;
    }
    let time = u64::from_be_bytes(token[..8].try_into().ok()?);
    let now = crate::acme::now();
    if time > now || now - time > 60 {
        return None;
    }
    let len = token[8] as usize;
    if len == 0 || len > quiche::MAX_CONN_ID_LEN || token.len() != 9 + len + server.len() + 32 {
        return None;
    }
    let split = token.len() - 32;
    let mut message = token[..split].to_vec();
    message.extend(from.to_string().bytes());
    if !boring::memcmp::eq(
        &boring::hash::hmac_sha256(key, &message).ok()?,
        &token[split..],
    ) || &token[9 + len..split] != server
    {
        return None;
    }
    Some(token[9..9 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn driver_timer_rearms_after_cancel_and_expiry_without_early_wakeup() {
        let timer = DriverTimer::new().unwrap();
        // Cancel a registered wait, then leave its expiration unread.
        tokio::select! {
            biased;
            _=timer.wait(Instant::now()+Duration::from_secs(60))=>panic!("early timer"),
            _=std::future::ready(())=>{},
        }
        rustix::time::timerfd_settime(
            timer.fd.get_ref(),
            rustix::time::TimerfdTimerFlags::empty(),
            &rustix::time::Itimerspec {
                it_interval: rustix::time::Timespec::default(),
                it_value: Duration::from_nanos(1).try_into().unwrap(),
            },
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let deadline = Instant::now() + Duration::from_millis(3);
        tokio::time::timeout(Duration::from_secs(1), timer.wait(deadline))
            .await
            .unwrap()
            .unwrap();
        assert!(Instant::now() >= deadline);
        // An already due timer must return instead of arming a zero/disarmed fd.
        tokio::time::timeout(Duration::from_secs(1), timer.wait(Instant::now()))
            .await
            .unwrap()
            .unwrap();
    }
    #[test]
    fn paced_datagram_survives_backpressure_without_regeneration() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let mut pending = None;
        let mut generated = 0;
        let mut next = || {
            generated += 1;
            if generated == 1 {
                Ok(Packet {
                    data: vec![1, 2, 3],
                    to: "127.0.0.1:1".parse().unwrap(),
                    at: later,
                })
            } else {
                Err(quiche::Error::Done)
            }
        };
        assert_eq!(
            transmit(
                &mut pending,
                &mut next,
                |_| panic!("sent before pacing deadline"),
                || now
            )
            .unwrap(),
            TransmitWait::Pacing(later)
        );
        assert_eq!(
            transmit(
                &mut pending,
                &mut next,
                |_| Err(std::io::ErrorKind::WouldBlock.into()),
                || later
            )
            .unwrap(),
            TransmitWait::Writable
        );
        assert_eq!(pending.as_ref().unwrap().data, [1, 2, 3]);
        let mut writes = 0;
        assert_eq!(
            transmit(
                &mut pending,
                &mut next,
                |packet| {
                    writes += 1;
                    assert_eq!(packet.data, [1, 2, 3]);
                    Ok(packet.data.len())
                },
                || later
            )
            .unwrap(),
            TransmitWait::Idle
        );
        assert_eq!(writes, 1);
        assert_eq!(generated, 2); // One packet followed by Done; no regeneration.
        assert!(pending.is_none());
    }
    #[test]
    fn transmit_budget_requires_continuation_and_keeps_next_paced_packet() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let mut pending = None;
        let mut generated = 0;
        let mut next = || {
            generated += 1;
            Ok(Packet {
                data: vec![generated],
                to: "127.0.0.1:1".parse().unwrap(),
                at: if generated <= 64 { now } else { later },
            })
        };
        let mut written = Vec::new();
        assert_eq!(
            transmit(
                &mut pending,
                &mut next,
                |packet| {
                    written.push(packet.data[0]);
                    Ok(1)
                },
                || now
            )
            .unwrap(),
            TransmitWait::Budget
        );
        assert_eq!(written, (1..=64).collect::<Vec<_>>());
        assert_eq!(
            transmit(
                &mut pending,
                &mut next,
                |_| panic!("next packet is paced"),
                || now
            )
            .unwrap(),
            TransmitWait::Pacing(later)
        );
        assert_eq!(pending.as_ref().unwrap().data, [65]);
    }
    #[test]
    fn retry_token_authenticates_address_cid_and_expiry() {
        let key = [7; 32];
        let from = "127.0.0.1:12345".parse().unwrap();
        let original = [5; 8];
        let server = [9; 20];
        let token = mint(&key, from, &original, &server);
        assert_eq!(
            validate(&key, from, &server, &token),
            Some(original.to_vec())
        );
        assert!(validate(&key, "127.0.0.1:12346".parse().unwrap(), &server, &token).is_none());
        assert!(validate(&key, from, &[10; 20], &token).is_none());
        let mut tampered = token.clone();
        tampered[12] ^= 1;
        assert!(validate(&key, from, &server, &tampered).is_none());
        let mut expired = token;
        expired[..8].copy_from_slice(&(crate::acme::now() - 61).to_be_bytes());
        let split = expired.len() - 32;
        let mut message = expired[..split].to_vec();
        message.extend(from.to_string().bytes());
        expired[split..].copy_from_slice(&boring::hash::hmac_sha256(&key, &message).unwrap());
        assert!(validate(&key, from, &server, &expired).is_none());
    }
}
