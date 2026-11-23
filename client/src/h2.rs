//! HTTP/2 transport: one shared TLS connection, one CONNECT stream per tunnel.
//!
//! Each proof binds the actual stream ID. `h2` assigns client stream IDs
//! sequentially when `send_request` is called, so stream opening is serialized
//! under a lock and the predicted ID is checked against the assigned one.
use crate::{
    config::Settings,
    tls,
    tunnel::{self, Framer, OpenError, READ_CHUNK, Unframer},
};
use bytes::Bytes;
use moon_naive_core::{auth::Binding, codec::Mode};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

struct Connection {
    opener: Mutex<(h2::client::SendRequest<Bytes>, u64)>,
    exporter: [u8; 32],
    closed: Arc<AtomicBool>,
}
pub struct Pool {
    settings: Arc<Settings>,
    current: Mutex<Option<Arc<Connection>>>,
}
pub struct Tunnel {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    mode: Mode,
}

impl Pool {
    pub fn new(settings: Arc<Settings>) -> Self {
        Self {
            settings,
            current: Mutex::new(None),
        }
    }
    async fn connection(&self) -> Result<Arc<Connection>, OpenError> {
        let mut current = self.current.lock().await;
        if let Some(connection) = current.as_ref()
            && !connection.closed.load(Ordering::Acquire)
        {
            return Ok(connection.clone());
        }
        let connection = Arc::new(
            tokio::time::timeout(self.settings.connect_timeout, connect(&self.settings))
                .await
                .map_err(|_| OpenError::Timeout)??,
        );
        *current = Some(connection.clone());
        Ok(connection)
    }
    pub async fn open(&self, authority: &str) -> Result<Tunnel, OpenError> {
        let connection = self.connection().await?;
        let result = open_on(&self.settings, &connection, authority).await;
        if matches!(result, Err(OpenError::Connection(_))) {
            connection.closed.store(true, Ordering::Release);
        }
        result
    }
}

async fn connect(settings: &Settings) -> Result<Connection, OpenError> {
    let failed = |e: String| OpenError::Connection(e);
    let tcp = TcpStream::connect((settings.host.as_str(), settings.port))
        .await
        .map_err(|e| failed(format!("TCP connect: {e}")))?;
    tcp.set_nodelay(true).ok();
    let mut connector = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())
        .map_err(|e| failed(e.to_string()))?;
    tls::configure(settings, &mut connector, b"\x02h2").map_err(failed)?;
    // ConnectConfiguration enables SNI and hostname verification.
    let mut configuration = connector
        .build()
        .configure()
        .map_err(|e| failed(e.to_string()))?;
    tls::apply_ech(settings, &mut configuration).map_err(failed)?;
    let stream = tokio_boring::connect(configuration, &settings.server_name, tcp)
        .await
        .map_err(|e| failed(format!("TLS handshake: {e}")))?;
    if stream.ssl().selected_alpn_protocol() != Some(b"h2") {
        return Err(failed("server did not negotiate h2".into()));
    }
    let exporter = tls::exporter(settings, stream.ssl()).map_err(failed)?;
    let (sender, connection) = h2::client::Builder::new()
        .enable_push(false)
        .handshake(stream)
        .await
        .map_err(|e| failed(format!("HTTP/2 handshake: {e}")))?;
    let closed = Arc::new(AtomicBool::new(false));
    let flag = closed.clone();
    tokio::spawn(async move {
        let _ = connection.await;
        flag.store(true, Ordering::Release);
    });
    Ok(Connection {
        opener: Mutex::new((sender, 1)),
        exporter,
        closed,
    })
}

async fn open_on(
    settings: &Settings,
    connection: &Connection,
    authority: &str,
) -> Result<Tunnel, OpenError> {
    let failed = |e: String| OpenError::Connection(e);
    let (response, send, binding) = {
        let mut opener = connection.opener.lock().await;
        let ready = opener
            .0
            .clone()
            .ready()
            .await
            .map_err(|e| failed(format!("HTTP/2 stream unavailable: {e}")))?;
        opener.0 = ready;
        let binding = Binding {
            exporter: connection.exporter,
            stream_id: opener.1,
        };
        let mut proof = http::HeaderValue::from_str(&tunnel::authorization(
            &settings.credentials,
            &binding,
            authority,
        ))
        .expect("ASCII proof");
        // Never index the proof in HPACK.
        proof.set_sensitive(true);
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(authority)
            .header("proxy-authorization", proof)
            .body(())
            .map_err(|_| OpenError::Status(400))?;
        let (response, send) = opener
            .0
            .send_request(request, false)
            .map_err(|e| failed(format!("HTTP/2 request: {e}")))?;
        if u64::from(u32::from(send.stream_id())) != binding.stream_id {
            return Err(failed(
                "HTTP/2 stream ID diverged from the signed ID".into(),
            ));
        }
        opener.1 += 2;
        (response, send, binding)
    };
    let response = tokio::time::timeout(settings.connect_timeout, response)
        .await
        .map_err(|_| OpenError::Timeout)?
        .map_err(|e| {
            if e.is_reset() {
                OpenError::Status(502)
            } else {
                failed(format!("HTTP/2 response: {e}"))
            }
        })?;
    let values: Vec<&str> = response
        .headers()
        .get_all("proxy-authentication-info")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let mode = tunnel::confirm(
        &settings.credentials,
        &binding,
        authority,
        response.status().as_u16(),
        &values,
    )?;
    Ok(Tunnel {
        send,
        recv: response.into_body(),
        mode,
    })
}

impl Tunnel {
    /// Relay until both directions finish. Each direction half-closes
    /// independently; any error resets the stream (dropping both handles
    /// makes `h2` send RST_STREAM).
    pub async fn relay(self, local: TcpStream) -> Result<(), String> {
        let Self {
            mut send,
            mut recv,
            mode,
        } = self;
        let (mut reader, mut writer) = local.into_split();
        let upload = async move {
            let mut framer = Framer::new(mode);
            let mut buffer = vec![0u8; READ_CHUNK];
            loop {
                let n = reader.read(&mut buffer).await.map_err(|e| e.to_string())?;
                if n == 0 {
                    send.send_data(Bytes::new(), true)
                        .map_err(|e| e.to_string())?;
                    return Ok::<_, String>(send);
                }
                let mut wire = framer.frame(&buffer[..n])?;
                while !wire.is_empty() {
                    send.reserve_capacity(wire.len());
                    let granted = std::future::poll_fn(|cx| send.poll_capacity(cx))
                        .await
                        .ok_or("stream closed")?
                        .map_err(|e| e.to_string())?;
                    let chunk = wire.split_to(granted.min(wire.len()));
                    send.send_data(chunk, false).map_err(|e| e.to_string())?;
                }
            }
        };
        let download = async move {
            let mut unframer = Unframer::new(mode);
            while let Some(data) = recv.data().await {
                let data = data.map_err(|e| e.to_string())?;
                let length = data.len();
                writer
                    .write_all(unframer.feed(&data)?)
                    .await
                    .map_err(|e| e.to_string())?;
                // Release credit only after the local peer accepted the bytes.
                let _ = recv.flow_control().release_capacity(length);
            }
            unframer.finish()?;
            writer.shutdown().await.map_err(|e| e.to_string())?;
            Ok::<_, String>(())
        };
        tokio::pin!(upload, download);
        let (mut uploaded, mut downloaded) = (None, false);
        while uploaded.is_none() || !downloaded {
            tokio::select! {
                result = &mut upload, if uploaded.is_none() => uploaded = Some(result?),
                result = &mut download, if !downloaded => { result?; downloaded = true; }
            }
        }
        drop(uploaded);
        Ok(())
    }
}
