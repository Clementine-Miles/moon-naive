//! Moon-naive first-party client.
//!
//! Accepts local SOCKS5 and HTTP CONNECT requests and carries each one over
//! its own authenticated mona (Rupin profile) CONNECT stream. The proxy
//! connection is made by the Moon-naive Chromium Native Engine
//! (`libmoon_engine`, Chromium's own HTTP/2 and QUIC/HTTP/3 stack, see
//! `moon-naive-engine`). This crate supplies the Rupin proofs, verifies the
//! confirmation before any payload, frames records and runs the local side.
//! Certificate verification is always on, TLS 1.3 is required, ECH is
//! mandatory when configured, and TCP Fast Open is never used.
pub mod config;
pub mod local;
pub mod tunnel;

pub use config::{Config, LogLevel, Settings, Transport};
use moon_naive_core::{auth::Binding, codec::Mode};
pub use moon_naive_engine as engine;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task::JoinSet,
};
use tunnel::{Framer, OpenError, READ_CHUNK, Unframer};

/// How long the H3-then-H2 policy avoids QUIC after it failed to connect.
const H3_COOL_DOWN: Duration = Duration::from_secs(300);

pub(crate) fn log(settings: &Settings, level: LogLevel, message: &str) {
    if level <= settings.log {
        eprintln!("{message}");
    }
}

/// Signs and verifies on the engine thread with the configured credentials.
struct RupinAuthenticator {
    settings: Arc<Settings>,
}
impl RupinAuthenticator {
    fn binding(binding: &engine::Binding) -> Binding {
        Binding {
            exporter: binding.exporter,
            stream_id: binding.stream_id,
        }
    }
}
impl engine::Authenticator for RupinAuthenticator {
    fn authorize(&self, binding: &engine::Binding, authority: &str) -> Option<Vec<u8>> {
        // Chromium enforces strict ECH already; never sign without it.
        if self.settings.ech_config_list.is_some() && !binding.ech_accepted {
            return None;
        }
        Some(
            tunnel::authorization(
                &self.settings.credentials,
                &Self::binding(binding),
                authority,
            )
            .into_bytes(),
        )
    }
    fn verify(&self, binding: &engine::Binding, authority: &str, values: &[&[u8]]) -> Option<u8> {
        let values: Vec<&str> = values
            .iter()
            .map(|value| std::str::from_utf8(value))
            .collect::<Result<_, _>>()
            .ok()?;
        tunnel::confirm(
            &self.settings.credentials,
            &Self::binding(binding),
            authority,
            200,
            &values,
        )
        .ok()
        .map(Mode::bits)
    }
}

/// The engine configuration for these settings.
pub fn engine_config(settings: &Settings) -> engine::Config {
    engine::Config {
        library: settings.engine_library.clone(),
        server_name: settings.server_name.clone(),
        connect_host: (settings.host != settings.server_name).then(|| settings.host.clone()),
        port: settings.port,
        ca_file: settings.ca_file.clone(),
        ech_config_list: settings.ech_config_list.clone(),
        exporter_label: moon_naive_core::auth::EXPORTER_LABEL.to_owned(),
        quic_idle_timeout: settings.quic_idle_timeout,
    }
}

/// An established, confirmed tunnel and its record mode.
pub struct Remote {
    tunnel: engine::Tunnel,
    mode: Mode,
    transport: engine::Transport,
}
impl Remote {
    fn transport(&self) -> &'static str {
        match self.transport {
            engine::Transport::H2 => "h2",
            engine::Transport::H3 => "h3",
        }
    }
    /// Relay until both directions finished. Half-close is propagated in each
    /// direction independently; any error resets the stream.
    pub async fn relay(self, local: TcpStream) -> Result<(), String> {
        let (mut remote_read, mut remote_write) = self.tunnel.into_split();
        let mode = self.mode;
        let (mut reader, mut writer) = local.into_split();
        let upload = async move {
            let mut framer = Framer::new(mode);
            let mut buffer = vec![0u8; READ_CHUNK];
            loop {
                let n = reader.read(&mut buffer).await.map_err(|e| e.to_string())?;
                if n == 0 {
                    remote_write.shutdown().await.map_err(|e| e.to_string())?;
                    return Ok::<_, String>(remote_write);
                }
                let wire = framer.frame(&buffer[..n])?;
                remote_write
                    .write_all(&wire)
                    .await
                    .map_err(|e| e.to_string())?;
            }
        };
        let download = async move {
            let mut unframer = Unframer::new(mode);
            while let Some(data) = remote_read.read().await.map_err(|e| e.to_string())? {
                writer
                    .write_all(unframer.feed(&data)?)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            unframer.finish()?;
            writer.shutdown().await.map_err(|e| e.to_string())?;
            Ok::<_, String>(remote_read)
        };
        // Keep both halves alive until both directions completed, so the
        // engine sees a finished stream rather than an abort.
        let (uploaded, downloaded) = tokio::try_join!(upload, download)?;
        drop((uploaded, downloaded));
        Ok(())
    }
}

fn map_open_error(error: engine::OpenError) -> OpenError {
    match error {
        engine::OpenError::Connection { net_error } => {
            OpenError::Connection(format!("net error {net_error}"))
        }
        engine::OpenError::Status(status) => OpenError::Status(status),
        engine::OpenError::Confirmation => OpenError::Confirmation,
        engine::OpenError::Refused => OpenError::Refused,
        engine::OpenError::Invalid => OpenError::Invalid,
        engine::OpenError::Closed => OpenError::Connection("engine closed".into()),
    }
}

/// Opens tunnels on the configured transport(s).
pub struct Dialer {
    settings: Arc<Settings>,
    engine: engine::Engine,
    h3_cool_down: Mutex<Option<Instant>>,
}
impl Dialer {
    /// Load and start the engine. Fails with an actionable message when the
    /// engine library is unavailable; there is no other transport.
    pub fn new(settings: Arc<Settings>) -> Result<Self, String> {
        let log_settings = settings.clone();
        let logger: engine::Logger = Box::new(move |level, message| {
            let level = match level {
                engine::LogLevel::Info => LogLevel::Debug,
                engine::LogLevel::Warning => LogLevel::Info,
                engine::LogLevel::Error => LogLevel::Error,
            };
            log(
                &log_settings,
                level,
                &format!("event=engine message={message:?}"),
            );
        });
        let engine = engine::Engine::new(
            &engine_config(&settings),
            Arc::new(RupinAuthenticator {
                settings: settings.clone(),
            }),
            Some(logger),
        )?;
        Ok(Self {
            settings,
            engine,
            h3_cool_down: Mutex::new(None),
        })
    }

    async fn open_on(
        &self,
        authority: &str,
        transport: engine::Transport,
    ) -> Result<Remote, OpenError> {
        let (tunnel, opened) = tokio::time::timeout(
            self.settings.connect_timeout,
            self.engine.open(authority, transport),
        )
        .await
        .map_err(|_| OpenError::Timeout)?
        .map_err(map_open_error)?;
        // The selection was authenticated by the confirmation MAC.
        let mode = Mode::from_bits(opened.selection).map_err(|_| OpenError::Confirmation)?;
        if opened.transport != transport {
            return Err(OpenError::Confirmation);
        }
        Ok(Remote {
            tunnel,
            mode,
            transport,
        })
    }

    pub async fn open(&self, authority: &str) -> Result<Remote, OpenError> {
        let (h2, h3) = match self.settings.transport {
            Transport::H2 => (true, false),
            Transport::H3 => (false, true),
            Transport::H3ThenH2 => (true, true),
        };
        if h3 {
            let cooling = self
                .h3_cool_down
                .lock()
                .expect("cool-down lock")
                .is_some_and(|until| Instant::now() < until);
            if !h2 || !cooling {
                match self.open_on(authority, engine::Transport::H3).await {
                    Ok(remote) => return Ok(remote),
                    // Only a QUIC connection failure falls back. Server
                    // answers (status, confirmation) are final on any transport.
                    Err(OpenError::Connection(_) | OpenError::Timeout) if h2 => {
                        log(
                            &self.settings,
                            LogLevel::Info,
                            "event=h3_unavailable fallback=h2 cool_down_secs=300",
                        );
                        *self.h3_cool_down.lock().expect("cool-down lock") =
                            Some(Instant::now() + H3_COOL_DOWN);
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        self.open_on(authority, engine::Transport::H2).await
    }
}

/// Bind the configured listener and serve until `shutdown` becomes true.
pub async fn run(settings: Arc<Settings>, shutdown: watch::Receiver<bool>) -> Result<(), String> {
    let listener = TcpListener::bind(settings.listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", settings.listen))?;
    serve(settings, listener, shutdown).await
}

/// Serve local requests on an already bound listener.
pub async fn serve(
    settings: Arc<Settings>,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), String> {
    let address = listener.local_addr().map_err(|e| e.to_string())?;
    // The local proxy has no authentication: never serve beyond loopback.
    if !address.ip().is_loopback() {
        return Err(format!(
            "refusing to serve on non-loopback address {address}: the local proxy has no authentication"
        ));
    }
    log(
        &settings,
        LogLevel::Info,
        &format!(
            "event=client_ready listen={address} transport={:?} ech={}",
            settings.transport,
            settings.ech_config_list.is_some()
        ),
    );
    // Starting the engine waits for its thread; keep that off the runtime.
    let dialer = {
        let settings = settings.clone();
        Arc::new(
            tokio::task::spawn_blocking(move || Dialer::new(settings))
                .await
                .map_err(|e| e.to_string())??,
        )
    };
    let permits = Arc::new(Semaphore::new(settings.max_tunnels));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.wait_for(|stop| *stop) => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    log(&settings, LogLevel::Error, "event=local_rejected reason=max_tunnels");
                    continue;
                };
                let (settings, dialer) = (settings.clone(), dialer.clone());
                tasks.spawn(async move {
                    handle(&settings, &dialer, stream).await;
                    drop(permit);
                });
            }
        }
    }
    tasks.shutdown().await;
    // Tearing the engine down joins its thread.
    tokio::task::spawn_blocking(move || drop(dialer)).await.ok();
    log(&settings, LogLevel::Info, "event=client_stopped");
    Ok(())
}

async fn handle(settings: &Settings, dialer: &Dialer, mut stream: TcpStream) {
    stream.set_nodelay(true).ok();
    let request = match tokio::time::timeout(
        settings.local_handshake_timeout,
        local::negotiate(&mut stream),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(reason)) => {
            return log(
                settings,
                LogLevel::Debug,
                &format!("event=local_error reason={reason:?}"),
            );
        }
        Err(_) => {
            return log(
                settings,
                LogLevel::Debug,
                "event=local_error reason=timeout",
            );
        }
    };
    match dialer.open(&request.authority).await {
        Ok(remote) => {
            let transport = remote.transport();
            local::succeed(&mut stream, request.protocol).await;
            log(
                settings,
                LogLevel::Debug,
                &format!(
                    "event=tunnel_open transport={transport} target={}",
                    request.authority
                ),
            );
            if let Err(reason) = remote.relay(stream).await {
                log(
                    settings,
                    LogLevel::Debug,
                    &format!("event=tunnel_reset transport={transport} reason={reason:?}"),
                );
            }
        }
        Err(error) => {
            local::fail(&mut stream, request.protocol, &error).await;
            // Targets are private browsing data: only logged at debug level.
            log(
                settings,
                LogLevel::Info,
                &format!("event=tunnel_failed reason={error}"),
            );
            log(
                settings,
                LogLevel::Debug,
                &format!("event=tunnel_failed target={}", request.authority),
            );
        }
    }
}
