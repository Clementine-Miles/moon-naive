//! Moon-naive first-party client.
//!
//! Accepts local SOCKS5 and HTTP CONNECT requests and carries each one over
//! its own authenticated mona (Rupin profile) CONNECT stream on HTTP/2 or
//! HTTP/3. Certificate verification is always on, TLS 1.3 is required, ECH
//! is mandatory when configured, and TCP Fast Open is never used.
pub mod config;
mod h2;
mod h3;
pub mod local;
mod tls;
pub mod tunnel;

pub use config::{Config, LogLevel, Settings, Transport};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task::JoinSet,
};
use tunnel::OpenError;

/// How long the H3-then-H2 policy avoids QUIC after it failed to connect.
const H3_COOL_DOWN: Duration = Duration::from_secs(300);

pub(crate) fn log(settings: &Settings, level: LogLevel, message: &str) {
    if level <= settings.log {
        eprintln!("{message}");
    }
}

enum Remote {
    H2(h2::Tunnel),
    H3(h3::Tunnel),
}
impl Remote {
    fn transport(&self) -> &'static str {
        match self {
            Self::H2(_) => "h2",
            Self::H3(_) => "h3",
        }
    }
    async fn relay(self, local: TcpStream) -> Result<(), String> {
        match self {
            Self::H2(tunnel) => tunnel.relay(local).await,
            Self::H3(tunnel) => tunnel.relay(local).await,
        }
    }
}

/// Opens tunnels on the configured transport(s).
pub struct Dialer {
    settings: Arc<Settings>,
    h2: Option<h2::Pool>,
    h3: Option<h3::Pool>,
    h3_cool_down: Mutex<Option<Instant>>,
}
impl Dialer {
    pub fn new(settings: Arc<Settings>) -> Self {
        let (h2, h3) = match settings.transport {
            Transport::H2 => (true, false),
            Transport::H3 => (false, true),
            Transport::H3ThenH2 => (true, true),
        };
        Self {
            h2: h2.then(|| h2::Pool::new(settings.clone())),
            h3: h3.then(|| h3::Pool::new(settings.clone())),
            settings,
            h3_cool_down: Mutex::new(None),
        }
    }
    async fn open(&self, authority: &str) -> Result<Remote, OpenError> {
        if let Some(h3) = &self.h3 {
            let cooling = !h3::expired(*self.h3_cool_down.lock().expect("cool-down lock"));
            if self.h2.is_none() || !cooling {
                match h3.open(authority).await {
                    Ok(tunnel) => return Ok(Remote::H3(tunnel)),
                    // Only a QUIC connection failure falls back. Server
                    // answers (status, confirmation) are final on any transport.
                    Err(OpenError::Connection(_) | OpenError::Timeout) if self.h2.is_some() => {
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
        match &self.h2 {
            Some(h2) => h2.open(authority).await.map(Remote::H2),
            None => Err(OpenError::Connection("no transport configured".into())),
        }
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
    if !address.ip().is_loopback() {
        log(
            &settings,
            LogLevel::Error,
            "event=warning reason=listener_not_loopback detail=the local proxy has no authentication",
        );
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
    let dialer = Arc::new(Dialer::new(settings.clone()));
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
