//! One process, with ACME fsync and DNS control work on its own OS/runtime thread.
use crate::{
    Result,
    acme::{
        self,
        dns::DnsProvider,
        http::Http,
        manager::{Manager, Tick},
    },
    net::Prepared,
};
use moon_naive_core::config::Config;
use std::{sync::Arc, thread::JoinHandle, time::Duration};
use tokio::sync::{oneshot, watch};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Run,
    Once,
    Cleanup,
    Check,
}
pub(crate) struct Control {
    pub ready: watch::Receiver<bool>,
    done: oneshot::Receiver<Result<()>>,
    thread: Option<JoinHandle<()>>,
    finished: bool,
}
pub(crate) fn open(config: &Config) -> Result<Manager<Box<dyn DnsProvider>>> {
    if !config.acme.accept_terms {
        eprintln!("event=control_error reason=accept_terms_must_be_true");
        return Err("live ACME requires accept_terms = true".into());
    }
    let timeout = Duration::from_secs(config.acme.request_timeout_secs);
    let http = Http::new(config.acme.directory_ca_file.as_deref(), timeout)?;
    let mut dns_http = Http::new(None, timeout)?;
    dns_http.retry_after = http.retry_after.clone();
    let provider = acme::dns::provider_from_config(config, dns_http)?;
    Manager::open(config, provider, http)
}
impl Control {
    pub fn start(config: Arc<Config>, stop: watch::Receiver<bool>, mode: Mode) -> Result<Self> {
        Self::spawn(move || open(&config), stop, mode)
    }
    fn spawn<P, F>(factory: F, stop: watch::Receiver<bool>, mode: Mode) -> Result<Self>
    where
        P: DnsProvider + 'static,
        F: FnOnce() -> Result<Manager<P>> + Send + 'static,
    {
        let (ready_send, ready) = watch::channel(false);
        let (done_send, done) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("moon-naive-acme".into())
            .spawn(move || {
                let result = (|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        runtime.block_on(async move {
                            eprintln!("event=control_start phase=setup");
                            let mut manager = factory()?;
                            eprintln!(
                                "event=control_restored certificate_ready={} next_attempt={}",
                                manager.ready(),
                                manager.next_attempt()
                            );
                            ready_send.send_replace(manager.ready());
                            if mode == Mode::Check {
                                return Ok(());
                            }
                            let result = control_loop(&mut manager, stop, &ready_send, mode).await;
                            // Dropped operations leave their durable intent for restart recovery.
                            let cleanup =
                                tokio::time::timeout(Duration::from_secs(30), manager.cleanup())
                                    .await
                                    .map_err(|_| -> crate::Error {
                                        "DNS cleanup deadline; journal retained".into()
                                    })
                                    .and_then(|result| result);
                            result.and(cleanup)
                        })
                    }));
                    runtime.shutdown_timeout(Duration::from_secs(1));
                    result.unwrap_or_else(|_| {
                        Err("ACME control panicked; explicit state reconciliation required".into())
                    })
                })();
                let _ = done_send.send(result);
            })?;
        Ok(Self {
            ready,
            done,
            thread: Some(thread),
            finished: false,
        })
    }
    pub async fn wait(&mut self) -> Result<()> {
        let result = (&mut self.done).await;
        self.finished = true;
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| "ACME control thread panicked")?;
        }
        result.map_err(|_| "ACME control thread terminated")?
    }
}
async fn control_loop<P: DnsProvider>(
    manager: &mut Manager<P>,
    mut stop: watch::Receiver<bool>,
    ready: &watch::Sender<bool>,
    mode: Mode,
) -> Result<()> {
    if mode == Mode::Cleanup {
        return Ok(());
    }
    let mut health = acme::health::Worker::new(manager.health_path.clone())?;
    loop {
        if *stop.borrow() {
            break;
        }
        health.observation.next_attempt = manager.next_attempt();
        health.observation.phase = manager.last_failure_phase().into();
        health.pulse()?;
        let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
        let tick = {
            let tick = manager.tick();
            tokio::pin!(tick);
            loop {
                tokio::select! {biased;
                    _=wait_stop(&mut stop)=>return Ok(()),
                    result=&mut tick=>match result {Ok(tick)=>break tick,Err(error)=>{health.observation.reconciliation_required=true;return Err(error);}},
                    _=heartbeat.tick()=>health.pulse()?,
                }
            }
        };
        if tick == Tick::Installed {
            health.observation.last_success = acme::now();
        }
        health.observation.next_attempt = manager.next_attempt();
        health.observation.phase = manager.last_failure_phase().into();
        health.pulse()?;
        ready.send_replace(manager.ready());
        if tick != Tick::Idle {
            eprintln!(
                "event=acme_tick result={tick:?} certificate_ready={} next_attempt={} renew_at={} phase={}",
                manager.ready(),
                manager.next_attempt(),
                manager.renew_at(),
                manager.last_failure_phase()
            );
        }
        if mode == Mode::Once {
            return if tick == Tick::RetryScheduled || !manager.ready() {
                Err("certificate unavailable; retry state persisted".into())
            } else {
                Ok(())
            };
        }
        tokio::select! {_=wait_stop(&mut stop)=>break,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
    }
    Ok(())
}
pub(crate) async fn wait_stop(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow() || stop.changed().await.is_err() {
            return;
        }
    }
}
/// Issue the first certificate before binding, then keep renewing while serving.
pub async fn serve(config: Arc<Config>, shutdown: watch::Receiver<bool>) -> Result<()> {
    serve_with(config, shutdown, |config, stop| {
        Control::start(config, stop, Mode::Run)
    })
    .await
}
/// Embed the lifecycle with an explicit DNS implementation. The CLI only uses
/// provider_from_config; there is no test/provider-endpoint configuration switch.
pub async fn serve_with_provider<P: DnsProvider + 'static>(
    config: Arc<Config>,
    provider: P,
    http: Http,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    serve_with(config, shutdown, move |config, stop| {
        Control::spawn(
            move || Manager::open(&config, provider, http),
            stop,
            Mode::Run,
        )
    })
    .await
}
async fn serve_with<F>(
    config: Arc<Config>,
    mut shutdown: watch::Receiver<bool>,
    factory: F,
) -> Result<()>
where
    F: FnOnce(Arc<Config>, watch::Receiver<bool>) -> Result<Control>,
{
    if *shutdown.borrow() {
        return Ok(());
    }
    eprintln!(
        "event=server_start version={} phase=preflight",
        env!("CARGO_PKG_VERSION")
    );
    let prepared = tokio::select! {biased;_=wait_stop(&mut shutdown)=>return Ok(()),result=Prepared::load(config.clone())=>result?};
    let (stop, receive) = watch::channel(false);
    let mut control = factory(config, receive.clone())?;
    let mut ready = control.ready.clone();
    let mut serving = false;
    let result=async {
        if !*ready.borrow() {notify("STATUS=Waiting for the initial certificate")?;eprintln!("event=certificate_wait listeners_opened=false");}
        while !*ready.borrow() {
            tokio::select! {biased;
                _=wait_stop(&mut shutdown)=>return Ok(()),
                result=control.wait()=>{result?;return Err("ACME control stopped before startup".into());},
                result=ready.changed()=>{result.map_err(|_|"certificate readiness channel closed")?;}
            }
        }
        let network=tokio::select! {biased;
            _=wait_stop(&mut shutdown)=>return Ok(()),
            result=control.wait()=>{result?;return Err("ACME control stopped during startup".into());},
            result=prepared.bind()=>result?,
        };
        serving = true;
        eprintln!("event=server_ready h2={} h3={} tls=boringssl quic=quiche",network.tcp_addr()?,network.udp_addr()?);
        notify("READY=1\nSTATUS=Serving H2/H3; automatic certificate renewal active")?;
        let network=network.run(receive);
        tokio::pin!(network);
        tokio::select! {biased;
            _=wait_stop(&mut shutdown)=>{notify("STOPPING=1\nSTATUS=Draining connections")?;let _=stop.send(true);network.await},
            result=control.wait()=>{
                // Remote Problem bodies and URLs are not safe operational log fields.
                eprintln!("event=renewal_stopped reconcile_required=true failed={}", result.is_err());
                if let Err(error) = notify("STATUS=Network continues with TLS/ECH admission checks; renewal stopped, explicit reconciliation required") {
                    eprintln!("event=renewal_status_report_failed detail={error}");
                }
                // Never resume the failed Manager or replay unknown side effects.
                // Network admission continues to check inner and ECH expiry.
                tokio::select! {
                    _=wait_stop(&mut shutdown)=>{let _=stop.send(true);network.await},
                    result=&mut network=>result,
                }
            },
            result=&mut network=>{result?;Err("network drivers stopped unexpectedly".into())},
        }
    }.await;
    let _ = stop.send(true);
    let cleanup = if control.finished {
        Ok(())
    } else {
        tokio::time::timeout(Duration::from_secs(35), control.wait())
            .await
            .map_err(|_| -> crate::Error { "ACME shutdown deadline; journal retained".into() })
            .and_then(|result| result)
    };
    eprintln!(
        "event=server_stopped clean={}",
        result.is_ok() && cleanup.is_ok()
    );
    if serving {
        if cleanup.is_err() {
            eprintln!("event=renewal_cleanup_failed reconcile_required=true");
        }
        // The same post-startup renewal failure must have the same consequence
        // whether control.wait or the explicit network shutdown won the select.
        result
    } else {
        result.and(cleanup)
    }
}
fn notify(message: &str) -> Result<()> {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    notify_to(&path, message)
}
fn notify_to(path: &std::ffi::OsStr, message: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::{
        ffi::OsStrExt,
        net::{SocketAddr, UnixDatagram},
    };
    #[cfg(target_os = "linux")]
    let address = if path.as_bytes().first() == Some(&b'@') {
        SocketAddr::from_abstract_name(&path.as_bytes()[1..])?
    } else {
        SocketAddr::from_pathname(path)?
    };
    #[cfg(not(target_os = "linux"))]
    let address = SocketAddr::from_pathname(path)?;
    let socket = UnixDatagram::unbound()?;
    socket.set_nonblocking(true)?;
    socket.connect_addr(&address)?;
    socket.send(message.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn an_already_requested_shutdown_opens_no_files_or_listeners() {
        let config = Config::parse(include_str!("../config.example.toml")).unwrap();
        let (_send, receive) = watch::channel(true);
        serve(Arc::new(config), receive).await.unwrap();
    }
    #[test]
    fn readiness_uses_the_systemd_datagram_protocol() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify.sock");
        let receiver = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        notify_to(path.as_os_str(), "READY=1\nSTATUS=Serving H2/H3").unwrap();
        let mut buffer = [0; 128];
        let len = receiver.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..len], b"READY=1\nSTATUS=Serving H2/H3");
    }
}
