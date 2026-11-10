//! Bound system resolver jobs, including work that outlives a cancelled waiter.
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, OnceLock},
};
use tokio::sync::Semaphore;

pub(crate) async fn lookup(
    host: &str,
    port: u16,
) -> std::io::Result<std::vec::IntoIter<SocketAddr>> {
    static JOBS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    lookup_in(
        JOBS.get_or_init(|| Arc::new(Semaphore::new(32))).clone(),
        host,
        port,
    )
    .await
}
pub(crate) async fn lookup_control(
    host: &str,
    port: u16,
) -> std::io::Result<std::vec::IntoIter<SocketAddr>> {
    static JOBS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    lookup_in(
        JOBS.get_or_init(|| Arc::new(Semaphore::new(8))).clone(),
        host,
        port,
    )
    .await
}
async fn lookup_in(
    pool: Arc<Semaphore>,
    host: &str,
    port: u16,
) -> std::io::Result<std::vec::IntoIter<SocketAddr>> {
    #[cfg(test)]
    if std::env::var_os("ACME_LAB_DNS_LISTEN").is_none() {
        // Deterministic resolver fixture. Public candidates exercise the real
        // ACL; test-only dial injection maps them to controlled loopback peers.
        // No default unit/integration test sends DNS to an external resolver.
        let ip = host
            .parse::<std::net::IpAddr>()
            .ok()
            .or_else(|| match host {
                "localhost" | "proxy.example.test" => Some("127.0.0.1".parse().unwrap()),
                "example.com" | "example.org" => Some("93.184.216.34".parse().unwrap()),
                _ => None,
            });
        return ip
            .map(|ip| vec![SocketAddr::new(ip, port)].into_iter())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "fixture DNS negative answer")
            });
    }
    let host = host.to_owned();
    run_job(pool, move || {
        (host.as_str(), port)
            .to_socket_addrs()
            .map(|items| items.take(33).collect::<Vec<_>>().into_iter())
    })
    .await
}
async fn run_job<T: Send + 'static>(
    pool: Arc<Semaphore>,
    job: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> std::io::Result<T> {
    let permit = pool
        .try_acquire_owned()
        .map_err(|_| std::io::Error::other("resolver job budget exhausted"))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        job()
    })
    .await
    .map_err(std::io::Error::other)?
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cancelled_waiter_does_not_release_running_system_job() {
        let pool = Arc::new(Semaphore::new(1));
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let task = tokio::spawn(run_job(pool.clone(), move || {
            let _ = started.send(());
            wait.recv().unwrap();
            Ok(())
        }));
        ready.await.unwrap();
        task.abort();
        let _ = task.await;
        assert_eq!(pool.available_permits(), 0);
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while pool.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    #[test]
    #[ignore = "requires isolated namespace mapping the configured system nameserver to loopback"]
    fn actual_system_dns_cancellation_keeps_running_job_until_reply() {
        use std::{
            net::UdpSocket,
            sync::atomic::{AtomicBool, Ordering},
            time::{Duration, Instant},
        };
        let case = crate::acme::lab_support::Case::new("system-resolver-cancel");
        let address = std::env::var("ACME_LAB_DNS_LISTEN")
            .expect("run tools/acme-lab/run.py --only resolver");
        let _capture = case.capture(&[53]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let socket = UdpSocket::bind(&address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let release = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        struct Daemon {
            release: Arc<AtomicBool>,
            stop: Arc<AtomicBool>,
            join: Option<std::thread::JoinHandle<()>>,
        }
        impl Drop for Daemon {
            fn drop(&mut self) {
                self.release.store(true, Ordering::SeqCst);
                self.stop.store(true, Ordering::SeqCst);
                let _ = self.join.take().unwrap().join();
            }
        }
        let (ready, received) = std::sync::mpsc::channel();
        let allow = release.clone();
        let stopped = stop.clone();
        let log = case.clone();
        let daemon = Daemon {
            release: release.clone(),
            stop,
            join: Some(std::thread::spawn(move || {
                let mut pending = Vec::new();
                let mut bytes = [0; 4096];
                loop {
                    if let Ok((n, peer)) = socket.recv_from(&mut bytes) {
                        let _ = ready.send(());
                        pending.push((bytes[..n].to_vec(), peer));
                        log.event(
                            "system_dns_query",
                            serde_json::json!({"peer":peer.to_string(),"bytes":n}),
                        );
                    }
                    if allow.load(Ordering::SeqCst) {
                        for (mut reply, peer) in pending.drain(..) {
                            reply[2] = 0x81;
                            reply[3] = 0x83;
                            socket.send_to(&reply, peer).unwrap();
                        }
                    }
                    if stopped.load(Ordering::SeqCst) {
                        break;
                    }
                }
            })),
        };
        let pool = Arc::new(Semaphore::new(1));
        let jobs = pool.clone();
        let task =
            runtime.spawn(async move { lookup_in(jobs, "cancelled.acme-lab.invalid", 443).await });
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), async {
                while received.try_recv().is_err() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            task.abort();
            let _ = task.await;
        });
        assert_eq!(pool.available_permits(), 0);
        let start = Instant::now();
        runtime.shutdown_timeout(Duration::from_millis(100));
        case.event("resolver_runtime_shutdown",serde_json::json!({"elapsed_ms":start.elapsed().as_millis(),"permits_while_dns_pending":pool.available_permits(),"system_nameserver":address,"resolver_options":std::env::var("RES_OPTIONS").unwrap()}));
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(
            pool.available_permits(),
            0,
            "shutdown timeout does not stop an already running system resolver job"
        );
        release.store(true, Ordering::SeqCst);
        let until = Instant::now() + Duration::from_secs(5);
        while pool.available_permits() == 0 {
            assert!(
                Instant::now() < until,
                "system resolver did not return after NXDOMAIN"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        case.event(
            "resolver_completed",
            serde_json::json!({"permits":pool.available_permits()}),
        );
        drop(daemon);
    }
}
