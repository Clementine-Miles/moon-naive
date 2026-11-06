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
}
