//! Single-flight, bounded generation acquisition. Requests are never replayed.
use super::Result;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::{
    sync::{Mutex, Semaphore},
    time::{Instant, timeout},
};

pub(super) struct Generations<T> {
    state: Mutex<State<T>>,
    waiting: Semaphore,
    closed: Arc<AtomicBool>,
}
struct State<T> {
    current: Option<Arc<T>>,
    retry_at: Instant,
}
impl<T> Generations<T> {
    pub fn new(limit: usize) -> Self {
        Self {
            state: Mutex::new(State {
                current: None,
                retry_at: Instant::now(),
            }),
            waiting: Semaphore::new(limit),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn share_shutdown(&mut self, other: &Self) {
        self.closed = other.closed.clone();
    }
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.waiting.close();
    }
    pub async fn get<F, Fut>(&self, healthy: impl Fn(&T) -> bool, build: F) -> Result<Arc<T>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        // No unbounded queue of waiters behind the construction mutex.
        let _permit = self
            .waiting
            .try_acquire()
            .map_err(|_| "bridge admission unavailable")?;
        timeout(Duration::from_secs(3), async {
            let mut state = self.state.lock().await;
            if self.closed.load(Ordering::Acquire) {
                return Err("bridge stopped".into());
            }
            if let Some(current) = &state.current
                && healthy(current)
            {
                return Ok(current.clone());
            }
            // Dropping our reference does not replay or abort a live request.
            state.current = None;
            if Instant::now() < state.retry_at {
                return Err("bridge reconstruction cooling down".into());
            }
            // Set before awaiting: cancellation and construction failures also back off.
            state.retry_at = Instant::now() + Duration::from_secs(1);
            let next = Arc::new(build().await?);
            if self.closed.load(Ordering::Acquire) {
                return Err("bridge stopped".into());
            }
            state.current = Some(next.clone());
            Ok(next)
        })
        .await
        .map_err(|_| "bridge acquisition deadline")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    fn healthy(value: &AtomicBool) -> bool {
        value.load(Ordering::Relaxed)
    }
    #[tokio::test(start_paused = true)]
    async fn failed_construction_cools_down_then_recovers() {
        let slot = Generations::new(4);
        assert!(
            slot.get(healthy, || async { Err("injected".into()) })
                .await
                .is_err()
        );
        assert!(
            slot.get(healthy, || async { panic!("backoff bypassed") })
                .await
                .is_err()
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        let first = slot
            .get(healthy, || async { Ok(AtomicBool::new(true)) })
            .await
            .unwrap();
        first.store(false, Ordering::Relaxed);
        tokio::time::advance(Duration::from_secs(1)).await;
        let next = slot
            .get(healthy, || async { Ok(AtomicBool::new(true)) })
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&first, &next));
    }
    #[tokio::test(start_paused = true)]
    async fn concurrent_failure_has_one_replacement_and_bounded_retention() {
        let slot = Arc::new(Generations::new(32));
        let builds = Arc::new(AtomicUsize::new(0));
        for _ in 0..64 {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..16 {
                let slot = slot.clone();
                let builds = builds.clone();
                tasks.spawn(async move {
                    slot.get(healthy, || async {
                        builds.fetch_add(1, Ordering::Relaxed);
                        tokio::task::yield_now().await;
                        Ok(AtomicBool::new(true))
                    })
                    .await
                    .unwrap()
                });
            }
            let first = tasks.join_next().await.unwrap().unwrap();
            while let Some(next) = tasks.join_next().await {
                assert!(Arc::ptr_eq(&first, &next.unwrap()));
            }
            assert_eq!(Arc::strong_count(&first), 2);
            first.store(false, Ordering::Relaxed);
            let old = Arc::downgrade(&first);
            drop(first);
            tokio::time::advance(Duration::from_secs(1)).await;
            // Next iteration replaces the sole cached generation; there is no history list.
            let mut state = slot.state.lock().await;
            state.current = None;
            drop(state);
            assert!(old.upgrade().is_none());
        }
        assert_eq!(builds.load(Ordering::Relaxed), 64);
    }
    #[tokio::test(start_paused = true)]
    async fn cancelled_constructor_releases_permit_and_shutdown_prevents_rebuild() {
        let slot = Generations::new(1);
        let mut pending = Box::pin(slot.get(healthy, std::future::pending));
        tokio::select! { biased; _ = &mut pending => panic!("unexpected completion"), _ = tokio::task::yield_now() => {} }
        drop(pending);
        assert_eq!(slot.waiting.available_permits(), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        slot.get(healthy, || async { Ok(AtomicBool::new(true)) })
            .await
            .unwrap();
        slot.close();
        assert!(
            slot.get(healthy, || async { panic!("construction after shutdown") })
                .await
                .is_err()
        );
    }
    #[tokio::test(start_paused = true)]
    async fn construction_deadline_releases_admission() {
        let slot = Generations::new(1);
        assert!(slot.get(healthy, std::future::pending).await.is_err());
        assert_eq!(slot.waiting.available_permits(), 1);
        slot.get(healthy, || async { Ok(AtomicBool::new(true)) })
            .await
            .unwrap();
    }
}
