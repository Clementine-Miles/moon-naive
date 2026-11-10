//! Bounded LRU of per-user origins. Only bookkeeping runs under the async lock.
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, OnceCell};
type Key = (usize, String);
struct Entry<T> {
    key: Key,
    used: Instant,
    value: Arc<OnceCell<Arc<T>>>,
}
pub(super) struct Cache<T> {
    entries: Mutex<VecDeque<Entry<T>>>,
    capacity: usize,
    ttl: Duration,
}
impl<T> Default for Cache<T> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(VecDeque::new()),
            capacity: 128,
            ttl: Duration::from_secs(300),
        }
    }
}
impl<T> Cache<T> {
    pub async fn slot(&self, key: Key) -> Arc<OnceCell<Arc<T>>> {
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        entries.retain(|e| now.duration_since(e.used) < self.ttl);
        if let Some(index) = entries.iter().position(|e| e.key == key) {
            let mut entry = entries.remove(index).unwrap();
            entry.used = now;
            let value = entry.value.clone();
            entries.push_back(entry);
            return value;
        }
        let value = Arc::new(OnceCell::new());
        if entries.len() == self.capacity {
            entries.pop_front();
        }
        entries.push_back(Entry {
            key,
            used: now,
            value: value.clone(),
        });
        value
    }
    pub async fn clear(&self) {
        self.entries.lock().await.clear();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn concurrent_initialization_lru_eviction_and_active_ownership() {
        let cache = Cache {
            capacity: 2,
            ..Cache::default()
        };
        let a = cache.slot((0, "a".into())).await;
        let same = cache.slot((0, "a".into())).await;
        assert!(Arc::ptr_eq(&a, &same));
        let count = std::sync::atomic::AtomicUsize::new(0);
        let make = || async {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::task::yield_now().await;
            Arc::new(123)
        };
        let (x, y) = tokio::join!(a.get_or_init(make), same.get_or_init(make));
        assert!(Arc::ptr_eq(x, y));
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
        let active = x.clone();
        let weak = Arc::downgrade(x);
        drop(a);
        drop(same);
        cache.slot((1, "a".into())).await; // user is part of identity
        cache.slot((0, "a".into())).await; // refresh MRU
        cache.slot((2, "b".into())).await;
        assert!(weak.upgrade().is_some());
        for i in 0..500 {
            cache.slot((i, "churn".into())).await;
        }
        assert_eq!(cache.entries.lock().await.len(), 2);
        assert_eq!(*active, 123); // evicting must not abort an active exchange
        drop(active);
        assert!(weak.upgrade().is_none());
        cache.clear().await;
        assert!(cache.entries.lock().await.is_empty());
    }
    #[tokio::test]
    async fn failed_or_cancelled_initializer_can_retry_and_ttl_expires() {
        let cache = Cache::<usize> {
            ttl: Duration::ZERO,
            ..Cache::default()
        };
        let a = cache.slot((0, "a".into())).await;
        assert!(
            a.get_or_try_init(|| async { Err::<Arc<usize>, _>("failed") })
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(1),
                a.get_or_init(std::future::pending)
            )
            .await
            .is_err()
        );
        assert_eq!(**a.get_or_init(|| async { Arc::new(1) }).await, 1);
        let b = cache.slot((0, "a".into())).await;
        assert!(!Arc::ptr_eq(&a, &b));
    }
}
