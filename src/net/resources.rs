//! Resource ownership: connection credit is never lent to an authenticated stream.
use moon_naive_core::{
    config::Config,
    policy::{Budget, Permit},
};
use std::sync::Arc;
use tokio::sync::Semaphore;
pub(super) struct Resources {
    pub connections: Budget,
    pub tunnels: Budget,
    pub requests: Budget,
    pub waiting: Budget,
    pub receive: Arc<Semaphore>,
    pub buffers: Arc<BufferPool>,
    users: Vec<Budget>,
}
pub(crate) struct TunnelLease {
    _global: Permit,
    _user: Option<Permit>,
}
impl Resources {
    pub fn new(config: &Config, users: usize) -> super::Result<Self> {
        Ok(Self {
            connections: Budget::new(config.limits.max_connections)?,
            tunnels: Budget::new(config.limits.max_streams)?,
            requests: Budget::new(config.limits.max_streams.saturating_mul(2))?,
            waiting: Budget::new(config.limits.max_pending_requests)?,
            receive: Arc::new(Semaphore::new(config.limits.max_total_receive_bytes)),
            buffers: BufferPool::new(config.limits.max_total_buffer_bytes),
            users: (0..users)
                .map(|_| {
                    Budget::new(
                        config
                            .limits
                            .max_tunnels_per_user
                            .min(config.limits.max_streams),
                    )
                })
                .collect::<Result<_, _>>()?,
        })
    }
    pub fn tunnel(&self, user: Option<usize>) -> Option<TunnelLease> {
        let global = self.tunnels.acquire()?;
        let user = match user {
            Some(index) => Some(self.users.get(index)?.acquire()?),
            None => None,
        };
        Some(TunnelLease {
            _global: global,
            _user: user,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn user_leases_rollback_partial_admission() {
        let mut config = Config::parse(include_str!("../../config.example.toml")).unwrap();
        config.limits.max_tunnels_per_user = 1;
        let ledger = Resources::new(&config, 2).unwrap();
        let a = ledger.tunnel(Some(0)).unwrap();
        assert!(ledger.tunnel(Some(0)).is_none());
        assert_eq!(ledger.tunnels.active(), 1);
        let b = ledger.tunnel(Some(1)).unwrap();
        drop(a);
        drop(b);
        assert_eq!(ledger.tunnels.active(), 0);
    }
}

/// Charges follow Bytes clones/slices even after a protocol library takes them.
/// Protocol receive buffers remain covered by the connection's credit lease.
pub(crate) struct BufferPool {
    capacity: usize,
    pub available: Arc<Semaphore>,
    pub wake: Arc<tokio::sync::Notify>,
}
struct Charged {
    bytes: bytes::Bytes,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    wake: Arc<tokio::sync::Notify>,
}
impl AsRef<[u8]> for Charged {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl Drop for Charged {
    fn drop(&mut self) {
        drop(std::mem::take(&mut self.bytes));
        drop(self.permit.take());
        self.wake.notify_one();
    }
}
impl BufferPool {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            available: Arc::new(Semaphore::new(capacity)),
            wake: Arc::new(tokio::sync::Notify::new()),
        })
    }
    pub fn wrap(
        &self,
        bytes: bytes::Bytes,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> bytes::Bytes {
        bytes::Bytes::from_owner(Charged {
            bytes,
            permit: Some(permit),
            wake: self.wake.clone(),
        })
    }
    pub async fn charge(&self, bytes: bytes::Bytes) -> super::Result<bytes::Bytes> {
        if bytes.len() > self.capacity {
            return Err("application buffer exceeds pool capacity".into());
        }
        if bytes.is_empty() {
            return Ok(bytes);
        }
        let permit = self
            .available
            .clone()
            .acquire_many_owned(u32::try_from(bytes.len())?)
            .await?;
        Ok(self.wrap(bytes, permit))
    }
}
#[cfg(test)]
mod buffer_tests {
    use super::*;
    #[tokio::test]
    async fn clones_and_slices_retain_charge_until_last_owner_drops() {
        let pool = BufferPool::new(16);
        let bytes = pool
            .charge(bytes::Bytes::from_static(b"abcdefgh"))
            .await
            .unwrap();
        let part = bytes.slice(2..4);
        drop(bytes);
        assert_eq!(pool.available.available_permits(), 8);
        drop(part);
        assert_eq!(pool.available.available_permits(), 16);
    }
}
