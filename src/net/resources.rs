//! Resource ownership: connection credit is never lent to an authenticated stream.
use moon_naive_core::{
    config::{Config, Limits},
    policy::{Budget, Permit},
};
use std::sync::Arc;
use tokio::sync::Semaphore;
pub(super) struct Resources {
    pub connections: Budget,
    pub tunnels: Budget,
    pub requests: Budget,
    pub waiting: Budget,
    pub receive: Arc<ByteBudget>,
    pub buffers: Arc<BufferPool>,
    users: Vec<Budget>,
    forward_users: Vec<Budget>,
    pub initializers: Arc<Semaphore>,
}
pub(crate) struct TunnelLease {
    _global: Permit,
    _user: Option<Permit>,
}
impl TunnelLease {
    pub(super) fn anonymous(budget: &Budget) -> Option<Self> {
        Some(Self {
            _global: budget.acquire()?,
            _user: None,
        })
    }
}
impl Resources {
    pub fn new(config: &Config, users: usize) -> super::Result<Self> {
        Ok(Self {
            initializers: Arc::new(Semaphore::new(config.limits.max_pending_requests)),
            forward_users: (0..users)
                .map(|_| Budget::new(config.proxy.forward.max_requests_per_user))
                .collect::<Result<_, _>>()?,
            connections: Budget::new(config.limits.max_connections)?,
            tunnels: Budget::new(config.limits.max_streams)?,
            requests: Budget::new(config.limits.max_streams.saturating_mul(2))?,
            waiting: Budget::new(config.limits.max_pending_requests)?,
            receive: ByteBudget::new(config.limits.max_total_receive_bytes),
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
    /// Derive endpoint-local ceilings without duplicating global/user credit.
    /// Sharing user counters intentionally permits devices on different IPs and
    /// ports while preserving the existing aggregate per-user safety ceiling.
    pub fn endpoint(&self, config: &Config, limits: &Limits) -> super::Result<Self> {
        Ok(Self {
            connections: self.connections.child(limits.max_connections)?,
            tunnels: self.tunnels.child(limits.max_streams)?,
            requests: self.requests.child(limits.max_streams.saturating_mul(2))?,
            waiting: self.waiting.child(limits.max_pending_requests)?,
            receive: ByteBudget::child(self.receive.clone(), limits.max_total_receive_bytes),
            buffers: BufferPool::child(self.buffers.clone(), limits.max_total_buffer_bytes),
            users: self
                .users
                .iter()
                .map(|user| user.child(limits.max_tunnels_per_user.min(limits.max_streams)))
                .collect::<Result<_, _>>()?,
            forward_users: self
                .forward_users
                .iter()
                .map(|user| {
                    user.child(
                        config
                            .proxy
                            .forward
                            .max_requests_per_user
                            .min(limits.max_streams),
                    )
                })
                .collect::<Result<_, _>>()?,
            initializers: self.initializers.clone(),
        })
    }
    /// Held from authentication through DNS, retries and response completion.
    pub fn forward(&self, user: usize) -> Option<TunnelLease> {
        let global = self.tunnels.acquire()?;
        let user = self.forward_users.get(user)?.acquire()?;
        Some(TunnelLease {
            _global: global,
            _user: Some(user),
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
    #[test]
    fn endpoint_stream_saturation_preserves_sibling_and_global_user_limits() {
        let mut config = Config::parse(include_str!("../../config.example.toml")).unwrap();
        config.limits.max_streams = 3;
        config.limits.max_tunnels_per_user = 2;
        let global = Resources::new(&config, 2).unwrap();
        let mut local = config.limits.clone();
        local.max_streams = 1;
        let a = global.endpoint(&config, &local).unwrap();
        let b = global.endpoint(&config, &local).unwrap();
        let first = a.tunnel(Some(0)).unwrap();
        assert!(a.tunnel(Some(1)).is_none());
        assert_eq!(global.tunnels.active(), 1);
        let second = b.tunnel(Some(0)).unwrap();
        assert_eq!(global.tunnels.active(), 2);
        // A third endpoint still cannot bypass the shared user's two slots.
        let c = global.endpoint(&config, &local).unwrap();
        assert!(c.tunnel(Some(0)).is_none());
        assert_eq!(c.tunnels.active(), 0);
        let third = c.tunnel(Some(1)).unwrap();
        assert_eq!(global.tunnels.active(), 3);
        drop((first, second, third));
        assert_eq!(global.tunnels.active(), 0);
    }
}

/// Byte credit is acquired from the endpoint and every ancestor, and is owned
/// for exactly the same lifetime at every level. Acquisition order is always
/// child-to-parent; there are no cycles or detached global reservations.
pub(crate) struct ByteBudget {
    semaphore: Arc<Semaphore>,
    parent: Option<Arc<ByteBudget>>,
    capacity: usize,
}
pub(crate) struct BytePermit {
    _permits: Vec<tokio::sync::OwnedSemaphorePermit>,
}
impl ByteBudget {
    fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(capacity)),
            parent: None,
            capacity,
        })
    }
    fn child(parent: Arc<Self>, capacity: usize) -> Arc<Self> {
        let capacity = capacity.min(parent.capacity);
        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(capacity)),
            parent: Some(parent),
            capacity,
        })
    }
    #[cfg(test)]
    pub fn available_permits(&self) -> usize {
        let local = self.semaphore.available_permits();
        self.parent
            .as_ref()
            .map_or(local, |parent| local.min(parent.available_permits()))
    }
    pub fn try_acquire_many_owned(
        self: Arc<Self>,
        count: u32,
    ) -> Result<BytePermit, tokio::sync::TryAcquireError> {
        let mut permits = Vec::with_capacity(2);
        let mut current = Some(self);
        while let Some(budget) = current {
            permits.push(budget.semaphore.clone().try_acquire_many_owned(count)?);
            current = budget.parent.clone();
        }
        Ok(BytePermit { _permits: permits })
    }
    pub async fn acquire_many_owned(
        self: Arc<Self>,
        count: u32,
    ) -> Result<BytePermit, tokio::sync::AcquireError> {
        let mut permits = Vec::with_capacity(2);
        let mut current = Some(self);
        while let Some(budget) = current {
            permits.push(budget.semaphore.clone().acquire_many_owned(count).await?);
            current = budget.parent.clone();
        }
        Ok(BytePermit { _permits: permits })
    }
}

/// Charges follow Bytes clones/slices even after a protocol library takes them.
/// Protocol receive buffers remain covered by the connection's credit lease.
pub(crate) struct BufferPool {
    capacity: usize,
    pub available: Arc<ByteBudget>,
    pub wake: Arc<tokio::sync::Notify>,
}
struct Charged {
    bytes: bytes::Bytes,
    permit: Option<BytePermit>,
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
        self.wake.notify_waiters();
        self.wake.notify_one();
    }
}
impl BufferPool {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            available: ByteBudget::new(capacity),
            wake: Arc::new(tokio::sync::Notify::new()),
        })
    }
    pub fn child(parent: Arc<Self>, capacity: usize) -> Arc<Self> {
        let capacity = capacity.min(parent.capacity);
        Arc::new(Self {
            capacity,
            available: ByteBudget::child(parent.available.clone(), capacity),
            // The shared wake reaches sibling QUIC drivers when global credit
            // is returned by another endpoint's last Bytes owner.
            wake: parent.wake.clone(),
        })
    }
    pub fn wrap(&self, bytes: bytes::Bytes, permit: BytePermit) -> bytes::Bytes {
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
    async fn child_buffer_credit_isolated_globally_bounded_and_retained_by_clones() {
        let global = BufferPool::new(16);
        let a = BufferPool::child(global.clone(), 8);
        let b = BufferPool::child(global.clone(), 16);
        let bytes = a
            .charge(bytes::Bytes::from_static(b"abcdefgh"))
            .await
            .unwrap();
        let alias = bytes.slice(1..2);
        assert_eq!(a.available.available_permits(), 0);
        assert_eq!(b.available.available_permits(), 8);
        assert!(a.available.clone().try_acquire_many_owned(1).is_err());
        let held = b.available.clone().try_acquire_many_owned(8).unwrap();
        assert!(b.available.clone().try_acquire_many_owned(1).is_err());
        drop(bytes);
        assert_eq!(global.available.available_permits(), 0);
        drop(alias);
        assert_eq!(global.available.available_permits(), 8);
        drop(held);
        assert_eq!(global.available.available_permits(), 16);
    }
    #[tokio::test]
    async fn cancelled_global_byte_wait_rolls_back_endpoint_credit() {
        let global = ByteBudget::new(8);
        let a = ByteBudget::child(global.clone(), 8);
        let b = ByteBudget::child(global.clone(), 8);
        let held = a.clone().try_acquire_many_owned(8).unwrap();
        let waiting = tokio::spawn(b.clone().acquire_many_owned(8));
        tokio::task::yield_now().await;
        assert_eq!(b.semaphore.available_permits(), 0);
        waiting.abort();
        assert!(matches!(waiting.await, Err(error) if error.is_cancelled()));
        assert_eq!(b.semaphore.available_permits(), 8);
        drop(held);
        assert_eq!(global.available_permits(), 8);
    }
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
