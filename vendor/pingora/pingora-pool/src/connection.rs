// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Generic connection pooling

use dashmap::DashMap;
use log::{debug, warn};
use parking_lot::Mutex;
use pingora_timeout::{sleep, timeout};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{oneshot, watch, Notify, OwnedMutexGuard};

use super::lru::Lru;
use futures::FutureExt;

type GroupKey = u64;
#[cfg(unix)]
type ID = i32;
#[cfg(windows)]
type ID = usize;

/// the metadata of a connection
#[derive(Clone, Debug)]
pub struct ConnectionMeta {
    /// The group key. All connections under the same key are considered the same for connection reuse.
    pub key: GroupKey,
    /// The unique ID of a connection.
    pub id: ID,
}

impl ConnectionMeta {
    /// Create a new [ConnectionMeta]
    pub fn new(key: GroupKey, id: ID) -> Self {
        ConnectionMeta { key, id }
    }
}

struct PoolConnection<S> {
    pub notify_use: oneshot::Sender<bool>,
    pub connection: S,
}

impl<S> PoolConnection<S> {
    pub fn new(notify_use: oneshot::Sender<bool>, connection: S) -> Self {
        PoolConnection {
            notify_use,
            connection,
        }
    }

    pub fn release(self) -> S {
        // notify the idle watcher to release the connection
        let _ = self.notify_use.send(true);
        // wait for the watcher to release
        self.connection
    }
}

use crossbeam_queue::ArrayQueue;

/// A pool of exchangeable items
pub struct PoolNode<T> {
    connections: Mutex<HashMap<ID, T>>,
    // a small lock free queue to avoid lock contention
    hot_queue: ArrayQueue<(ID, T)>,
    // to avoid race between 2 evictions on the queue
    hot_queue_remove_lock: Mutex<()>,
    // TODO: store the GroupKey to avoid hash collision?
}

// Keep the queue size small because eviction is O(n) in the queue
const HOT_QUEUE_SIZE: usize = 16;

impl<T> PoolNode<T> {
    /// Create a new [PoolNode]
    pub fn new() -> Self {
        PoolNode {
            connections: Mutex::new(HashMap::new()),
            hot_queue: ArrayQueue::new(HOT_QUEUE_SIZE),
            hot_queue_remove_lock: Mutex::new(()),
        }
    }

    /// Get any item from the pool
    pub fn get_any(&self) -> Option<(ID, T)> {
        let hot_conn = self.hot_queue.pop();
        if hot_conn.is_some() {
            return hot_conn;
        }
        let mut connections = self.connections.lock();
        // find one connection, any connection will do
        let id = match connections.iter().next() {
            Some((k, _)) => *k, // OK to copy i32
            None => return None,
        };
        // unwrap is safe since we just found it
        let connection = connections.remove(&id).unwrap();
        /* NOTE: we don't resize or drop empty connections hashmap
         * We may want to do it if they consume too much memory
         * maybe we should use trees to save memory */
        Some((id, connection))
        // connections.lock released here
    }

    /// Insert an item with the given unique ID into the pool
    pub fn insert(&self, id: ID, conn: T) {
        if let Err(node) = self.hot_queue.push((id, conn)) {
            // hot queue is full
            let mut connections = self.connections.lock();
            connections.insert(node.0, node.1); // TODO: check dup
        }
    }

    /// Returns `true` if the pool node contains no connections in either the hot queue
    /// or the overflow hash map.
    ///
    /// # Concurrency note
    ///
    /// This check is not atomic across the two internal stores (`hot_queue` and
    /// `connections`). Between checking one and the other, a concurrent `insert` or
    /// `get_any` could change the state. This is acceptable because callers use
    /// `is_empty` only as a hint to attempt cleanup, and always re-verify under
    /// an exclusive (write) lock before actually removing the node from the parent
    /// pool HashMap. A false-negative simply defers cleanup to the next opportunity;
    /// a false-positive is largely mitigated by the re-check (see
    /// [`ConnectionPool::try_remove_empty_node`] for residual race-window analysis).
    pub fn is_empty(&self) -> bool {
        // Check the lock-free queue first (cheap atomic load) to avoid acquiring
        // the mutex in the common case where connections are present.
        self.hot_queue.is_empty() && self.connections.lock().is_empty()
    }

    // This function acquires 2 locks and iterates over the entire hot queue.
    // But it should be fine because remove() rarely happens on a busy PoolNode.
    /// Remove the item associated with the id from the pool. The item is returned
    /// if it is found and removed.
    pub fn remove(&self, id: ID) -> Option<T> {
        // check the table first as least recent used ones are likely there
        let removed = self.connections.lock().remove(&id);
        if removed.is_some() {
            return removed;
        } // lock drops here

        let _queue_lock = self.hot_queue_remove_lock.lock();
        // check the hot queue, note that the queue can be accessed in parallel by insert and get
        let max_len = self.hot_queue.len();
        for _ in 0..max_len {
            if let Some((conn_id, conn)) = self.hot_queue.pop() {
                if conn_id == id {
                    // this is the item, it is already popped
                    return Some(conn);
                } else {
                    // not this item, put back to hot queue, but it could also be full
                    self.insert(conn_id, conn);
                }
            } else {
                // other threads grab all the connections
                return None;
            }
        }
        None
        // _queue_lock drops here
    }
}

type Pool<S> = PoolNode<PoolConnection<S>>;

/// Connection pool
///
/// [ConnectionPool] holds reusable connections. A reusable connection is released to this pool to
/// be picked up by another user/request.
pub struct ConnectionPool<S> {
    // Concurrent per-key pool index; each value handles per-key connection storage.
    pools: DashMap<GroupKey, Arc<Pool<S>>>,
    lru: Lru<ID, ConnectionMeta>,
}

impl<S> ConnectionPool<S> {
    /// Create a new [ConnectionPool] with a global size limit.
    ///
    /// When a connection is released to this pool and total occupancy is at
    /// or above `size`, the least recently used connection is dropped.
    pub fn new(size: usize) -> Self {
        ConnectionPool {
            pools: DashMap::with_capacity(size),
            lru: Lru::new(size),
        }
    }

    /// Insert a connection under `key` while the DashMap entry guard is held.
    ///
    /// Holding the guard through [`PoolNode::insert`] prevents empty-node cleanup
    /// from removing the map entry between looking it up and repopulating it.
    fn insert_pool_connection(&self, key: GroupKey, id: ID, connection: PoolConnection<S>) {
        let pool_node = self
            .pools
            .entry(key)
            .or_insert_with(|| Arc::new(PoolNode::new()));
        pool_node.insert(id, connection);
    }

    /// Attempt to remove an empty [`PoolNode`] entry from the pool `HashMap`.
    ///
    /// This prevents unbounded growth of the pool map when many unique group keys
    /// are seen over the lifetime of the pool (e.g. connecting to many distinct
    /// upstreams). Without this cleanup, each unique `GroupKey` leaves an
    /// empty `PoolNode` behind even after all its connections are gone.
    ///
    /// The method acquires the pool write lock and re-checks emptiness to avoid
    /// removing a node that was concurrently repopulated between the caller's
    /// initial `is_empty()` hint and this write-lock acquisition.
    ///
    /// Insertions go through [`Self::insert_pool_connection`], which holds the
    /// DashMap entry guard until the connection is in the node. That prevents
    /// this cleanup from removing a node between an inserter's entry lookup and
    /// its [`PoolNode::insert`] call.
    fn try_remove_empty_node(&self, key: GroupKey) {
        if let Some(node) = self.pools.get(&key) {
            if node.is_empty() {
                // Release the DashMap read guard before remove_if() acquires
                // mutable access to the same shard. Re-check emptiness in the
                // predicate because another thread may repopulate the node in
                // between dropping this guard and attempting removal.
                drop(node);
                self.pools.remove_if(&key, |_, node| node.is_empty());
            }
        }
    }

    // only remove from the pool because lru already removed it
    fn pop_evicted(&self, meta: &ConnectionMeta) {
        let pool_node = match self.pools.get(&meta.key) {
            Some(v) => v.value().clone(),
            None => {
                warn!("Fail to get pool node for {meta:?}");
                return;
            } // nothing to pop, should return error?
        };

        pool_node.remove(meta.id);
        debug!("evict fd: {} from key {}", meta.id, meta.key);

        // Clean up the PoolNode entry if it is now empty, to prevent unbounded
        // growth of the pool HashMap.
        // The is_empty() check avoids acquiring the write lock in the common case
        // where other connections still exist under this key.
        if pool_node.is_empty() {
            self.try_remove_empty_node(meta.key);
        }
    }

    pub fn pop_closed(&self, meta: &ConnectionMeta) {
        // NOTE: which of these should be done first?
        self.pop_evicted(meta);
        self.lru.pop(&meta.id);
    }

    /// Get a connection from this pool under the same group key
    pub fn get(&self, key: &GroupKey) -> Option<S> {
        let pool_node = self.pools.get(key)?.value().clone();

        if let Some((id, connection)) = pool_node.get_any() {
            self.lru.pop(&id); // the notified is not needed

            // Clean up the now-empty node. This path is important because when a
            // connection is retrieved (not evicted), the idle_poll/idle_timeout
            // tasks exit via the watch_use channel and never call pop_closed(),
            // so pop_evicted's cleanup would never run for this key.
            if pool_node.is_empty() {
                self.try_remove_empty_node(*key);
            }

            Some(connection.release())
        } else {
            // The node exists but has no connections. Clean it up.
            self.try_remove_empty_node(*key);
            None
        }
    }

    /// Release a connection to this pool for reuse
    ///
    /// - The returned [`Arc<Notify>`] will notify any listener when the connection is evicted from the pool.
    /// - The returned [`oneshot::Receiver<bool>`] will notify when the connection is being picked up by [Self::get()].
    pub fn put(
        &self,
        meta: &ConnectionMeta,
        connection: S,
    ) -> (Arc<Notify>, oneshot::Receiver<bool>) {
        let (notify_close, evicted) = self.lru.add(meta.id, meta.clone());
        for meta in &evicted {
            self.pop_evicted(meta);
        }
        let (notify_use, watch_use) = oneshot::channel();
        let connection = PoolConnection::new(notify_use, connection);
        self.insert_pool_connection(meta.key, meta.id, connection);
        (notify_close, watch_use)
    }

    /// Actively monitor the health of a connection that is already released to this pool
    ///
    /// When the connection breaks, or the optional `timeout` is reached this function will
    /// remove it from the pool and drop the connection.
    ///
    /// If the connection is reused via [Self::get()] or being evicted, this function will just exit.
    ///
    /// Returns `true` if the connection was evicted from the pool, and `false` otherwise.
    pub async fn idle_poll<Stream>(
        &self,
        connection: OwnedMutexGuard<Stream>,
        meta: &ConnectionMeta,
        timeout: Option<Duration>,
        notify_evicted: Arc<Notify>,
        watch_use: oneshot::Receiver<bool>,
    ) -> bool
    where
        Stream: AsyncRead + Unpin + Send,
    {
        // Reuse this same Notified future in the watch_use branch: notify_one()
        // may deliver the wakeup to an already-polled future, so creating a new
        // notified() future after watch_use resolves could miss the eviction.
        let evicted = notify_evicted.notified();
        tokio::pin!(evicted);

        let read_result = tokio::select! {
            biased;
            event = watch_use => {
                return match event {
                    Ok(_) => {
                        debug!("idle connection is being picked up");
                        false
                    }
                    // `watch_use` also resolves when the sender is dropped.
                    // During LRU eviction, pop_evicted() removes the
                    // PoolConnection, dropping the sender after notify_evicted
                    // has been signaled. Keep this biased branch first for the
                    // common reuse path, but confirm the eviction signal before
                    // classifying sender drop as eviction.
                    Err(_) => evicted.now_or_never().is_some(),
                };
            },
            _ = &mut evicted => {
                debug!("idle connection is being evicted");
                // TODO: gracefully close the connection?
                return true
            },
            read_result = read_with_timeout(connection , timeout) => read_result
        };

        match read_result {
            Ok(n) => {
                if n > 0 {
                    warn!("Data received on idle client connection, close it");
                } else {
                    debug!("Peer closed the idle connection or timeout");
                }
            }

            Err(e) => {
                debug!("error with the idle connection, close it {:?}", e);
            }
        };
        // connection terminated from either peer or timer
        self.pop_closed(meta);
        false
    }

    /// Passively wait to close the connection after the timeout
    ///
    /// If this connection is not being picked up or evicted before the timeout is reach, this
    /// function will remove it from the pool and close the connection.
    ///
    /// Returns `true` if the connection was evicted from the pool, and `false` otherwise.
    pub async fn idle_timeout(
        &self,
        meta: &ConnectionMeta,
        timeout: Option<Duration>,
        notify_evicted: Arc<Notify>,
        mut notify_closed: watch::Receiver<bool>,
        watch_use: oneshot::Receiver<bool>,
    ) -> bool {
        // Reuse this same Notified future in the watch_use branch: notify_one()
        // may deliver the wakeup to an already-polled future, so creating a new
        // notified() future after watch_use resolves could miss the eviction.
        let evicted = notify_evicted.notified();
        tokio::pin!(evicted);

        tokio::select! {
            biased;
            event = watch_use => {
                match event {
                    Ok(_) => {
                        debug!("idle connection is being picked up");
                        false
                    }
                    // `watch_use` also resolves when the sender is dropped.
                    // During LRU eviction, pop_evicted() removes the
                    // PoolConnection, dropping the sender after notify_evicted
                    // has been signaled. Keep this biased branch first for the
                    // common reuse path, but confirm the eviction signal before
                    // classifying sender drop as eviction.
                    Err(_) => evicted.now_or_never().is_some(),
                }
            },
            _ = &mut evicted => {
                debug!("idle connection is being evicted");
                // TODO: gracefully close the connection?
                true
            },
            _ = notify_closed.changed() => {
                // assume always changed from false to true
                debug!("idle connection is being closed");
                self.pop_closed(meta);
                false
            }
            // async expression is evaluated if timeout is None but it's never polled, set it to MAX
            _ = sleep(timeout.unwrap_or(Duration::MAX)), if timeout.is_some() => {
                debug!("idle connection is being evicted");
                self.pop_closed(meta);
                false
            }
        }
    }
}

async fn read_with_timeout<S>(
    mut connection: OwnedMutexGuard<S>,
    timeout_duration: Option<Duration>,
) -> io::Result<usize>
where
    S: AsyncRead + Unpin + Send,
{
    let mut buf = [0; 1];
    let read_event = connection.read(&mut buf[..]);
    match timeout_duration {
        Some(d) => match timeout(d, read_event).await {
            Ok(res) => res,
            Err(e) => {
                debug!("keepalive timeout {:?} reached, {:?}", d, e);
                Ok(0)
            }
        },
        _ => read_event.await,
    }
}
