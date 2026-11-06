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

use ahash::RandomState;
use std::borrow::Borrow;
use std::hash::Hash;
use std::marker::PhantomData;
use std::time::{Duration, Instant};

use tinyufo::TinyUfo;

mod read_through;
pub use read_through::{Lookup, MultiLookup, RTCache};

#[derive(Debug, PartialEq, Eq)]
/// [CacheStatus] indicates the response type for a query.
pub enum CacheStatus {
    /// The key was found in the cache
    Hit,
    /// The key was not found.
    Miss,
    /// The key was found but it was expired.
    Expired,
    /// The key was not initially found but was found after awaiting a lock.
    LockHit,
    /// The returned value was expired but still returned. The [Duration] is
    /// how long it has been since its expiration time.
    Stale(Duration),
}

impl CacheStatus {
    /// Return the string representation for [CacheStatus].
    pub fn as_str(&self) -> &str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Expired => "expired",
            Self::LockHit => "lock_hit",
            Self::Stale(_) => "stale",
        }
    }

    /// Returns whether this status represents a cache hit.
    pub fn is_hit(&self) -> bool {
        match self {
            CacheStatus::Hit | CacheStatus::LockHit | CacheStatus::Stale(_) => true,
            CacheStatus::Miss | CacheStatus::Expired => false,
        }
    }

    /// Returns the stale duration if any
    pub fn stale(&self) -> Option<Duration> {
        match self {
            CacheStatus::Stale(time) => Some(*time),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct Node<T: Clone> {
    pub value: T,
    expire_on: Option<Instant>,
}

impl<T: Clone> Node<T> {
    fn new(value: T, ttl: Option<Duration>) -> Self {
        let expire_on = match ttl {
            Some(t) => Instant::now().checked_add(t),
            None => None,
        };
        Node { value, expire_on }
    }

    fn will_expire_at(&self, time: &Instant) -> bool {
        self.stale_duration(time).is_some()
    }

    fn is_expired(&self) -> bool {
        self.will_expire_at(&Instant::now())
    }

    fn stale_duration(&self, time: &Instant) -> Option<Duration> {
        let expire_time = self.expire_on?;
        if &expire_time <= time {
            Some(time.duration_since(expire_time))
        } else {
            None
        }
    }
}

/// A high performant in-memory cache with S3-FIFO + TinyLFU
pub struct MemoryCache<K: Hash, T: Clone> {
    store: TinyUfo<u64, Node<T>>,
    _key_type: PhantomData<K>,
    pub(crate) hasher: RandomState,
}

impl<K: Hash, T: Clone + Send + Sync + 'static> MemoryCache<K, T> {
    /// Create a new [MemoryCache] with the given size.
    pub fn new(size: usize) -> Self {
        MemoryCache {
            store: TinyUfo::new(size, size),
            _key_type: PhantomData,
            hasher: RandomState::new(),
        }
    }

    /// Fetch the key and return its value in addition to a [CacheStatus].
    pub fn get<Q>(&self, key: &Q) -> (Option<T>, CacheStatus)
    where
        K: Borrow<Q>,
        Q: Hash + ?Sized,
    {
        let hashed_key = self.hasher.hash_one(key);

        if let Some(n) = self.store.get(&hashed_key) {
            if !n.is_expired() {
                (Some(n.value), CacheStatus::Hit)
            } else {
                (None, CacheStatus::Expired)
            }
        } else {
            (None, CacheStatus::Miss)
        }
    }

    /// Similar to [Self::get], fetch the key and return its value in addition to a
    /// [CacheStatus] but also return the value even if it is expired. When the
    /// value is expired, the [Duration] of how long it has been stale will
    /// also be returned.
    pub fn get_stale<Q>(&self, key: &Q) -> (Option<T>, CacheStatus)
    where
        K: Borrow<Q>,
        Q: Hash + ?Sized,
    {
        let hashed_key = self.hasher.hash_one(key);

        if let Some(n) = self.store.get(&hashed_key) {
            let stale_duration = n.stale_duration(&Instant::now());
            if let Some(stale_duration) = stale_duration {
                (Some(n.value), CacheStatus::Stale(stale_duration))
            } else {
                (Some(n.value), CacheStatus::Hit)
            }
        } else {
            (None, CacheStatus::Miss)
        }
    }

    /// Insert a key and value pair with an optional TTL into the cache.
    ///
    /// An item with zero TTL of zero will not be inserted.
    pub fn put<Q>(&self, key: &Q, value: T, ttl: Option<Duration>)
    where
        K: Borrow<Q>,
        Q: Hash + ?Sized,
    {
        if let Some(t) = ttl {
            if t.is_zero() {
                return;
            }
        }
        let hashed_key = self.hasher.hash_one(key);
        let node = Node::new(value, ttl);
        // weight is always 1 for now
        self.store.put(hashed_key, node, 1);
    }

    /// Remove a key from the cache if it exists.
    pub fn remove<Q>(&self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Hash + ?Sized,
    {
        let hashed_key = self.hasher.hash_one(key);
        self.store.remove(&hashed_key);
    }

    pub(crate) fn force_put(&self, key: &K, value: T, ttl: Option<Duration>) {
        if let Some(t) = ttl {
            if t.is_zero() {
                return;
            }
        }
        let hashed_key = self.hasher.hash_one(key);
        let node = Node::new(value, ttl);
        // weight is always 1 for now
        self.store.force_put(hashed_key, node, 1);
    }

    /// This is equivalent to [MemoryCache::get] but for an arbitrary amount of keys.
    pub fn multi_get<'a, I, Q>(&self, keys: I) -> Vec<(Option<T>, CacheStatus)>
    where
        I: Iterator<Item = &'a Q>,
        Q: Hash + ?Sized + 'a,
        K: Borrow<Q> + 'a,
    {
        let mut resp = Vec::with_capacity(keys.size_hint().0);
        for key in keys {
            resp.push(self.get(key));
        }
        resp
    }

    /// Same as [MemoryCache::multi_get] but returns the keys that are missing from the cache.
    pub fn multi_get_with_miss<'a, I, Q>(
        &self,
        keys: I,
    ) -> (Vec<(Option<T>, CacheStatus)>, Vec<&'a Q>)
    where
        I: Iterator<Item = &'a Q>,
        Q: Hash + ?Sized + 'a,
        K: Borrow<Q> + 'a,
    {
        let mut resp = Vec::with_capacity(keys.size_hint().0);
        let mut missed = Vec::with_capacity(keys.size_hint().0 / 2);
        for key in keys {
            let (lookup, cache_status) = self.get(key);
            if lookup.is_none() {
                missed.push(key);
            }
            resp.push((lookup, cache_status));
        }
        (resp, missed)
    }

    // TODO: evict expired first
}
