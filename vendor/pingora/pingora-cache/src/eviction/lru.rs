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

//! A shared LRU cache manager

use super::{CacheEntryKey, CacheEntryKeyRef, EvictionManager};


use async_trait::async_trait;
use pingora_error::{ErrorType::*, OrErr, Result};
use pingora_lru::{persistence, Lru};
use serde::de::SeqAccess;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::time::SystemTime;

/// A shared LRU cache manager designed to manage a large volume of assets.
///
/// - Space optimized in-memory LRU (see [pingora_lru]).
/// - Instead of a single giant LRU, this struct shards the assets into `N` independent LRUs.
///
/// This allows [EvictionManager::save()] not to lock the entire cache manager while performing
/// serialization.
pub struct Manager<const N: usize>(Lru<CacheEntryKey, N>);

#[derive(Debug, Serialize, Deserialize)]
struct SerdeHelperNode(CacheEntryKey, usize);

impl<const N: usize> Manager<N> {
    /// Create a [Manager] with the given size limit and estimated per shard capacity.
    ///
    /// The `capacity` is for preallocating to avoid reallocation cost when the LRU grows.
    pub fn with_capacity(limit: usize, capacity: usize) -> Self {
        Manager(Lru::with_capacity(limit, capacity))
    }

    /// Create a [Manager] with an optional watermark in addition to weight limit.
    ///
    /// When `watermark` is set, the underlying LRU will also evict to keep total item count
    /// under or equal to that watermark.
    pub fn with_capacity_and_watermark(
        limit: usize,
        capacity: usize,
        watermark: Option<usize>,
    ) -> Self {
        Manager(Lru::with_capacity_and_watermark(limit, capacity, watermark))
    }

    /// Return the current total cache weight limit.
    pub fn weight_limit(&self) -> usize {
        self.0.weight_limit()
    }

    /// Set the total cache weight limit used by future eviction decisions.
    pub fn set_weight_limit(&self, limit: usize) {
        self.0.set_weight_limit(limit);
    }

    /// Get the number of shards
    pub fn shards(&self) -> usize {
        self.0.shards()
    }

    /// Get the weight (total size) of a specific shard
    pub fn shard_weight(&self, shard: usize) -> usize {
        self.0.shard_weight(shard)
    }

    /// Get the number of items in a specific shard. Best-effort
    /// lock-free read; see [`pingora_lru::Lru::shard_len`] for the
    /// consistency semantics.
    pub fn shard_len(&self, shard: usize) -> usize {
        self.0.shard_len(shard)
    }

    /// Get the shard index for a given cache entry
    ///
    /// This allows callers to know which shard was affected by an operation
    /// without acquiring any locks.
    pub fn get_shard_for_key(&self, key: &CacheEntryKey) -> usize {
        (u64key(key) % N as u64) as usize
    }

    /// Peek at the least-recently-used key in the given shard without evicting it.
    ///
    /// Returns the cache entry at the LRU tail of the shard, or `None` if empty.
    /// Useful for reporting the eviction frontier (the age of the next item
    /// that would be evicted).
    pub fn peek_lru(&self, shard: usize) -> Option<CacheEntryKey> {
        self.0.peek_lru(shard).map(|(key, _weight)| key)
    }

    /// Serialize the given shard
    pub fn serialize_shard(&self, shard: usize) -> Result<Vec<u8>> {
        use rmp_serde::encode::Serializer;
        use serde::ser::SerializeSeq;
        use serde::ser::Serializer as _;

        assert!(shard < N);

        // NOTE: This could use a lot of memory to buffer the serialized data in memory
        // NOTE: This for loop could lock the LRU for too long
        let mut nodes = Vec::with_capacity(self.0.shard_len(shard));
        self.0.iter_for_each(shard, |(node, size)| {
            nodes.push(SerdeHelperNode(node.clone(), size));
        });
        let mut ser = Serializer::new(vec![]);
        // Use the captured snapshot length for the MessagePack array header.
        // Re-reading shard_len() here can race with concurrent mutations and
        // emit a length that does not match the serialized nodes.
        let mut seq = ser
            .serialize_seq(Some(nodes.len()))
            .or_err(InternalError, "fail to serialize node")?;
        for node in nodes {
            seq.serialize_element(&node).unwrap(); // write to vec, safe
        }

        seq.end().or_err(InternalError, "when serializing LRU")?;
        Ok(ser.into_inner())
    }

    /// Deserialize a shard
    ///
    /// Shard number is not needed because the key itself will hash to the correct shard.
    pub fn deserialize_shard(&self, buf: &[u8]) -> Result<()> {
        use rmp_serde::decode::Deserializer;
        use serde::de::Deserializer as _;

        let mut de = Deserializer::new(buf);
        let visitor = InsertToManager { lru: self };
        de.deserialize_seq(visitor)
            .or_err(InternalError, "when deserializing LRU")?;
        Ok(())
    }

    /// Peek the weight associated with a cache entry without changing its LRU order.
    pub fn peek_weight(&self, item: &CacheEntryKey) -> Option<usize> {
        let key = u64key(item);
        self.0.peek_weight(key)
    }
}

struct InsertToManager<'a, const N: usize> {
    lru: &'a Manager<N>,
}

impl<'de, const N: usize> serde::de::Visitor<'de> for InsertToManager<'_, N> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("array of lru nodes")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(node) = seq.next_element::<SerdeHelperNode>()? {
            let key = u64key(&node.0);
            self.lru.0.insert_tail(key, node.0, node.1); // insert in the back
        }
        Ok(())
    }
}

#[inline]
fn u64key(key: &impl Hash) -> u64 {
    // note that std hash is not uniform, I'm not sure if ahash is also the case
    let mut hasher = ahash::AHasher::default();
    key.hash(&mut hasher);
    hasher.finish()
}

const FILE_NAME: &str = "lru.data";

#[async_trait]
impl<const N: usize> EvictionManager for Manager<N> {
    fn total_size(&self) -> usize {
        self.0.weight()
    }
    fn total_items(&self) -> usize {
        self.0.len()
    }
    fn evicted_size(&self) -> usize {
        self.0.evicted_weight()
    }
    fn evicted_items(&self) -> usize {
        self.0.evicted_len()
    }

    fn admit(
        &self,
        item: CacheEntryKey,
        size: usize,
        _fresh_until: SystemTime,
    ) -> Vec<CacheEntryKey> {
        let key = u64key(&item);
        self.0.admit(key, item, size);
        self.0
            .evict_to_limit()
            .into_iter()
            .map(|(key, _weight)| key)
            .collect()
    }

    fn increment_weight(
        &self,
        item: &CacheEntryKey,
        delta: usize,
        max_weight: Option<usize>,
    ) -> Vec<CacheEntryKey> {
        let key = u64key(item);
        self.0
            .increment_weight(key, || item.clone(), delta, max_weight);
        self.0
            .evict_to_limit()
            .into_iter()
            .map(|(key, _weight)| key)
            .collect()
    }

    fn remove(&self, item: CacheEntryKeyRef<'_>) {
        let key = u64key(&item);
        self.0.remove(key);
    }

    fn access(&self, item: &CacheEntryKey, size: usize, _fresh_until: SystemTime) -> bool {
        let key = u64key(item);
        if !self.0.promote(key) {
            self.0.admit(key, item.clone(), size);
            false
        } else {
            true
        }
    }

    fn peek(&self, item: &CacheEntryKey) -> bool {
        let key = u64key(item);
        self.0.peek(key)
    }

    async fn save(&self, dir_path: &str) -> Result<()> {
        persistence::save_shards(dir_path, FILE_NAME, N, |i| self.serialize_shard(i))
            .await
            .or_err(InternalError, "failed to save LRU")?;
        Ok(())
    }

    async fn load(&self, dir_path: &str) -> Result<()> {
        persistence::load_shards(dir_path, FILE_NAME, N, |_i, data| {
            self.deserialize_shard(data)
        })
        .await;
        Ok(())
    }
}
