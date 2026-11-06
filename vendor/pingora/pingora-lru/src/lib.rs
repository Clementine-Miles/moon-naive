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

//! An implementation of an LRU that focuses on memory efficiency, concurrency and persistence
//!
//! Features
//! - keys can have different sizes
//! - LRUs are sharded to avoid global locks.
//! - Memory layout and usage are optimized: small and no memory fragmentation

pub mod async_lru;
pub mod linked_list;
pub mod persistence;

use linked_list::LinkedListIter;

/// The old lock-based code uses `LinkedList<u64>`.
type LinkedList = linked_list::LinkedList<u64>;

use hashbrown::HashMap;
use parking_lot::RwLock;
use rand::Rng;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The LRU with `N` shards
pub struct Lru<T, const N: usize> {
    units: [RwLock<LruUnit<T>>; N],
    /// Lock-free `Relaxed` shadow of each shard's item count, backing
    /// [`Lru::shard_len`] and the P2C selection in [`Lru::evict_to_limit`].
    /// Maintained alongside [`Lru::len`] at every count-mutating site.
    shard_lens: [AtomicUsize; N],
    weight: AtomicUsize,
    weight_limit: AtomicUsize,
    len_watermark: Option<usize>,
    len: AtomicUsize,
    evicted_weight: AtomicUsize,
    evicted_len: AtomicUsize,
}

impl<T, const N: usize> Lru<T, N> {
    /// Create an [Lru] with the given weight limit and predicted capacity.
    ///
    /// The capacity is per shard (for simplicity). So the total capacity = capacity * N
    pub fn with_capacity(weight_limit: usize, capacity: usize) -> Self {
        Self::with_capacity_and_watermark(weight_limit, capacity, None)
    }

    /// Create an [Lru] with the given weight limit, predicted capacity and optional watermark
    ///
    /// The capacity is per shard (for simplicity). So the total capacity = capacity * N
    ///
    /// The watermark indicates at what count we should begin evicting and acts as a limit
    /// on the total number of allowed items.
    pub fn with_capacity_and_watermark(
        weight_limit: usize,
        capacity: usize,
        len_watermark: Option<usize>,
    ) -> Self {
        // use the unsafe code from ArrayVec just to init the array
        let mut units = arrayvec::ArrayVec::<_, N>::new();
        let mut shard_lens = arrayvec::ArrayVec::<_, N>::new();
        for _ in 0..N {
            units.push(RwLock::new(LruUnit::with_capacity(capacity)));
            shard_lens.push(AtomicUsize::new(0));
        }
        Lru {
            units: units.into_inner().map_err(|_| "").unwrap(),
            shard_lens: shard_lens
                .into_inner()
                .expect("shard_lens ArrayVec filled with exactly N elements"),
            weight: AtomicUsize::new(0),
            weight_limit: AtomicUsize::new(weight_limit),
            len_watermark,
            len: AtomicUsize::new(0),
            evicted_weight: AtomicUsize::new(0),
            evicted_len: AtomicUsize::new(0),
        }
    }

    /// Return the current total weight limit.
    pub fn weight_limit(&self) -> usize {
        self.weight_limit.load(Ordering::Relaxed)
    }

    /// Set the total weight limit used by [`Self::evict_to_limit`].
    pub fn set_weight_limit(&self, weight_limit: usize) {
        self.weight_limit.store(weight_limit, Ordering::Relaxed);
    }

    /// Increment item-count bookkeeping for `shard`. Both atomics use
    /// `Relaxed`; called while holding the shard write lock so that
    /// `len` and `shard_lens[shard]` advance in lockstep.
    #[inline]
    fn incr_count(&self, shard: usize) {
        self.len.fetch_add(1, Ordering::Relaxed);
        self.shard_lens[shard].fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement item-count bookkeeping for `shard`. See
    /// [`Self::incr_count`].
    #[inline]
    fn decr_count(&self, shard: usize) {
        self.len.fetch_sub(1, Ordering::Relaxed);
        self.shard_lens[shard].fetch_sub(1, Ordering::Relaxed);
    }

    /// Admit the key value to the [Lru]
    ///
    /// Return the shard index which the asset is added to
    pub fn admit(&self, key: u64, data: T, weight: usize) -> usize {
        let shard = get_shard(key, N);
        let unit = &mut self.units[shard].write();

        // Make sure weight is positive otherwise eviction won't work
        // TODO: Probably should use NonZeroUsize instead
        let weight = weight.max(1);

        let old_weight = unit.admit(key, data, weight);
        if old_weight != weight {
            self.weight.fetch_add(weight, Ordering::Relaxed);
            if old_weight > 0 {
                self.weight.fetch_sub(old_weight, Ordering::Relaxed);
            } else {
                // Assume old_weight == 0 means a new item is admitted
                self.incr_count(shard);
            }
        }
        shard
    }

    /// Increment the weight associated with a given key, up to an optional max weight.
    ///
    /// If the key does not exist, it is admitted with data from `admit_data` and a weight
    /// equal to `delta`, capped to `max_weight` when provided, and floored to 1. The
    /// admission data is only constructed for missing keys; existing entries keep their
    /// stored data unchanged.
    ///
    /// If a `max_weight` is provided, the weight cannot grow beyond this max weight. If the
    /// current weight is higher than the max, the current weight is retained.
    ///
    /// Return the total new weight.
    pub fn increment_weight<F>(
        &self,
        key: u64,
        admit_data: F,
        delta: usize,
        max_weight: Option<usize>,
    ) -> usize
    where
        F: FnOnce() -> T,
    {
        let shard = get_shard(key, N);
        let unit = &mut self.units[shard].write();
        let (old_weight, new_weight, admitted) =
            unit.increment_weight(key, admit_data, delta, max_weight);
        debug_assert!(new_weight >= old_weight);
        self.weight
            .fetch_add(new_weight - old_weight, Ordering::Relaxed);
        if admitted {
            self.incr_count(shard);
        }
        new_weight
    }

    /// Update an existing entry while holding its shard write lock, or admit a
    /// new entry if it is not present.
    ///
    /// Existing entries are passed to `update` with their current data and
    /// weight. The returned weight is floored to `1`, the entry is promoted,
    /// and the global weight is adjusted while the shard mutation is still
    /// exclusive.
    ///
    /// Missing entries call `admit_data` to construct the data and initial
    /// weight, insert the entry at the head, and floor the weight to `1`.
    ///
    /// Returns the old weight when the entry existed, or `None` when the
    /// entry was newly admitted.
    pub fn update_or_admit<U, A>(&self, key: u64, update: U, admit_data: A) -> Option<usize>
    where
        U: FnOnce(&mut T, usize) -> usize,
        A: FnOnce() -> (T, usize),
    {
        let shard = get_shard(key, N);
        let unit = &mut self.units[shard].write();
        let (old_weight, new_weight) = unit.update_or_admit(key, update, admit_data);
        match old_weight {
            Some(old_weight) => {
                if old_weight != new_weight {
                    self.weight.fetch_add(new_weight, Ordering::Relaxed);
                    self.weight.fetch_sub(old_weight, Ordering::Relaxed);
                }
            }
            None => {
                self.weight.fetch_add(new_weight, Ordering::Relaxed);
                self.incr_count(shard);
            }
        }
        old_weight
    }

    /// Set the weight associated with an existing key without changing LRU order.
    ///
    /// Missing keys are left unchanged and return `None`. The weight is floored
    /// to `1`.
    ///
    /// Return the old weight if the key exists.
    pub fn set_weight(&self, key: u64, weight: usize) -> Option<usize> {
        let shard = get_shard(key, N);
        let unit = &mut self.units[shard].write();

        let weight = weight.max(1);
        let old_weight = unit.set_weight(key, weight)?;
        if old_weight != weight {
            self.weight.fetch_add(weight, Ordering::Relaxed);
            self.weight.fetch_sub(old_weight, Ordering::Relaxed);
        }
        Some(old_weight)
    }

    /// Promote the key to the head of the LRU
    ///
    /// Return `true` if the key exists.
    pub fn promote(&self, key: u64) -> bool {
        self.units[get_shard(key, N)].write().access(key)
    }

    /// Promote to the top n of the LRU
    ///
    /// This function acquires a read lock first to check if the key is already
    /// in the top `n` positions. If so, it returns early without a write lock.
    /// Otherwise it falls through to a write lock for the actual promotion.
    ///
    /// **Performance note**: this optimization only helps when `n` covers a
    /// significant fraction of the shard. At production scale (~100K+ items
    /// per shard), hot items are rarely in the top N positions, so the
    /// read-lock scan is usually wasted work that adds latency without
    /// reducing contention. Benchmarks (`cargo bench --bench bench_lru`)
    /// show that plain [`promote()`](Self::promote) is faster at scale.
    /// Consider using `promote()` directly unless profiling shows a clear
    /// benefit for your workload.
    ///
    /// Return false if the item doesn't exist
    pub fn promote_top_n(&self, key: u64, top: usize) -> bool {
        let unit = &self.units[get_shard(key, N)];
        if !unit.read().need_promote(key, top) {
            return true;
        }
        unit.write().access(key)
    }

    /// Evict at most one item from the given shard, identified by the
    /// hash-like `shard` seed (mapped into `0..N` via `% N`).
    ///
    /// Return the evicted asset and its size if there is anything to evict.
    pub fn evict_shard(&self, shard: u64) -> Option<(T, usize)> {
        self.evict_shard_at(get_shard(shard, N))
    }

    /// Evict at most one item from the shard at index `shard` (in `0..N`).
    /// Internal entry point that skips the `% N` round-trip in
    /// [`Self::evict_shard`].
    fn evict_shard_at(&self, shard: usize) -> Option<(T, usize)> {
        assert!(shard < N);
        let evicted = self.units[shard].write().evict();
        if let Some((_, weight)) = evicted.as_ref() {
            self.weight.fetch_sub(*weight, Ordering::Relaxed);
            self.decr_count(shard);
            self.evicted_weight.fetch_add(*weight, Ordering::Relaxed);
            self.evicted_len.fetch_add(1, Ordering::Relaxed);
        }
        evicted
    }

    /// Evict the [Lru] until the overall weight is below the limit (or the configured watermark).
    ///
    /// Return a list of evicted items.
    ///
    /// Each iteration selects the shard to evict from using the "power of two
    /// choices" strategy: two shards are picked uniformly at random and the
    /// one with more items is chosen (see
    /// <https://brooker.co.za/blog/2012/01/17/two-random.html>). This biases
    /// eviction toward longer shards and drives [`Self::shard_len`] toward a
    /// uniform distribution, which keeps per-shard serialization cost (e.g.
    /// `pingora_cache::eviction::lru::Manager::serialize_shard`) bounded.
    ///
    /// Selection is by item count, not weight, even when eviction is
    /// triggered by `weight_limit`. With heavily skewed item weights this
    /// may evict more items than a weight-biased policy to reach the same
    /// total weight — the tradeoff is intentional in favor of bounded
    /// per-shard serialization cost.
    ///
    /// O(1) per iteration in the common case. If the chosen shard is
    /// empty when we acquire its write lock (the Relaxed shadow may
    /// not always reflect actual emptiness, and P2C may tie-break to
    /// an empty shard when all shadow lengths are equal), we linearly
    /// probe successive shard indices until one yields an item or we
    /// wrap back to the starting shard — at which point every shard
    /// was observed empty and we exit. Bounded by at most N probes
    /// per outer iteration.
    pub fn evict_to_limit(&self) -> Vec<(T, usize)> {
        self.evict_to_limit_with_rng(&mut rand::thread_rng())
    }

    /// Internal entry point for [`Self::evict_to_limit`] that lets tests
    /// inject a seeded RNG for deterministic P2C selection.
    fn evict_to_limit_with_rng<R: Rng>(&self, rng: &mut R) -> Vec<(T, usize)> {
        let mut evicted = vec![];
        let mut initial_weight = self.weight();
        let mut initial_len = self.len();

        // Transient over-limit weight can persist until the next
        // admit/increment_weight call, which is acceptable because the
        // next admission will re-trigger eviction.
        let weight_limit = self.weight_limit();
        while (initial_weight > weight_limit && self.weight() > weight_limit)
            || self
                .len_watermark
                .is_some_and(|w| initial_len > w && self.len() > w)
        {
            // Power of two choices: pick the longer of two random shards.
            // N == 1 short-circuits the redundant second roll.
            let start = if N <= 1 {
                0
            } else {
                let a = rng.gen_range(0..N);
                let b = rng.gen_range(0..N);
                if self.shard_len(a) >= self.shard_len(b) {
                    a
                } else {
                    b
                }
            };
            // Try the chosen shard first; on a miss (empty or raced),
            // linearly probe successive indices. Wrapping back to
            // `start` means every shard was observed empty, so we exit.
            let mut shard = start;
            let evicted_one = loop {
                if let Some(item) = self.evict_shard_at(shard) {
                    break Some(item);
                }
                shard = (shard + 1) % N;
                if shard == start {
                    break None;
                }
            };
            match evicted_one {
                Some(i) => {
                    initial_weight = initial_weight.saturating_sub(i.1);
                    initial_len = initial_len.saturating_sub(1);
                    evicted.push(i);
                }
                None => break,
            }
        }
        evicted
    }

    /// Remove the given asset.
    pub fn remove(&self, key: u64) -> Option<(T, usize)> {
        let shard = get_shard(key, N);
        let removed = self.units[shard].write().remove(key);
        if let Some((_, weight)) = removed.as_ref() {
            self.weight.fetch_sub(*weight, Ordering::Relaxed);
            self.decr_count(shard);
        }
        removed
    }

    /// Insert the item to the tail of this LRU.
    ///
    /// Useful to recreate an LRU in most-to-least order
    pub fn insert_tail(&self, key: u64, data: T, weight: usize) -> bool {
        let shard = get_shard(key, N);
        if self.units[shard].write().insert_tail(key, data, weight) {
            self.weight.fetch_add(weight, Ordering::Relaxed);
            self.incr_count(shard);
            true
        } else {
            false
        }
    }

    /// Check existence of a key without changing the order in LRU.
    pub fn peek(&self, key: u64) -> bool {
        self.units[get_shard(key, N)].read().peek(key).is_some()
    }

    /// Check the weight of a key without changing the order in LRU.
    pub fn peek_weight(&self, key: u64) -> Option<usize> {
        self.units[get_shard(key, N)].read().peek_weight(key)
    }

    /// Peek at the least-recently-used item in the given shard without removing it.
    ///
    /// Returns a clone of the data and the weight, or `None` if the shard is empty
    /// or `shard >= N`.
    pub fn peek_lru(&self, shard: usize) -> Option<(T, usize)>
    where
        T: Clone,
    {
        self.units
            .get(shard)?
            .read()
            .peek_lru()
            .map(|(data, weight)| (data.clone(), weight))
    }

    /// Return the current total weight.
    ///
    /// Lock-free `Relaxed` load. Best-effort: not synchronized with
    /// concurrent admissions or evictions on other threads.
    pub fn weight(&self) -> usize {
        self.weight.load(Ordering::Relaxed)
    }

    /// Return the total weight of items evicted from this [Lru].
    pub fn evicted_weight(&self) -> usize {
        self.evicted_weight.load(Ordering::Relaxed)
    }

    /// Return the total count of items evicted from this [Lru].
    pub fn evicted_len(&self) -> usize {
        self.evicted_len.load(Ordering::Relaxed)
    }

    /// The number of items inside this [Lru].
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    /// Scan a shard with the given function F
    pub fn iter_for_each<F>(&self, shard: usize, f: F)
    where
        F: FnMut((&T, usize)),
    {
        assert!(shard < N);
        self.units[shard].read().iter().for_each(f);
    }

    /// Get the total number of shards
    pub const fn shards(&self) -> usize {
        N
    }

    /// Get the number of items inside a shard.
    ///
    /// Lock-free `Relaxed` load from a per-shard atomic shadow. Best-effort:
    /// there is no cross-thread ordering between this and [`Self::len`], and
    /// `Σ shard_len(i)` is not guaranteed to equal [`Self::len`] at any
    /// given instant. Suitable for eviction-balance heuristics and
    /// observability; not suitable for synchronization.
    pub fn shard_len(&self, shard: usize) -> usize {
        self.shard_lens[shard].load(Ordering::Relaxed)
    }

    /// Get the weight (total size) inside a shard
    pub fn shard_weight(&self, shard: usize) -> usize {
        self.units[shard].read().used_weight
    }

    /// Reserve capacity for `additional` more entries in `shard`, avoiding the
    /// reallocation/rehashing of incremental [`Self::insert_tail`] when bulk
    /// loading a shard of known size.
    pub fn reserve_shard(&self, shard: usize, additional: usize) {
        if let Some(unit) = self.units.get(shard) {
            unit.write().reserve(additional);
        }
    }




}

#[inline]
fn get_shard(key: u64, n_shards: usize) -> usize {
    (key % n_shards as u64) as usize
}

struct LruNode<T> {
    data: T,
    list_index: usize,
    weight: usize,
}

struct LruUnit<T> {
    lookup_table: HashMap<u64, Box<LruNode<T>>>,
    order: LinkedList,
    used_weight: usize,
}

impl<T> LruUnit<T> {
    fn with_capacity(capacity: usize) -> Self {
        LruUnit {
            lookup_table: HashMap::with_capacity(capacity),
            order: LinkedList::with_capacity(capacity),
            used_weight: 0,
        }
    }

    /// Peek data associated with key, if it exists.
    pub fn peek(&self, key: u64) -> Option<&T> {
        self.lookup_table.get(&key).map(|n| &n.data)
    }

    /// Peek weight associated with key, if it exists.
    pub fn peek_weight(&self, key: u64) -> Option<usize> {
        self.lookup_table.get(&key).map(|n| n.weight)
    }

    /// Admit into LRU, return old weight if there was any.
    pub fn admit(&mut self, key: u64, data: T, weight: usize) -> usize {
        if let Some(node) = self.lookup_table.get_mut(&key) {
            let old_weight = Self::adjust_weight(node, &mut self.used_weight, weight);
            node.data = data;
            self.order.promote(node.list_index);
            return old_weight;
        }
        let list_index = self.order.push_head(key);
        self.used_weight += weight;
        let node = Box::new(LruNode {
            data,
            list_index,
            weight,
        });
        self.lookup_table.insert(key, node);
        0
    }

    /// Increase the weight of a key, admitting it if needed.
    ///
    /// `admit_data` is only called when the key is not already tracked. Existing entries
    /// keep their stored data unchanged.
    ///
    /// If a `max_weight` is provided, the weight cannot grow beyond this max weight. If the
    /// current weight is higher than the max, the current weight is retained.
    ///
    /// Returns `(old_weight, new_weight, admitted)`, where `admitted` is true when a new
    /// entry was inserted.
    pub fn increment_weight<F>(
        &mut self,
        key: u64,
        admit_data: F,
        delta: usize,
        max_weight: Option<usize>,
    ) -> (usize, usize, bool)
    where
        F: FnOnce() -> T,
    {
        if let Some(node) = self.lookup_table.get_mut(&key) {
            let incremented = node.weight.saturating_add(delta);
            let new_weight =
                max_weight.map_or(incremented, |m| incremented.min(m).max(node.weight));
            let old_weight = Self::adjust_weight(node, &mut self.used_weight, new_weight);
            self.order.promote(node.list_index);
            return (old_weight, new_weight, false);
        }
        let weight = max_weight.map_or(delta, |m| delta.min(m)).max(1);
        let list_index = self.order.push_head(key);
        self.used_weight += weight;
        let node = Box::new(LruNode {
            data: admit_data(),
            list_index,
            weight,
        });
        self.lookup_table.insert(key, node);
        (0, weight, true)
    }

    /// Update an existing entry in place, or admit it if missing.
    ///
    /// Returns `(old_weight, new_weight)`, where `old_weight` is `None` when a
    /// new entry was inserted.
    pub fn update_or_admit<U, A>(
        &mut self,
        key: u64,
        update: U,
        admit_data: A,
    ) -> (Option<usize>, usize)
    where
        U: FnOnce(&mut T, usize) -> usize,
        A: FnOnce() -> (T, usize),
    {
        if let Some(node) = self.lookup_table.get_mut(&key) {
            let old_weight = node.weight;
            let new_weight = update(&mut node.data, old_weight).max(1);
            let old_weight = Self::adjust_weight(node, &mut self.used_weight, new_weight);
            self.order.promote(node.list_index);
            return (Some(old_weight), new_weight);
        }
        let (data, weight) = admit_data();
        let weight = weight.max(1);
        let list_index = self.order.push_head(key);
        self.used_weight += weight;
        let node = Box::new(LruNode {
            data,
            list_index,
            weight,
        });
        self.lookup_table.insert(key, node);
        (None, weight)
    }

    pub fn access(&mut self, key: u64) -> bool {
        if let Some(node) = self.lookup_table.get(&key) {
            self.order.promote(node.list_index);
            true
        } else {
            false
        }
    }

    /// Set the weight associated with an existing key without changing LRU order.
    pub fn set_weight(&mut self, key: u64, weight: usize) -> Option<usize> {
        let node = self.lookup_table.get_mut(&key)?;
        Some(Self::adjust_weight(node, &mut self.used_weight, weight))
    }

    // Check if a key is already in the top n most recently used nodes.
    // this is a heuristic to reduce write, which requires exclusive locks, for promotion,
    // especially on very populate nodes
    // NOTE: O(n) search here so limit needs to be small
    pub fn need_promote(&self, key: u64, limit: usize) -> bool {
        !self.order.exist_near_head(&key, limit)
    }

    // try to evict 1 node
    pub fn evict(&mut self) -> Option<(T, usize)> {
        self.order.pop_tail().map(|key| {
            // unwrap is safe because we always insert in both the hashtable and the list
            let node = self.lookup_table.remove(&key).unwrap();
            self.used_weight -= node.weight;
            (node.data, node.weight)
        })
    }

    /// Peek at the least-recently-used item without removing it.
    ///
    /// Returns a reference to the data and weight of the tail item, or `None`
    /// if empty.
    pub fn peek_lru(&self) -> Option<(&T, usize)> {
        self.order
            .tail()
            .and_then(|idx| self.order.peek(idx))
            .and_then(|key| self.lookup_table.get(key))
            .map(|node| (&node.data, node.weight))
    }

    // TODO: scan the tail up to K elements to decide which ones to evict

    pub fn remove(&mut self, key: u64) -> Option<(T, usize)> {
        self.lookup_table.remove(&key).map(|node| {
            let list_key = self.order.remove(node.list_index);
            assert_eq!(key, list_key);
            self.used_weight -= node.weight;
            (node.data, node.weight)
        })
    }

    /// Reserve capacity for `additional` more entries in this shard (lookup
    /// table + ordering list), avoiding reallocation/rehashing on bulk load.
    fn reserve(&mut self, additional: usize) {
        self.lookup_table.reserve(additional);
        self.order.reserve(additional);
    }

    pub fn insert_tail(&mut self, key: u64, data: T, weight: usize) -> bool {
        if self.lookup_table.contains_key(&key) {
            return false;
        }
        let list_index = self.order.push_tail(key);
        let node = Box::new(LruNode {
            data,
            list_index,
            weight,
        });
        self.lookup_table.insert(key, node);
        self.used_weight += weight;
        true
    }





    pub fn iter(&self) -> LruUnitIter<'_, T> {
        LruUnitIter {
            unit: self,
            iter: self.order.iter(),
        }
    }

    // Adjusts node weight to the new given weight.
    // Returns old weight.
    #[inline]
    fn adjust_weight(node: &mut LruNode<T>, used_weight: &mut usize, weight: usize) -> usize {
        let old_weight = node.weight;
        if weight != old_weight {
            *used_weight += weight;
            *used_weight -= old_weight;
            node.weight = weight;
        }
        old_weight
    }
}

struct LruUnitIter<'a, T> {
    unit: &'a LruUnit<T>,
    iter: LinkedListIter<'a, u64>,
}

impl<'a, T> Iterator for LruUnitIter<'a, T> {
    type Item = (&'a T, usize);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|key| {
            // safe because we always items in table and list are always 1:1
            let node = self.unit.lookup_table.get(key).unwrap();
            (&node.data, node.weight)
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<T> DoubleEndedIterator for LruUnitIter<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(|key| {
            // safe because we always items in table and list are always 1:1
            let node = self.unit.lookup_table.get(key).unwrap();
            (&node.data, node.weight)
        })
    }
}
