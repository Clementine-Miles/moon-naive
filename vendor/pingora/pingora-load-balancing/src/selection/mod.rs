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

//! Backend selection interfaces and algorithms

pub mod algorithms;
pub mod consistent;
pub mod weighted;

use super::Backend;
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use weighted::Weighted;

/// [BackendSelection] is the interface to implement backend selection mechanisms.
pub trait BackendSelection: Sized {
    /// The [BackendIter] returned from iter() below.
    type Iter;

    /// The configuration type constructing [BackendSelection]
    type Config: Send + Sync;

    /// Create a [BackendSelection] from a set of backends and the given configuration. The
    /// default implementation ignores the configuration and simply calls [Self::build]
    fn build_with_config(backends: &BTreeSet<Backend>, _config: &Self::Config) -> Self {
        Self::build(backends)
    }

    /// The function to create a [BackendSelection] implementation.
    fn build(backends: &BTreeSet<Backend>) -> Self;
    /// Select backends for a given key.
    ///
    /// An [BackendIter] should be returned. The first item in the iter is the first
    /// choice backend. The user should continue to iterate over it if the first backend
    /// cannot be used due to its health or other reasons.
    fn iter(self: &Arc<Self>, key: &[u8]) -> Self::Iter
    where
        Self::Iter: BackendIter;
}

/// An iterator to find the suitable backend
///
/// Similar to [Iterator] but allow self referencing.
pub trait BackendIter {
    /// Return `Some(&Backend)` when there are more backends left to choose from.
    fn next(&mut self) -> Option<&Backend>;
}

/// [SelectionAlgorithm] is the interface to implement selection algorithms.
///
/// All [std::hash::Hasher] + [Default] can be used directly as a selection algorithm.
pub trait SelectionAlgorithm {
    /// Create a new implementation
    fn new() -> Self;
    /// Return the next index of backend. The caller should perform modulo to get
    /// the valid index of the backend.
    fn next(&self, key: &[u8]) -> u64;
}

/// [FNV](https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function) hashing
/// on weighted backends
pub type FNVHash = Weighted<fnv::FnvHasher>;

/// Alias of [`FNVHash`] for backwards compatibility until the next breaking change
#[doc(hidden)]
pub type FVNHash = Weighted<fnv::FnvHasher>;
/// Random selection on weighted backends
pub type Random = Weighted<algorithms::Random>;
/// Round robin selection on weighted backends
pub type RoundRobin = Weighted<algorithms::RoundRobin>;
/// Consistent Ketama hashing on weighted backends
pub type Consistent = consistent::KetamaHashing;

// TODO: least conn

/// An iterator which wraps another iterator and yields unique items. It optionally takes a max
/// number of iterations if the wrapped iterator never returns.
pub struct UniqueIterator<I>
where
    I: BackendIter,
{
    iter: I,
    seen: HashSet<u64>,
    max_iterations: usize,
    steps: usize,
}

impl<I> UniqueIterator<I>
where
    I: BackendIter,
{
    /// Wrap a new iterator and specify the maximum number of times we want to iterate.
    pub fn new(iter: I, max_iterations: usize) -> Self {
        Self {
            iter,
            max_iterations,
            seen: HashSet::new(),
            steps: 0,
        }
    }

    pub fn get_next(&mut self) -> Option<Backend> {
        while let Some(item) = self.iter.next() {
            if self.steps >= self.max_iterations {
                return None;
            }
            self.steps += 1;

            let hash_key = item.hash_key();
            if !self.seen.contains(&hash_key) {
                self.seen.insert(hash_key);
                return Some(item.clone());
            }
        }

        None
    }
}
