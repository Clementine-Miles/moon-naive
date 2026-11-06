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

//! Cacheability Predictor

use crate::hashtable::ConcurrentLruCache;

pub type CustomReasonPredicate = fn(&'static str) -> bool;

/// Cacheability Predictor
///
/// Remembers previously uncacheable assets.
/// Allows bypassing cache / cache lock early based on historical precedent.
///
/// NOTE: to simply avoid caching requests with certain characteristics,
/// add checks in request_cache_filter to avoid enabling cache in the first place.
/// The predictor's bypass mechanism handles cases where the request _looks_ cacheable
/// but its previous responses suggest otherwise. The request _could_ be cacheable in the future.
pub struct Predictor<const N_SHARDS: usize> {
    /// Maps a remembered-uncacheable key to the [NoCacheReason] it was last marked with,
    /// so callers can tell a size-driven bypass apart from any other kind.
    uncacheable_keys: ConcurrentLruCache<NoCacheReason, N_SHARDS>,
    skip_custom_reasons_fn: Option<CustomReasonPredicate>,
}

use crate::{key::CacheHashKey, CacheKey, NoCacheReason};
use log::debug;

/// The cache predictor trait.
///
/// This trait allows user defined predictor to replace [Predictor].
pub trait CacheablePredictor {
    /// Return true if likely cacheable, false if likely not.
    fn cacheable_prediction(&self, key: &CacheKey) -> bool;

    /// Return the [NoCacheReason] this key is currently remembered as uncacheable for.
    ///
    /// Callers use this to report *why* a request bypassed the cache instead of inferring it.
    /// `None` means the key is not remembered as uncacheable, or the implementation does not
    /// track reasons, so callers must not assume anything about the previous response.
    ///
    /// The default implementation returns `None`.
    fn predicted_uncacheable_reason(&self, _key: &CacheKey) -> Option<NoCacheReason> {
        None
    }

    /// Mark cacheable to allow next request to cache.
    /// Returns false if the key was already marked cacheable.
    fn mark_cacheable(&self, key: &CacheKey) -> bool;

    /// Mark uncacheable to actively bypass cache on the next request.
    /// May skip marking on certain NoCacheReasons.
    /// Returns None if we skipped marking uncacheable.
    /// Returns Some(false) if the key was already marked uncacheable.
    fn mark_uncacheable(&self, key: &CacheKey, reason: NoCacheReason) -> Option<bool>;
}

impl<const N_SHARDS: usize> Predictor<N_SHARDS> {
    /// Create a new Predictor with `N_SHARDS * shard_capacity` total capacity for
    /// uncacheable cache keys.
    ///
    /// - `shard_capacity`: defines number of keys remembered as uncacheable per LRU shard.
    /// - `skip_custom_reasons_fn`: an optional predicate used in `mark_uncacheable`
    ///   that can customize which `Custom` `NoCacheReason`s ought to be remembered as uncacheable.
    ///   If the predicate returns true, then the predictor will skip remembering the current
    ///   cache key as uncacheable (and avoid bypassing cache on the next request).
    pub fn new(
        shard_capacity: usize,
        skip_custom_reasons_fn: Option<CustomReasonPredicate>,
    ) -> Predictor<N_SHARDS> {
        Predictor {
            uncacheable_keys: ConcurrentLruCache::<NoCacheReason, N_SHARDS>::new(shard_capacity),
            skip_custom_reasons_fn,
        }
    }
}

impl<const N_SHARDS: usize> CacheablePredictor for Predictor<N_SHARDS> {
    fn cacheable_prediction(&self, key: &CacheKey) -> bool {
        self.predicted_uncacheable_reason(key).is_none()
    }

    fn predicted_uncacheable_reason(&self, key: &CacheKey) -> Option<NoCacheReason> {
        // variance key is ignored because this check happens before cache lookup
        let hash = key.primary_bin();
        let key = u128::from_be_bytes(hash); // Endianness doesn't matter

        // Note: LRU updated in mark_* functions only,
        // as we assume the caller always updates the cacheability of the response later.
        // peek() reads without promoting, matching that.
        self.uncacheable_keys.read(key).peek(&key).copied()
    }

    fn mark_cacheable(&self, key: &CacheKey) -> bool {
        // variance key is ignored because cacheable_prediction() is called before cache lookup
        // where the variance key is unknown
        let hash = key.primary_bin();
        let key = u128::from_be_bytes(hash);

        let cache = self.uncacheable_keys.get(key);
        if !cache.read().contains(&key) {
            // not in uncacheable list, nothing to do
            return true;
        }

        let mut cache = cache.write();
        cache.pop(&key);
        debug!("bypassed request became cacheable");
        false
    }

    fn mark_uncacheable(&self, key: &CacheKey, reason: NoCacheReason) -> Option<bool> {
        // only mark as uncacheable for the future on certain reasons,
        // (e.g. InternalErrors)
        use NoCacheReason::*;
        match reason {
            // CacheLockGiveUp: the writer will set OriginNotCache (if applicable)
            // readers don't need to do it
            NeverEnabled
            | StorageError
            | InternalError
            | Deferred
            | CacheLockGiveUp
            | CacheLockTimeout
            | CacheLockRetryLimit
            | DeclinedToUpstream
            | UpstreamError
            | PredictedResponseTooLarge => {
                return None;
            }
            // Skip certain NoCacheReason::Custom according to user
            Custom(reason) if self.skip_custom_reasons_fn.is_some_and(|f| f(reason)) => {
                return None;
            }
            Custom(_) | OriginNotCache | ResponseTooLarge => { /* mark uncacheable for these only */
            }
        }

        // variance key is ignored because cacheable_prediction() is called before cache lookup
        // where the variance key is unknown
        let hash = key.primary_bin();
        let key = u128::from_be_bytes(hash);

        let mut cache = self.uncacheable_keys.get(key).write();
        // put() returns Some(old_reason) if the key existed, else None.
        // Re-marking overwrites, so the most recent reason is the one reported.
        let new_key = cache.put(key, reason).is_none();
        if new_key {
            debug!("request marked uncacheable");
        }
        Some(new_key)
    }
}
