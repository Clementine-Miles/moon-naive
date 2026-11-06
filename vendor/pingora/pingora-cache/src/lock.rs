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

//! Cache lock

use crate::trace::{Span, Tag};
use crate::{hashtable::ConcurrentHashTable, key::CacheHashKey, CacheKey, NoCacheReason};

use http::Extensions;
use pingora_timeout::timeout;
use std::sync::Arc;
use std::time::Duration;

pub type CacheKeyLockImpl = dyn CacheKeyLock + Send + Sync;

pub trait CacheKeyLock {
    /// Try to lock a cache fetch
    ///
    /// If `stale_writer` is true, this fetch is to revalidate an asset already in cache.
    /// Else this fetch was a cache miss (i.e. not found via lookup, or force missed).
    ///
    /// Users should call after a cache miss before fetching the asset.
    /// The returned [Locked] will tell the caller either to fetch or wait.
    fn lock(&self, key: &CacheKey, stale_writer: bool) -> Locked;

    /// Release a lock for the given key
    ///
    /// When the write lock is dropped without being released, the read lock holders will consider
    /// it to be failed so that they will compete for the write lock again.
    fn release(&self, key: &CacheKey, permit: WritePermit, reason: LockStatus);

    /// Set tags on a trace span for the cache lock wait.
    fn trace_lock_wait(&self, span: &mut Span, _read_lock: &ReadLock, lock_status: LockStatus) {
        let tag_value: &'static str = lock_status.into();
        span.set_tag(|| Tag::new("status", tag_value));
    }

    /// Set a lock status for a custom `NoCacheReason`.
    fn custom_lock_status(&self, _custom_no_cache: &'static str) -> LockStatus {
        // treat custom no cache reasons as GiveUp by default
        // (like OriginNotCache)
        LockStatus::GiveUp
    }
}

const N_SHARDS: usize = 16;

/// The global cache locking manager
#[derive(Debug)]
pub struct CacheLock {
    lock_table: ConcurrentHashTable<LockStub, N_SHARDS>,
    // fixed lock timeout values for now
    age_timeout_default: Duration,
}

/// A struct representing locked cache access
#[derive(Debug)]
pub enum Locked {
    /// The writer is allowed to fetch the asset
    Write(WritePermit),
    /// The reader waits for the writer to fetch the asset
    Read(ReadLock),
}

impl Locked {
    /// Is this a write lock
    pub fn is_write(&self) -> bool {
        matches!(self, Self::Write(_))
    }
}

impl CacheLock {
    /// Create a new [CacheLock] with the given lock timeout
    ///
    /// Age timeout refers to how long a writer has been holding onto a particular lock, and wait
    /// timeout refers to how long a reader may hold onto any number of locks before giving up.
    /// When either timeout is reached, the read locks are automatically unlocked.
    pub fn new_boxed(age_timeout: Duration) -> Box<Self> {
        Box::new(CacheLock {
            lock_table: ConcurrentHashTable::new(),
            age_timeout_default: age_timeout,
        })
    }

    /// Create a new [CacheLock] with the given lock timeout
    ///
    /// Age timeout refers to how long a writer has been holding onto a particular lock, and wait
    /// timeout refers to how long a reader may hold onto any number of locks before giving up.
    /// When either timeout is reached, the read locks are automatically unlocked.
    pub fn new(age_timeout_default: Duration) -> Self {
        CacheLock {
            lock_table: ConcurrentHashTable::new(),
            age_timeout_default,
        }
    }
}

impl CacheKeyLock for CacheLock {
    fn lock(&self, key: &CacheKey, stale_writer: bool) -> Locked {
        let hash = key.combined_bin();
        let key = u128::from_be_bytes(hash); // endianness doesn't matter
        let table = self.lock_table.get(key);
        if let Some(lock) = table.read().get(&key) {
            // already has an ongoing request
            // If the lock status is dangling or timeout, the lock will _remain_ in the table
            // and readers should attempt to replace it.
            // In the case of writer timeout, any remaining readers that were waiting on THIS
            // LockCore should have (or are about to) timed out on their own.
            // Finding a Timeout status means that THIS writer's lock already expired, so future
            // requests ought to recreate the lock.
            if !matches!(
                lock.0.lock_status(),
                LockStatus::Dangling | LockStatus::AgeTimeout
            ) {
                return Locked::Read(lock.read_lock());
            }
            // Dangling: the previous writer quit without unlocking the lock. Requests should
            // compete for the write lock again.
        }

        let mut table = table.write();
        // check again in case another request already added it
        if let Some(lock) = table.get(&key) {
            if !matches!(
                lock.0.lock_status(),
                LockStatus::Dangling | LockStatus::AgeTimeout
            ) {
                return Locked::Read(lock.read_lock());
            }
        }
        let (permit, stub) =
            WritePermit::new(self.age_timeout_default, stale_writer, Extensions::new());
        table.insert(key, stub);
        Locked::Write(permit)
    }

    fn release(&self, key: &CacheKey, mut permit: WritePermit, reason: LockStatus) {
        let hash = key.combined_bin();
        let key = u128::from_be_bytes(hash); // endianness doesn't matter
        if permit.lock.lock_status() == LockStatus::AgeTimeout {
            // if lock age timed out, then readers are capable of
            // replacing the lock associated with this permit from the lock table
            // (see lock() implementation)
            // keep the lock status as Timeout accordingly when unlocking
            // (because we aren't removing it from the lock_table)
            permit.unlock(LockStatus::AgeTimeout);
        } else if let Some(_lock) = self.lock_table.write(key).remove(&key) {
            permit.unlock(reason);
        }
        // these situations above should capture all possible options,
        // else dangling cache lock may start
    }
}

use log::warn;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Instant;
use strum::{FromRepr, IntoStaticStr};
use tokio::sync::{oneshot, Semaphore};

/// Status which the read locks could possibly see.
#[derive(Debug, Copy, Clone, PartialEq, Eq, IntoStaticStr, FromRepr)]
#[repr(u8)]
pub enum LockStatus {
    /// Waiting for the writer to populate the asset
    Waiting = 0,
    /// The writer finishes, readers can start
    Done = 1,
    /// The writer encountered error, such as network issue. A new writer will be elected.
    TransientError = 2,
    /// The writer observed that no cache lock is needed (e.g., uncacheable), readers should start
    /// to fetch independently without a new writer
    GiveUp = 3,
    /// The write lock is dropped without being unlocked
    Dangling = 4,
    /// Reader has held onto cache locks for too long, give up
    WaitTimeout = 5,
    /// The lock is held for too long by the writer
    AgeTimeout = 6,
}

impl From<LockStatus> for u8 {
    fn from(l: LockStatus) -> u8 {
        match l {
            LockStatus::Waiting => 0,
            LockStatus::Done => 1,
            LockStatus::TransientError => 2,
            LockStatus::GiveUp => 3,
            LockStatus::Dangling => 4,
            LockStatus::WaitTimeout => 5,
            LockStatus::AgeTimeout => 6,
        }
    }
}

impl From<u8> for LockStatus {
    fn from(v: u8) -> Self {
        Self::from_repr(v).unwrap_or(Self::GiveUp)
    }
}

#[derive(Debug)]
pub struct LockCore {
    pub lock_start: Instant,
    pub age_timeout: Duration,
    pub(super) lock: Semaphore,
    // use u8 for Atomic enum
    lock_status: AtomicU8,
    stale_writer: bool,
    extensions: Extensions,
    /// What the writer has said about its fill, and who is waiting to hear it. One
    /// mutex for both, so nothing publishes in the gap between a reader checking and
    /// registering.
    fill: Mutex<FillState>,
    /// Lets `publish` skip the lock when replacing nothing with nothing. Written
    /// under `fill` so it cannot disagree with `published`; a stale `false` read only
    /// means a racing publication.
    published_any: AtomicBool,
}

#[derive(Debug, Default)]
struct FillState {
    /// Replaced, not accumulated: see [`WritePermit::publish`].
    published: Vec<u64>,
    /// Readers to be told about a later publication, in no meaningful order. Nobody
    /// removes themselves: a departure is a closed sender, swept by whoever next
    /// holds this lock.
    waiters: Vec<TokenWaiter>,
    /// Where the next sweep resumes. Sweeps examine a bounded window, so the cursor
    /// advances past survivors and wraps to stop entries hiding behind live ones.
    sweep_cursor: usize,
}

/// Entries examined per registration. The vector settles near
/// `live * BUDGET / (BUDGET - 1)`.
const WAITER_SWEEP_BUDGET: usize = 8;

#[derive(Debug)]
struct TokenWaiter {
    /// Shared with the reader's [`UnusableFills`], so registering is a refcount bump.
    unusable: Arc<[UnusableFill]>,
    /// Also the liveness signal: closed once the reader drops its receiver.
    tell: oneshot::Sender<UnusableFill>,
}

impl LockCore {
    pub fn new_arc(timeout: Duration, stale_writer: bool, extensions: Extensions) -> Arc<Self> {
        Arc::new(LockCore {
            lock: Semaphore::new(0),
            age_timeout: timeout,
            lock_start: Instant::now(),
            lock_status: AtomicU8::new(LockStatus::Waiting.into()),
            stale_writer,
            extensions,
            fill: Mutex::new(FillState::default()),
            published_any: AtomicBool::new(false),
        })
    }

    pub fn locked(&self) -> bool {
        self.lock.available_permits() == 0
    }

    /// Check what is published, and if none of it matters, register for later
    /// publications. One lock for both, or a publication lands in the gap.
    fn watch_fill(&self, unusable: &Arc<[UnusableFill]>) -> Watching {
        let mut fill = self.fill.lock();
        if let Some(matched) = first_match(&fill.published, unusable) {
            return Watching::AlreadyPublished(matched);
        }

        // On the lock this registration takes anyway, and bounded so one
        // registration cannot end up scanning every reader ahead of it.
        let mut budget = WAITER_SWEEP_BUDGET;
        while budget > 0 && !fill.waiters.is_empty() {
            if fill.sweep_cursor >= fill.waiters.len() {
                fill.sweep_cursor = 0;
            }
            let at = fill.sweep_cursor;
            if fill.waiters[at].tell.is_closed() {
                // Cursor stays: `swap_remove` moves an unexamined entry here.
                fill.waiters.swap_remove(at);
            } else {
                fill.sweep_cursor += 1;
            }
            budget -= 1;
        }

        let (tell, told) = oneshot::channel();
        fill.waiters.push(TokenWaiter {
            unusable: unusable.clone(),
            tell,
        });
        Watching::Registered(told)
    }

    /// Replace what is published and wake only the readers it matters to.
    fn publish(&self, tokens: &[u64]) {
        let woken = {
            let mut fill = self.fill.lock();
            fill.published.clear();
            fill.published.extend_from_slice(tokens);
            // Same lock as `published`, so racing publications cannot disagree.
            self.published_any
                .store(!tokens.is_empty(), Ordering::Relaxed);

            // One pass in place: departed readers dropped, matched readers taken out
            // to be told once the lock is released. An empty `woken` never allocates.
            let mut woken = Vec::new();
            let mut i = 0;
            while i < fill.waiters.len() {
                if fill.waiters[i].tell.is_closed() {
                    fill.waiters.swap_remove(i);
                    continue;
                }
                match first_match(tokens, &fill.waiters[i].unusable) {
                    Some(matched) => woken.push((fill.waiters.swap_remove(i).tell, matched)),
                    None => i += 1,
                }
            }
            woken
        };

        // Sent after releasing the lock.
        for (tell, matched) in woken {
            let _ = tell.send(matched);
        }
    }





    pub fn unlock(&self, reason: LockStatus) {
        assert!(
            reason != LockStatus::WaitTimeout,
            "WaitTimeout is not stored in LockCore"
        );
        self.lock_status.store(reason.into(), Ordering::SeqCst);
        // Any small positive number will do, 10 is used for RwLock as well.
        // No need to wake up all at once.
        self.lock.add_permits(10);
    }

    pub fn lock_status(&self) -> LockStatus {
        self.lock_status.load(Ordering::SeqCst).into()
    }

    /// Was this lock for a stale cache fetch writer?
    pub fn stale_writer(&self) -> bool {
        self.stale_writer
    }

    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

// all 3 structs below are just Arc<LockCore> with different interfaces

/// ReadLock: the requests who get it need to wait until it is released
#[derive(Debug)]
pub struct ReadLock(Arc<LockCore>);

/// One fill a reader cannot use, and why. Per token rather than per set, because a
/// key has one [`UnusableFills`] and a set-wide reason would attribute one part of
/// an application's give-up to another's cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnusableFill {
    /// Names a fill this reader cannot use. Opaque to the cache: whatever the
    /// writer and reader agree it means.
    pub token: u64,
    /// Why, as the [`crate::NoCacheReason::Custom`] label the cache disables with.
    /// Not a whole [`crate::NoCacheReason`]: the cause belongs to the application,
    /// and a caller could otherwise pass [`crate::NoCacheReason::NeverEnabled`],
    /// which [`crate::HttpCache::disable`] rejects.
    pub reason: &'static str,
}

/// The first published fill this reader cannot use, in the *reader's* order. Both
/// sides are a handful of tokens, so a plain scan.
fn first_match(published: &[u64], unusable: &[UnusableFill]) -> Option<UnusableFill> {
    unusable
        .iter()
        .find(|candidate| published.contains(&candidate.token))
        .copied()
}

/// What happened to *this* reader's cache-lock wait, and so what to do next.
///
/// Distinct from [`LockStatus`], the lock's *shared* state, which cannot carry a
/// payload. This is per-reader and never stored, which is what lets
/// [`Self::Abandoned`] carry its cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockWaitOutcome {
    /// The writer populated the asset. Look it up again.
    Done,
    /// The writer hit a transient error such as a network failure. Compete to be
    /// the new writer.
    TransientError,
    /// The write lock was dropped without being unlocked. A bug, but the request
    /// recovers by competing to be the new writer.
    Dangling,
    /// This reader has spent too long waiting on cache locks.
    WaitTimeout,
    /// The writer held the lock past its age. Compete for it rather than waiting,
    /// so a stuck writer cannot pin every reader to it.
    AgeTimeout,
    /// The writer found no lock was needed, for instance because the asset turned
    /// out to be uncacheable. Every reader proceeds uncached.
    GiveUp,
    /// This reader stopped waiting because the writer published a fill it cannot
    /// use. Local to this reader: the lock status is untouched and every other
    /// reader goes on coalescing behind the same writer.
    Abandoned {
        /// Why, from the matched [`UnusableFill`].
        reason: NoCacheReason,
        /// The published token it matched.
        token: u64,
    },
}

impl LockWaitOutcome {
    /// The nearest shared-status label, for tracing and metrics only.
    /// [`Self::Abandoned`] reports [`LockStatus::GiveUp`] because it shares that
    /// handling, but is never *stored* as such.
    pub fn lock_status(&self) -> LockStatus {
        match self {
            LockWaitOutcome::Done => LockStatus::Done,
            LockWaitOutcome::TransientError => LockStatus::TransientError,
            LockWaitOutcome::Dangling => LockStatus::Dangling,
            LockWaitOutcome::WaitTimeout => LockStatus::WaitTimeout,
            LockWaitOutcome::AgeTimeout => LockStatus::AgeTimeout,
            LockWaitOutcome::GiveUp | LockWaitOutcome::Abandoned { .. } => LockStatus::GiveUp,
        }
    }
}

/// The fills a reader cannot use. Put one in a [`crate::CacheKey`]'s extensions
/// and [`crate::HttpCache::cache_lock_wait`] honours it. Empty waits as normal.
///
/// One set and one publisher per key: extensions hold one value per type, and each
/// [`WritePermit::publish`] supersedes the last, so two features on a key must agree
/// on a combined set. Distinct token ranges stop tokens colliding but the space is
/// still flat and shared.
///
/// A match costs the reader its caching -- [`LockWaitOutcome::Abandoned`] means an
/// uncached fetch, where [`LockWaitOutcome::AgeTimeout`] recompetes and can still
/// cache. Name only fills that genuinely cannot be waited for.
#[derive(Debug, Clone)]
pub struct UnusableFills {
    pub(crate) fills: Arc<[UnusableFill]>,
}

impl UnusableFills {
    /// `fills` in precedence order: if several are published at once, the earliest
    /// here is reported back.
    pub fn new(fills: impl Into<Arc<[UnusableFill]>>) -> Self {
        UnusableFills {
            fills: fills.into(),
        }
    }

    /// The fills this reader cannot use, in precedence order.
    pub fn fills(&self) -> &[UnusableFill] {
        &self.fills
    }

    /// Which of `published` this reader cannot use, or `None` to keep waiting. The
    /// same function the wait uses, so a caller can check its token convention
    /// against the real rule rather than a copy.
    pub fn first_match(&self, published: &[u64]) -> Option<UnusableFill> {
        first_match(published, &self.fills)
    }
}

/// How a wait behind a writer ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The writer released the lock. Read [`ReadLock::lock_status`] for what it left
    /// behind.
    Released,
    /// The writer held the lock for longer than its age allows.
    AgeTimeout,
    /// The writer published a fill this reader cannot use.
    Abandoned(UnusableFill),
}

enum Watching {
    Registered(oneshot::Receiver<UnusableFill>),
    AlreadyPublished(UnusableFill),
}

impl ReadLock {
    /// Wait for the writer to release the lock
    pub async fn wait(&self) {
        self.wait_inner(None).await;
    }

    /// Wait for the writer to release the lock, unless it publishes a fill in
    /// `unusable` first — which lets a reader act on what the writer only learns
    /// after the reader committed to waiting.
    ///
    /// Giving up is local to this reader: the lock status is untouched and every
    /// other reader goes on coalescing. Tokens never published never match.
    pub async fn wait_unless_published(&self, unusable: &UnusableFills) -> WaitOutcome {
        self.wait_inner(Some(&unusable.fills)).await
    }

    async fn wait_inner(&self, unusable: Option<&Arc<[UnusableFill]>>) -> WaitOutcome {
        if !self.locked() {
            return WaitOutcome::Released;
        }

        // FIXME: for now it is the awkward responsibility of the ReadLock to set the
        // timeout status on the lock itself because the write permit cannot lock age
        // timeout on its own
        // TODO: need to be careful not to wake everyone up at the same time
        // (maybe not an issue because regular cache lock release behaves that way)
        //
        // Checked before any published token: an expired lock has to be replaced
        // whatever the writer said, and the caller can then recompete and still
        // cache. Also the only path that stores `AgeTimeout`.
        let Some(duration) = self.0.age_timeout.checked_sub(self.0.lock_start.elapsed()) else {
            // expiration has already occurred, store timeout status
            self.0
                .lock_status
                .store(LockStatus::AgeTimeout.into(), Ordering::SeqCst);
            return WaitOutcome::AgeTimeout;
        };

        // Naming nothing is the same as no interest: an empty set matches no token,
        // so registering would buy a wakeup nothing could deliver.
        let unusable = unusable.filter(|unusable| !unusable.is_empty());

        let told = match unusable {
            // The ordinary case: nothing named, so nothing to register or select on.
            None => {
                return Self::writer_done(&self.0, duration).await;
            }
            Some(unusable) => match self.0.watch_fill(unusable) {
                // Already true on arrival; no later publication would repeat it.
                Watching::AlreadyPublished(matched) => {
                    // The writer can release between the check above and here, and
                    // releasing does not clear what it published. Let the release
                    // win, as the `biased` select below does: the asset is in cache,
                    // so abandoning would fetch it uncached for nothing.
                    if !self.locked() {
                        return WaitOutcome::Released;
                    }
                    return WaitOutcome::Abandoned(matched);
                }
                Watching::Registered(told) => told,
            },
        };
        let told_to_stop = async {
            match told.await {
                Ok(matched) => WaitOutcome::Abandoned(matched),
                // Unreachable: the registry parts with a sender only by sending to
                // it, or by sweeping one already closed, which this cannot be while
                // this await holds its receiver. So this is a bug in this file
                // rather than a race a caller can provoke.
                //
                // `Released` rather than a panic in release builds: the caller then
                // takes the dangling-lock path, recompetes, and can still cache.
                Err(_) => {
                    debug_assert!(false, "fill waiter sender dropped while registered");
                    WaitOutcome::Released
                }
            }
        };

        // Biased so a writer that finishes at the same moment wins: completing the
        // wait normally is always at least as good as giving up on it.
        tokio::select! {
            biased;
            outcome = Self::writer_done(&self.0, duration) => outcome,
            outcome = told_to_stop => outcome,
        }
    }

    /// Wait out the writer, or the lock's remaining age.
    async fn writer_done(core: &LockCore, duration: Duration) -> WaitOutcome {
        match timeout(duration, core.lock.acquire()).await {
            Ok(Ok(_)) => {
                // permit is returned to Semaphore right away
                WaitOutcome::Released
            }
            Ok(Err(e)) => {
                warn!("error acquiring semaphore {e:?}");
                WaitOutcome::Released
            }
            Err(_) => {
                core.lock_status
                    .store(LockStatus::AgeTimeout.into(), Ordering::SeqCst);
                WaitOutcome::AgeTimeout
            }
        }
    }

    /// Test if it is still locked
    pub fn locked(&self) -> bool {
        self.0.locked()
    }

    /// Whether the lock is expired, e.g., the writer has been holding the lock for too long
    pub fn expired(&self) -> bool {
        // NOTE: this is whether the lock is currently expired
        // not whether it was timed out during wait()
        self.0.lock_start.elapsed() >= self.0.age_timeout
    }

    /// The current status of the lock
    pub fn lock_status(&self) -> LockStatus {
        let status = self.0.lock_status();
        if matches!(status, LockStatus::Waiting) && self.expired() {
            LockStatus::AgeTimeout
        } else {
            status
        }
    }

    pub fn extensions(&self) -> &Extensions {
        self.0.extensions()
    }
}

/// WritePermit: requires who get it need to populate the cache and then release it
#[derive(Debug)]
pub struct WritePermit {
    lock: Arc<LockCore>,
    finished: bool,
}

impl WritePermit {
    /// Create a new lock, with a permit to be given to the associated writer.
    pub fn new(
        timeout: Duration,
        stale_writer: bool,
        extensions: Extensions,
    ) -> (WritePermit, LockStub) {
        let lock = LockCore::new_arc(timeout, stale_writer, extensions);
        let stub = LockStub(lock.clone());
        (
            WritePermit {
                lock,
                finished: false,
            },
            stub,
        )
    }

    /// Was this lock for a stale cache fetch writer?
    pub fn stale_writer(&self) -> bool {
        self.lock.stale_writer()
    }

    pub fn unlock(&mut self, reason: LockStatus) {
        self.finished = true;
        self.lock.unlock(reason);
    }

    pub fn lock_status(&self) -> LockStatus {
        self.lock.lock_status()
    }

    pub fn extensions(&self) -> &Extensions {
        self.lock.extensions()
    }

    /// Describe what this fill involves, so readers that cannot use it stop
    /// waiting. Tokens are opaque: writer and readers need only agree on meaning.
    ///
    /// Each call **replaces** the previous description, since a writer that moved
    /// on is no longer doing what it said and a reader giving up over an
    /// abandoned attempt would lose its caching for nothing. Empty describes
    /// nothing. Only matching readers are woken.
    pub fn publish(&self, tokens: &[u64]) {
        // Most writers never publish anything, and this is called on every
        // upstream request. Replacing nothing with nothing cannot wake a reader,
        // since an empty set matches no token, so it does not need the lock.
        // Racing readers are unaffected either way: one that registers around
        // this point takes the lock, sees nothing published, and waits.
        if tokens.is_empty() && !self.lock.published_any.load(Ordering::Relaxed) {
            return;
        }
        self.lock.publish(tokens);
    }
}

impl Drop for WritePermit {
    fn drop(&mut self) {
        // Writer exited without properly unlocking. We let others to compete for the write lock again
        if !self.finished {
            debug_assert!(false, "Dangling cache lock started!");
            self.unlock(LockStatus::Dangling);
        }
    }
}

#[derive(Debug)]
pub struct LockStub(pub Arc<LockCore>);
impl LockStub {
    pub fn read_lock(&self) -> ReadLock {
        ReadLock(self.0.clone())
    }

    pub fn extensions(&self) -> &Extensions {
        &self.0.extensions
    }
}
