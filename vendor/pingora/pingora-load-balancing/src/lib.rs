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

//! # Pingora Load Balancing utilities
//! This crate provides common service discovery, health check and load balancing
//! algorithms for proxies to use.
//!
//! ## Grouped selector internals
//!
//! In `LoadBalancerGroup<S>`, `S` is the selector algorithm and its built data,
//! such as a Ketama ring. The other types manage its configuration, rebuilding,
//! publication, and lifetime.
//!
//! ```text
//! LoadBalancerGroup<S>
//! |-- BackendView (Backends)
//! |   |-- ServiceDiscovery
//! |   `-- Arc<HealthRegistry>
//! |-- SelectorRebuildGate
//! |-- SelectorRebuildCancellation
//! `-- SelectorSlot<S> x N
//!     |-- config
//!     |-- SelectorRebuildState
//!     |   `-- pending SelectorRebuildRequest
//!     `-- ArcSwap<PublishedSelector<S>>
//!         |-- Arc<S>
//!         |-- readiness snapshot
//!         `-- SelectorReleaseGuard
//!             `-- SelectorReleaseSignal
//!
//! Shared mode:
//! HealthCheckService ---> Arc<HealthRegistry> <--- other BackendViews
//! ```
//!
//! The main roles are:
//!
//! - `Backends`, also named `BackendView`, owns discovered membership,
//!   enablement, health references, and the membership generation. Each
//!   published group selector owns the readiness snapshot for its generation,
//!   so older selectors keep serving their own snapshot.
//! - `HealthRegistry` reconciles the targets contributed by its views and owns
//!   one health state and probe target per backend equivalence key.
//! - `HealthCheckService` runs one active health-check loop for a shared
//!   registry. Views with private registries are checked by their load balancer.
//! - `SelectorSlot<S>` owns one selector configuration, its published selector,
//!   generation, pending work, timings, and counters.
//! - `SelectorRebuildRequest` contains the backend membership, its readiness
//!   snapshot, and generation to build.
//! - `SelectorRebuildState` tracks the active rebuild task and newest pending
//!   request.
//! - `SelectorRebuildTaskGuard` clears the running state and restores an
//!   in-flight request if the task exits unexpectedly.
//! - `SelectorRebuildCancellation` stops rebuild tasks when the group is
//!   dropped.
//! - `PublishedSelector<S>` pairs the selector exposed to requests with the
//!   readiness snapshot for its generation and its lifetime tracking.
//! - `SelectorReleaseGuard` and `SelectorReleaseSignal` notify the gate after a
//!   replaced selector and all its readers are gone.
//! - `SelectorRebuildGate` allows one build at a time and prevents another build
//!   while an old selector is still being destroyed.
//!
//! ### Discovery and shared-health flow
//!
//! 1. `LoadBalancerGroup<S>` asks its `BackendView` to update.
//! 2. The view's `ServiceDiscovery` returns its current `Backend` membership and
//!    enablement.
//! 3. `BackendView` publishes that membership and updates its contribution to
//!    `HealthRegistry`.
//! 4. `HealthRegistry` reconciles the targets from all of its views.
//! 5. In shared mode, `HealthCheckService` probes each registry target once.
//! 6. The resulting health state is visible through every contributing view.
//! 7. Each view applies its own membership and enablement. Each rebuilt group
//!    selector is published with the readiness snapshot for its generation.
//!
//! ### Selector rebuild flow
//!
//! 1. `Backends` advances the membership generation and produces an indivisible
//!    membership and readiness update bundle.
//! 2. `LoadBalancerGroup<S>` schedules each selector rebuild from that bundle.
//! 3. `SelectorRebuildState` keeps one active rebuild and coalesces newer work
//!    into its pending request.
//! 4. `SelectorRebuildTaskGuard` tracks the in-flight request while the task
//!    acquires `SelectorRebuildGate`.
//! 5. The task builds the selector `S` from the request's backend snapshot.
//! 6. A new `PublishedSelector<S>` is stored in the slot's `ArcSwap`, replacing
//!    the old published selector atomically.
//! 7. The slot publishes its selector generation and can process its next
//!    pending request.
//!
//! ### Request flow
//!
//! 1. `LoadBalancerGroup<S>::select` loads a `PublishedSelector<S>` from the
//!    chosen `SelectorSlot<S>`.
//! 2. That published selector snapshot is held for the whole selection while it
//!    yields ordered backend candidates.
//! 3. The published selector's own readiness snapshot answers enablement and
//!    health for each candidate.
//! 4. The first accepted backend is returned; otherwise selection returns
//!    `None`.
//! 5. Replacing the selector does not affect this request's iterator.
//! 6. When the final reader releases the old `PublishedSelector<S>`, its
//!    `SelectorReleaseGuard` updates `SelectorReleaseSignal`.
//! 7. `SelectorRebuildGate` observes that signal and permits the next build.
//!
//! ### Cancellation flow
//!
//! 1. Dropping `LoadBalancerGroup<S>` triggers `SelectorRebuildCancellation`.
//! 2. A task waiting for `SelectorRebuildGate` exits without removing the old
//!    selector's `SelectorReleaseSignal`.
//! 3. `SelectorRebuildTaskGuard` restores an in-flight
//!    `SelectorRebuildRequest` unless a newer request already replaced it.
//! 4. A built but unpublished selector is destroyed on a blocking worker.
//! 5. That destruction retains the gate permit, so another group cannot build
//!    at the same time.
//! 6. The task guard clears the slot's running state and notifies waiters.
//! 7. After destruction completes, the gate permit is released.

// https://github.com/mcarton/rust-derivative/issues/112
// False positive for macro generated code
#![allow(clippy::non_canonical_partial_ord_impl)]

use arc_swap::ArcSwap;
use derivative::Derivative;
use futures::FutureExt;
pub use http::Extensions;
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_error::{ErrorType, OrErr, Result};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::io::Result as IoResult;
use std::net::ToSocketAddrs;
use std::sync::atomic::{
    AtomicBool, AtomicU64,
    Ordering::{Acquire, Relaxed, Release},
};
use std::sync::{mpsc, Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

mod background;
pub mod discovery;
pub mod health_check;
pub mod selection;

use discovery::ServiceDiscovery;
use health_check::Health;
use selection::UniqueIterator;
use selection::{BackendIter, BackendSelection};

pub mod prelude {
    pub use crate::health_check::TcpHealthCheck;
    pub use crate::selection::RoundRobin;
    pub use crate::{BackendView, HealthCheckService, HealthRegistry, LoadBalancer};
}

/// [Backend] represents a server to proxy or connect to.
#[derive(Derivative)]
#[derivative(Clone, Hash, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub struct Backend {
    /// The address to the backend server.
    pub addr: SocketAddr,
    /// The relative weight of the server. Load balancing algorithms will
    /// proportionally distributed traffic according to this value.
    pub weight: usize,

    /// The extension field to put arbitrary data to annotate the Backend.
    /// The data added here is opaque to this crate hence the data is ignored by
    /// functionalities of this crate. For example, two backends with the same
    /// [SocketAddr] and the same weight but different `ext` data are considered
    /// identical.
    /// See [Extensions] for how to add and read the data.
    #[derivative(PartialEq = "ignore")]
    #[derivative(PartialOrd = "ignore")]
    #[derivative(Hash = "ignore")]
    #[derivative(Ord = "ignore")]
    pub ext: Extensions,
}

impl Backend {
    /// Create a new [Backend] with `weight` 1. The function will try to parse
    ///  `addr` into a [std::net::SocketAddr].
    pub fn new(addr: &str) -> Result<Self> {
        Self::new_with_weight(addr, 1)
    }

    /// Creates a new [Backend] with the specified `weight`. The function will try to parse
    /// `addr` into a [std::net::SocketAddr].
    pub fn new_with_weight(addr: &str, weight: usize) -> Result<Self> {
        let addr = addr
            .parse()
            .or_err(ErrorType::InternalError, "invalid socket addr")?;
        Ok(Backend {
            addr: SocketAddr::Inet(addr),
            weight,
            ext: Extensions::new(),
        })
        // TODO: UDS
    }

    pub(crate) fn hash_key(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

impl std::ops::Deref for Backend {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        &self.addr
    }
}

impl std::ops::DerefMut for Backend {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.addr
    }
}

impl std::net::ToSocketAddrs for Backend {
    type Iter = std::iter::Once<std::net::SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        self.addr.to_socket_addrs()
    }
}

/// The backends to check and their health.
///
/// Both are updated together. If multiple backends have the same health key,
/// only one is checked and they all share one health value.
struct HealthRegistryState {
    targets: Box<[Backend]>,
    /// Health handles keyed by the registry's health key (see
    /// [`HealthRegistry::health_key`]). The default key uses full backend
    /// identity; callers can supply a different key when constructing a
    /// registry.
    health: HashMap<u64, Health>,
}

/// Active health state shared by one or more [`BackendView`]s.
///
/// Registries use full backend identity by default. Callers can supply an
/// equivalence key to intentionally share probes across backend variants.
pub struct HealthRegistry {
    health_check: OnceLock<Arc<dyn health_check::HealthCheck + Send + Sync + 'static>>,
    state: ArcSwap<HealthRegistryState>,
    /// View changes are applied one at a time so concurrent updates are not
    /// lost. Request handling does not read this map.
    views: Mutex<BTreeMap<u64, Arc<BTreeSet<Backend>>>>,
    /// Assigns each view the ID used to update and remove its backend set.
    next_view_id: AtomicU64,
    /// Queues view removals so dropping a view never waits for reconciliation.
    view_removal_tx: mpsc::Sender<u64>,
    /// View removals waiting to be applied during the next registry operation.
    pending_view_removals: Mutex<mpsc::Receiver<u64>>,
    /// Wakes the health service so queued removals are applied promptly.
    view_removed: Notify,
    /// Wakes the health service when the registry gains its first target.
    targets_available: Notify,
    /// Backends with the same key share one health check and health value.
    equivalence_key: Arc<dyn Fn(&Backend) -> u64 + Send + Sync + 'static>,
}

impl Default for HealthRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthRegistry {
    /// Create an empty registry keyed by full backend identity.
    pub fn new() -> Self {
        Self::with_equivalence(|backend| backend.hash_key())
    }

    /// Create an empty registry using `equivalence_key` to group targets.
    ///
    /// Backends that produce the same `u64` key share one health state and
    /// probe. Callers are responsible for ensuring that backends which need
    /// independent health state produce distinct keys.
    pub fn with_equivalence(
        equivalence_key: impl Fn(&Backend) -> u64 + Send + Sync + 'static,
    ) -> Self {
        let (view_removal_tx, pending_view_removals) = mpsc::channel();
        Self {
            health_check: OnceLock::new(),
            state: ArcSwap::new(Arc::new(HealthRegistryState {
                targets: Vec::new().into_boxed_slice(),
                health: HashMap::new(),
            })),
            views: Mutex::new(BTreeMap::new()),
            next_view_id: AtomicU64::new(1),
            view_removal_tx,
            pending_view_removals: Mutex::new(pending_view_removals),
            view_removed: Notify::new(),
            targets_available: Notify::new(),
            equivalence_key: Arc::new(equivalence_key),
        }
    }

    /// The key under which a backend's shared [`Health`] is tracked.
    fn health_key(&self, backend: &Backend) -> u64 {
        (self.equivalence_key)(backend)
    }

    /// Set the health-check implementation used by every view in this registry.
    ///
    /// # Panics
    ///
    /// Panics if a health check has already been set.
    pub fn set_health_check(&self, hc: Box<dyn health_check::HealthCheck + Send + Sync + 'static>) {
        assert!(
            self.health_check.set(hc.into()).is_ok(),
            "health check already configured"
        );
    }

    fn has_health_check(&self) -> bool {
        self.health_check.get().is_some()
    }

    fn register_view(&self) -> u64 {
        self.apply_pending_view_removals();
        let view_id = self.next_view_id.fetch_add(1, Relaxed);
        self.views
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(view_id, Arc::new(BTreeSet::new()));
        view_id
    }

    /// Publish `backends` as `view_id`'s membership and return the reconciled
    /// registry state so the caller can snapshot the shared health handles for
    /// its backends without a second registry load.
    fn update_view(
        &self,
        view_id: u64,
        backends: Arc<BTreeSet<Backend>>,
    ) -> Arc<HealthRegistryState> {
        self.apply_pending_view_removals();
        let mut views = self
            .views
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        views.insert(view_id, backends);
        self.reconcile(&views)
    }

    fn defer_view_removal(&self, view_id: u64) {
        let _ = self.view_removal_tx.send(view_id);
        self.view_removed.notify_one();
    }

    fn apply_pending_view_removals(&self) {
        let view_ids: Vec<_> = self
            .pending_view_removals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .try_iter()
            .collect();
        if view_ids.is_empty() {
            return;
        }

        let mut views = self
            .views
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut changed = false;
        for view_id in view_ids {
            changed |= views.remove(&view_id).is_some();
        }
        if changed {
            self.reconcile(&views);
        }
    }

    /// Wait until a view removal is queued. The caller must then apply pending removals.
    pub(crate) async fn wait_for_view_removal(&self) {
        self.view_removed.notified().await;
    }

    fn reconcile(&self, views: &BTreeMap<u64, Arc<BTreeSet<Backend>>>) -> Arc<HealthRegistryState> {
        let old_state = self.state.load();
        let mut targets_by_key = HashMap::new();
        for backends in views.values() {
            for backend in backends.iter() {
                targets_by_key
                    .entry(self.health_key(backend))
                    .or_insert_with(|| backend.clone());
            }
        }

        let mut targets: Vec<_> = targets_by_key.into_values().collect();
        targets.sort_unstable();
        let gained_first_target = old_state.targets.is_empty() && !targets.is_empty();
        let mut health = HashMap::with_capacity(targets.len());
        for backend in &targets {
            let key = self.health_key(backend);
            health.insert(key, old_state.health.get(&key).cloned().unwrap_or_default());
        }

        let new_state = Arc::new(HealthRegistryState {
            targets: targets.into_boxed_slice(),
            health,
        });
        self.state.store(Arc::clone(&new_state));
        if gained_first_target {
            self.targets_available.notify_one();
        }
        new_state
    }

    /// Return the number of distinct backend targets currently being tracked.
    ///
    /// Targets that produce the same registry health key count as one target.
    pub fn target_count(&self) -> usize {
        self.apply_pending_view_removals();
        self.state.load().targets.len()
    }

    /// Wait until at least one registered view contributes a backend target.
    pub(crate) async fn wait_for_targets(&self) {
        loop {
            let notified = self.targets_available.notified();
            // `enable()` requires a pinned future because it registers it in
            // `Notify`'s waiter list. Register first so a new target is not missed.
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.target_count() > 0 {
                return;
            }
            notified.await;
        }
    }

    /// Run one active health-check pass over the union of all registered views.
    ///
    /// When `parallel` is true, all targets are checked concurrently.
    ///
    /// Dropping the returned future cancels the pass: outstanding per-target
    /// checks are aborted rather than left running to completion, so targets
    /// not yet reported keep their previous health.
    pub async fn run_health_check(&self, parallel: bool) {
        use crate::health_check::HealthCheck;
        use log::{info, warn};
        use pingora_runtime::current_handle;

        async fn check_and_report(
            backend: &Backend,
            check: &Arc<dyn HealthCheck + Send + Sync>,
            health: &Health,
        ) {
            let errored = check.check(backend).await.err();
            let healthy = errored.is_none();
            let flipped = health.observe_health(healthy, check.health_threshold(healthy));
            if flipped {
                check.health_status_change(backend, healthy).await;
                let summary = check.backend_summary(backend);
                if let Some(error) = errored {
                    warn!("{summary} becomes unhealthy, {error}");
                } else {
                    info!("{summary} becomes healthy");
                }
            }
        }

        self.apply_pending_view_removals();
        let Some(health_check) = self.health_check.get().cloned() else {
            // nothing to do
            return;
        };

        let state = self.state.load_full();
        if parallel {
            let runtime = current_handle();
            // A `JoinSet` aborts every task it still owns when it is dropped, so
            // abandoning this pass mid-flight cancels the outstanding checks
            // instead of leaving them detached on the runtime.
            let mut jobs = tokio::task::JoinSet::new();
            for backend in state.targets.iter() {
                let backend = backend.clone();
                let key = self.health_key(&backend);
                let check = Arc::clone(&health_check);
                let state = Arc::clone(&state);
                jobs.spawn_on(
                    async move {
                        if let Some(health) = state.health.get(&key) {
                            check_and_report(&backend, &check, health).await;
                        }
                    },
                    &runtime,
                );
            }
            // Drained one at a time rather than with `JoinSet::join_all`, which
            // resumes a task panic in this caller. One backend's check panicking
            // should not abort the checks for every other backend.
            while let Some(joined) = jobs.join_next().await {
                if let Err(error) = joined {
                    // That backend keeps its previous health for this pass.
                    warn!("health check task failed: {error}");
                }
            }
        } else {
            for backend in state.targets.iter() {
                if let Some(health) = state.health.get(&self.health_key(backend)) {
                    check_and_report(backend, &health_check, health).await;
                }
            }
        }
    }
}

/// View-local enablement paired with the shared [`Health`] handle for one
/// backend identity.
///
/// Caching the [`Health`] handle in a [`ReadinessSnapshot`] lets readiness be
/// answered with a single map lookup, avoiding a snapshot of the
/// [`HealthRegistry`]. The handle shares its inner state with the registry, so
/// health observations and reconciliation remain visible through it, including
/// through a snapshot retained by an older selector.
#[derive(Clone)]
struct BackendReadiness {
    enabled: Arc<AtomicBool>,
    health: Health,
}

impl BackendReadiness {
    fn ready(&self) -> bool {
        self.enabled.load(Relaxed) && self.health.ready()
    }
}

/// An immutable, readiness-only snapshot of one backend view generation.
///
/// Readiness is indexed by [`Backend::hash_key`]. Cloning shares the underlying
/// map through an [`Arc`]; each [`BackendReadiness`] keeps the shared live
/// [`Health`] handle and the [`struct@AtomicBool`] enablement flag, so health
/// observations and manual enable/disable stay visible through every clone of a
/// generation's snapshot, including one owned by an older selector.
#[derive(Clone)]
struct ReadinessSnapshot(Arc<HashMap<u64, BackendReadiness>>);

impl ReadinessSnapshot {
    /// A snapshot with no known backends.
    fn empty() -> Self {
        Self(Arc::new(HashMap::new()))
    }

    /// Look up readiness by full backend identity.
    fn get(&self, backend: &Backend) -> Option<&BackendReadiness> {
        self.0.get(&backend.hash_key())
    }

    /// Whether the backend is present in this snapshot and both enabled and
    /// healthy.
    fn ready(&self, backend: &Backend) -> bool {
        self.get(backend).is_some_and(BackendReadiness::ready)
    }
}

/// One published snapshot of a backend view: its current membership paired with
/// the readiness snapshot for that generation.
struct BackendViewState {
    /// The backend membership exposed by this snapshot.
    backends: Arc<BTreeSet<Backend>>,
    /// Readiness for the current membership, keyed by full backend identity.
    readiness: ReadinessSnapshot,
}

/// An indivisible membership and readiness update produced by a membership
/// change.
///
/// Groups schedule selector rebuilds from this bundle so each rebuilt selector
/// is published with the exact readiness snapshot for its generation, keeping
/// membership, readiness, and generation consistent across coalescing, retries,
/// and cancellation.
struct BackendUpdate {
    /// Membership generation this update advanced to.
    generation: u64,
    /// Membership captured for this generation.
    backends: Arc<BTreeSet<Backend>>,
    /// Readiness snapshot for this generation.
    readiness: ReadinessSnapshot,
}

/// A discovered backend membership with view-local enablement and shared
/// active health state.
///
/// Readiness is the conjunction of current view membership, view-local
/// enablement, and the health state in the associated [`HealthRegistry`].
pub struct Backends {
    discovery: Box<dyn ServiceDiscovery + Send + Sync + 'static>,
    health_registry: Arc<HealthRegistry>,
    view_id: u64,
    state: ArcSwap<BackendViewState>,
    /// Membership generation, advanced on each change.
    generation: AtomicU64,
    /// Weak enablement handles keyed by full backend identity.
    ///
    /// Lets [`Backends::set_enable`] reach a removed backend whose enablement
    /// flag is still held by an older selector's readiness snapshot, and lets a
    /// re-added backend recover its manual enablement while an older selector
    /// still references it. Never read on the request path, so it takes a lock
    /// only during membership updates and manual enable/disable. Expired entries
    /// are cleaned up opportunistically on each membership change.
    enablement_handles: Mutex<HashMap<u64, Weak<AtomicBool>>>,
    /// Whether the load balancer owning this view owns its active health checks.
    /// Shared-registry views leave them to [`HealthCheckService`].
    owns_health_checks: bool,
}

/// Explicit name for a [`Backends`] instance used as one membership view.
pub type BackendView = Backends;

impl Backends {
    /// Create a backend view with a private health registry.
    ///
    /// Load balancers constructed from this view retain the existing behavior
    /// of scheduling their own health checks.
    pub fn new(discovery: Box<dyn ServiceDiscovery + Send + Sync + 'static>) -> Self {
        Self::new_inner(discovery, Arc::new(HealthRegistry::new()), true)
    }

    /// Create a backend view that contributes targets to `health_registry`.
    ///
    /// Health checks for shared views must be scheduled once through
    /// [`HealthCheckService`] instead of by every load balancer using the view.
    /// The registry must have a health check configured before that service is
    /// started.
    pub fn new_with_health_registry(
        discovery: Box<dyn ServiceDiscovery + Send + Sync + 'static>,
        health_registry: Arc<HealthRegistry>,
    ) -> Self {
        Self::new_inner(discovery, health_registry, false)
    }

    fn new_inner(
        discovery: Box<dyn ServiceDiscovery + Send + Sync + 'static>,
        health_registry: Arc<HealthRegistry>,
        owns_health_checks: bool,
    ) -> Self {
        let view_id = health_registry.register_view();
        Self {
            discovery,
            health_registry,
            view_id,
            state: ArcSwap::new(Arc::new(BackendViewState {
                backends: Arc::new(BTreeSet::new()),
                readiness: ReadinessSnapshot::empty(),
            })),
            generation: AtomicU64::new(0),
            enablement_handles: Mutex::new(HashMap::new()),
            owns_health_checks,
        }
    }

    /// The current membership generation, advanced once per membership change.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Relaxed)
    }

    fn lock_enablement_handles(&self) -> MutexGuard<'_, HashMap<u64, Weak<AtomicBool>>> {
        self.enablement_handles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The readiness snapshot for the currently published generation.
    fn readiness_snapshot(&self) -> ReadinessSnapshot {
        self.state.load().readiness.clone()
    }

    /// Set the health check used by this view's entire health registry.
    pub fn set_health_check(
        &mut self,
        hc: Box<dyn health_check::HealthCheck + Send + Sync + 'static>,
    ) {
        self.health_registry.set_health_check(hc);
    }

    fn do_update<F>(
        &self,
        new_backends: BTreeSet<Backend>,
        enablement: HashMap<u64, bool>,
        callback: F,
    ) -> Option<BackendUpdate>
    where
        F: FnOnce(Arc<BTreeSet<Backend>>),
    {
        let old_state = self.state.load_full();
        let membership_changed = *old_state.backends != new_backends;
        if membership_changed {
            let generation = self.generation.fetch_add(1, Relaxed) + 1;
            let new_backends = Arc::new(new_backends);
            let registry_state = self
                .health_registry
                .update_view(self.view_id, Arc::clone(&new_backends));

            let mut new_readiness = HashMap::with_capacity(new_backends.len());
            {
                let mut handles = self.lock_enablement_handles();
                // Opportunistically drop enablement handles that no readiness
                // snapshot references anymore.
                handles.retain(|_, weak| weak.strong_count() > 0);
                for backend in new_backends.iter() {
                    let key = backend.hash_key();
                    // Preserve enablement across removal and re-addition while
                    // an older selector's snapshot still holds the flag.
                    let enabled = old_state
                        .readiness
                        .get(backend)
                        .map(|current| Arc::clone(&current.enabled))
                        .or_else(|| handles.get(&key).and_then(Weak::upgrade))
                        .unwrap_or_else(|| Arc::new(AtomicBool::new(true)));
                    if let Some(enabled_override) = enablement.get(&key) {
                        enabled.store(*enabled_override, Relaxed);
                    }
                    handles.insert(key, Arc::downgrade(&enabled));
                    let health = registry_state
                        .health
                        .get(&self.health_registry.health_key(backend))
                        .cloned()
                        .unwrap_or_default();
                    new_readiness.insert(key, BackendReadiness { enabled, health });
                }
            }
            let new_readiness = ReadinessSnapshot(Arc::new(new_readiness));

            // Cover both the old and new readiness during a synchronous selector
            // rebuild so a request in the callback does not lose a backend the
            // about-to-be-replaced selector may still yield. This allocation is
            // linear in old and new membership and only runs on membership changes.
            let mut transition = old_state.readiness.0.as_ref().clone();
            for (key, readiness) in new_readiness.0.iter() {
                transition.insert(*key, readiness.clone());
            }
            self.state.store(Arc::new(BackendViewState {
                backends: Arc::clone(&old_state.backends),
                readiness: ReadinessSnapshot(Arc::new(transition)),
            }));

            callback(Arc::clone(&new_backends));

            self.state.store(Arc::new(BackendViewState {
                backends: Arc::clone(&new_backends),
                readiness: new_readiness.clone(),
            }));
            Some(BackendUpdate {
                generation,
                backends: new_backends,
                readiness: new_readiness,
            })
        } else {
            for (key, enabled) in enablement {
                if let Some(current) = old_state.readiness.0.get(&key) {
                    current.enabled.store(enabled, Relaxed);
                }
            }
            None
        }
    }

    /// Whether `backend` is enabled and healthy in this view's current
    /// membership.
    ///
    /// This is on the hot request path: it takes a single snapshot of the
    /// published view state and performs one map lookup to a `BackendReadiness`
    /// carrying both the view-local enablement flag and the shared `Health`
    /// handle, so no second registry snapshot is required.
    ///
    /// Readiness is keyed by full backend identity. Only the current membership
    /// is reported: a removed backend is not ready here even while an older
    /// group selector can still return it through its own readiness snapshot.
    pub fn ready(&self, backend: &Backend) -> bool {
        self.state.load().readiness.ready(backend)
    }

    /// Manually enable or disable `backend` by full backend identity.
    ///
    /// The current membership is updated in place. A removed backend is reached
    /// through the weak enablement-handle interner, so disabling or re-enabling
    /// a backend still held by an older group selector's readiness snapshot
    /// takes effect for that selector too. Not on the request path, so it may
    /// take the interner lock. If the backend is unknown or no snapshot retains
    /// its enablement flag, this method does nothing.
    pub fn set_enable(&self, backend: &Backend, enabled: bool) {
        let key = backend.hash_key();
        // Current membership shares the same `Arc<AtomicBool>` as the interner
        // and any older snapshot, so flipping it here is sufficient.
        if let Some(readiness) = self.state.load().readiness.0.get(&key) {
            readiness.enabled.store(enabled, Relaxed);
            return;
        }
        // Otherwise reach a removed backend whose flag an older selector's
        // snapshot may still hold.
        if let Some(enabled_flag) = self
            .lock_enablement_handles()
            .get(&key)
            .and_then(Weak::upgrade)
        {
            enabled_flag.store(enabled, Relaxed);
        }
    }

    /// Return this view's current backend membership.
    pub fn get_backend(&self) -> Arc<BTreeSet<Backend>> {
        Arc::clone(&self.state.load().backends)
    }

    /// Run discovery and invoke `callback` when membership changes.
    ///
    /// Calls on the same backend view must not overlap with another update.
    pub async fn update<F>(&self, callback: F) -> Result<()>
    where
        F: FnOnce(Arc<BTreeSet<Backend>>),
    {
        let (new_backends, enablement) = self.discovery.discover().await?;
        self.do_update(new_backends, enablement, callback);
        Ok(())
    }

    /// Run discovery and return the membership and readiness update bundle when
    /// membership changes, for a group to schedule selector rebuilds.
    async fn update_backends(&self) -> Result<Option<BackendUpdate>> {
        let (new_backends, enablement) = self.discovery.discover().await?;
        Ok(self.do_update(new_backends, enablement, |_| {}))
    }

    /// Run one health-check pass for this view's entire registry.
    ///
    /// Dropping the returned future cancels the pass, as described on
    /// [`HealthRegistry::run_health_check`].
    pub async fn run_health_check(&self, parallel: bool) {
        self.health_registry.run_health_check(parallel).await;
    }

    /// Return whether this view's load balancer owns its active probe loop.
    fn owns_health_checks(&self) -> bool {
        self.owns_health_checks
    }
}

impl Drop for Backends {
    fn drop(&mut self) {
        self.health_registry.defer_view_removal(self.view_id);
    }
}

/// Background service that runs one health-check loop for a shared
/// [`HealthRegistry`].
///
/// Use this service with views created by
/// [`BackendView::new_with_health_registry`]. Load balancers backed by
/// [`Backends::new`] already schedule their private registry and must not also
/// run a `HealthCheckService` for it.
///
/// In periodic mode (`health_check_frequency` set) the service signals
/// readiness after its first health-check pass, including when no views have
/// published targets yet, and publishing the first target wakes it for an
/// immediate pass. In one-shot mode (`health_check_frequency` is `None`) the
/// service instead waits for the first published target before running its
/// single pass and signaling readiness, so it never checks an empty registry
/// and returns before any target exists.
pub struct HealthCheckService {
    registry: Arc<HealthRegistry>,
    /// How frequently to run health checks.
    ///
    /// If `None`, health checks run once when the service starts.
    pub health_check_frequency: Option<Duration>,
    /// Whether to check all targets concurrently.
    pub parallel_health_check: bool,
}

impl HealthCheckService {
    /// Create a health-check service for `registry`.
    ///
    /// A health check must be configured on `registry` before the service is
    /// started. Starting without one fails closed without signaling readiness.
    pub fn new(registry: Arc<HealthRegistry>) -> Self {
        Self {
            registry,
            health_check_frequency: None,
            parallel_health_check: false,
        }
    }
}

/// Timing information from the most recent [`LoadBalancer::update`] call.
#[derive(Debug, Clone, Copy)]
pub struct UpdateTimings {
    /// Time spent in [`ServiceDiscovery::discover`].
    pub discovery_duration: Duration,
    /// Time spent building the selection algorithm and storing the updated backends.
    ///
    /// This is zero for [`LoadBalancerGroup`] because its selectors rebuild
    /// asynchronously. Use
    /// [`LoadBalancerGroup::selector_last_update_timing`] for per-selector
    /// queue and build durations.
    pub build_duration: Duration,
}

/// A [LoadBalancer] instance contains the service discovery, health check and backend selection
/// all together.
///
/// In order to run service discovery and health check at the designated frequencies, the [LoadBalancer]
/// needs to be run as a [pingora_core::services::background::BackgroundService].
pub struct LoadBalancer<S>
where
    S: BackendSelection,
{
    backends: Backends,
    selector: ArcSwap<S>,

    config: Option<S::Config>,

    /// Timing information from the most recent [`update`](Self::update) call.
    ///
    /// `None` until the first successful update completes.
    last_update_timing: ArcSwap<Option<UpdateTimings>>,

    /// How frequent the health check logic (if set) should run.
    ///
    /// If `None`, the health check logic will only run once at the beginning.
    /// This setting is ignored for views created with
    /// [`BackendView::new_with_health_registry`]; use [`HealthCheckService`]
    /// for those views.
    pub health_check_frequency: Option<Duration>,
    /// How frequent the service discovery should run.
    ///
    /// If `None`, the service discovery will only run once at the beginning.
    pub update_frequency: Option<Duration>,
    /// Whether to run health check to all backends in parallel. Default is false.
    pub parallel_health_check: bool,
}

fn build_selector<S>(backends: &BTreeSet<Backend>, config: Option<&S::Config>) -> S
where
    S: BackendSelection,
{
    if let Some(config) = config {
        S::build_with_config(backends, config)
    } else {
        S::build(backends)
    }
}

impl<S> LoadBalancer<S>
where
    S: BackendSelection + 'static,
    S::Iter: BackendIter,
{
    /// Build a [LoadBalancer] with static backends created from the iter.
    ///
    /// Note: [ToSocketAddrs] will invoke blocking network IO for DNS lookup if
    /// the input cannot be directly parsed as [SocketAddr].
    pub fn try_from_iter<A, T: IntoIterator<Item = A>>(iter: T) -> IoResult<Self>
    where
        A: ToSocketAddrs,
    {
        let discovery = discovery::Static::try_from_iter(iter)?;
        let backends = Backends::new(discovery);
        let lb = Self::from_backends(backends);
        lb.update()
            .now_or_never()
            .expect("static should not block")
            .expect("static should not error");
        Ok(lb)
    }

    /// Build a [LoadBalancer] with the given [Backends] and the config.
    pub fn from_backends_with_config(backends: Backends, config_opt: Option<S::Config>) -> Self {
        let selector_raw = build_selector::<S>(&backends.get_backend(), config_opt.as_ref());

        let selector = ArcSwap::new(Arc::new(selector_raw));

        LoadBalancer {
            backends,
            selector,
            config: config_opt,
            last_update_timing: ArcSwap::new(Arc::new(None)),
            health_check_frequency: None,
            update_frequency: None,
            parallel_health_check: false,
        }
    }

    /// Build a [LoadBalancer] with the given [Backends].
    pub fn from_backends(backends: Backends) -> Self {
        Self::from_backends_with_config(backends, None)
    }

    /// Run the service discovery and update the selection algorithm.
    ///
    /// This function will be called every `update_frequency` if this [LoadBalancer] instance
    /// is running as a background service.
    ///
    /// On success, the timing information from this call is stored and can be
    /// retrieved via [`last_update_timing`](Self::last_update_timing).
    pub async fn update(&self) -> Result<()> {
        use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

        let build_nanos = AtomicU64::new(0);
        let total_start = Instant::now();

        self.backends
            .update(|backends| {
                let build_start = Instant::now();
                let selector = build_selector::<S>(&backends, self.config.as_ref());
                self.selector.store(Arc::new(selector));
                build_nanos.store(build_start.elapsed().as_nanos() as u64, Relaxed);
            })
            .await?;

        let total = total_start.elapsed();
        let build = Duration::from_nanos(build_nanos.load(Relaxed));

        self.last_update_timing.store(Arc::new(Some(UpdateTimings {
            discovery_duration: total.saturating_sub(build),
            build_duration: build,
        })));

        Ok(())
    }

    /// Return the first healthy [Backend] according to the selection algorithm and the
    /// health check results.
    ///
    /// The `key` is used for hash based selection and is ignored if the selection is random or
    /// round robin.
    ///
    /// the `max_iterations` is there to bound the search time for the next Backend. In certain
    /// algorithm like Ketama hashing, the search for the next backend is linear and could take
    /// a lot steps.
    // TODO: consider remove `max_iterations` as users have no idea how to set it.
    pub fn select(&self, key: &[u8], max_iterations: usize) -> Option<Backend> {
        self.select_with(key, max_iterations, |_, health| health)
    }

    /// Similar to [Self::select], return the first healthy [Backend] according to the selection algorithm
    /// and the user defined `accept` function.
    ///
    /// The `accept` function takes two inputs, the backend being selected and the internal health of that
    /// backend. The function can do things like ignoring the internal health checks or skipping this backend
    /// because it failed before. The `accept` function is called multiple times iterating over backends
    /// until it returns `true`.
    pub fn select_with<F>(&self, key: &[u8], max_iterations: usize, accept: F) -> Option<Backend>
    where
        F: Fn(&Backend, bool) -> bool,
    {
        let selection = self.selector.load();
        let mut iter = UniqueIterator::new(selection.iter(key), max_iterations);
        while let Some(b) = iter.get_next() {
            if accept(&b, self.backends.ready(&b)) {
                return Some(b);
            }
        }
        None
    }

    /// Set the health check method. See [health_check].
    pub fn set_health_check(
        &mut self,
        hc: Box<dyn health_check::HealthCheck + Send + Sync + 'static>,
    ) {
        self.backends.set_health_check(hc);
    }

    /// Access the [Backends] of this [LoadBalancer]
    pub fn backends(&self) -> &Backends {
        &self.backends
    }

    /// Return the timing information from the most recent successful [`update`](Self::update) call.
    ///
    /// Returns `None` if [`update`](Self::update) has never completed successfully.
    pub fn last_update_timing(&self) -> Option<UpdateTimings> {
        **self.last_update_timing.load()
    }
}

/// Timing information for one selector rebuild.
#[derive(Debug, Clone, Copy)]
pub struct SelectorUpdateTimings {
    /// The backend generation used to build the selector.
    pub generation: u64,
    /// Time from the discovery update until selector construction started.
    pub queue_duration: Duration,
    /// Time spent constructing and publishing the selector.
    pub build_duration: Duration,
}

/// A request to rebuild one selector for a backend generation.
struct SelectorRebuildRequest {
    /// Backend generation this request will build.
    generation: u64,
    /// Backend membership captured for this generation.
    backends: Arc<BTreeSet<Backend>>,
    /// Readiness snapshot published with the rebuilt selector, kept together
    /// with membership and generation through coalescing, retries, and
    /// cancellation.
    readiness: ReadinessSnapshot,
    /// Time the rebuild was requested, used to measure queue delay.
    requested_at: Instant,
}

/// Per-selector state for one active rebuild and its newest pending request.
#[derive(Default)]
struct SelectorRebuildState {
    /// Whether a worker currently owns this selector's rebuild loop.
    is_running: bool,
    /// Newest request waiting for that worker; older requests are replaced.
    pending_request: Option<SelectorRebuildRequest>,
}

/// Restores a selector's rebuild state if its worker exits unexpectedly.
struct SelectorRebuildTaskGuard<S>
where
    S: BackendSelection,
{
    /// Selector slot whose worker state this guard owns.
    slot: Arc<SelectorSlot<S>>,
    /// Wakes the group background loop after cleanup.
    rebuild_notify: Arc<Notify>,
    /// Request restored to `pending` if the worker stops during a build.
    in_flight: Option<SelectorRebuildRequest>,
    /// Whether dropping this guard should perform cleanup.
    armed: bool,
}

/// Monotonic cancellation signal shared by all selector tasks in one group.
///
/// [`Self::wait_for_cancel`] registers its waiter before rechecking the flag because
/// [`Notify::notify_waiters`] does not retain a permit for future waiters.
struct SelectorRebuildCancellation {
    /// Remains true after cancellation begins.
    cancelled: AtomicBool,
    /// Wakes every rebuild task waiting for cancellation.
    notify: Notify,
}

impl SelectorRebuildCancellation {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Release);
        self.notify.notify_waiters();
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Acquire)
    }

    async fn wait_for_cancel(&self) {
        if self.is_cancelled() {
            return;
        }

        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

impl<S> SelectorRebuildTaskGuard<S>
where
    S: BackendSelection,
{
    fn new(slot: Arc<SelectorSlot<S>>, rebuild_notify: Arc<Notify>) -> Self {
        Self {
            slot,
            rebuild_notify,
            in_flight: None,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<S> Drop for SelectorRebuildTaskGuard<S>
where
    S: BackendSelection,
{
    fn drop(&mut self) {
        // Normal completion disarms the guard after clearing the worker state.
        if !self.armed {
            return;
        }

        // Record a worker panic that bypassed the normal rebuild error path.
        if std::thread::panicking() {
            self.slot.failed_rebuilds.fetch_add(1, Relaxed);
            log::error!("load-balancing selector rebuild task panicked");
        }
        // This lock is never held across an await or user code, so task
        // cancellation cannot re-enter it and competing critical sections are short.
        let mut rebuild_state = lock_rebuild_state(&self.slot.rebuild_state);
        if let Some(request) = self.in_flight.take() {
            if rebuild_state
                .pending_request
                .as_ref()
                .is_none_or(|pending| pending.generation <= request.generation)
            {
                rebuild_state.pending_request = Some(request);
            }
        }
        // no worker running the rebuild anymore
        rebuild_state.is_running = false;
        drop(rebuild_state);
        // Prompt startup readiness to recheck generations after unexpected
        // cleanup. This does not restart the stopped rebuild worker.
        self.rebuild_notify.notify_one();
    }
}

/// One independently configured selector in a [`LoadBalancerGroup`].
struct SelectorSlot<S>
where
    S: BackendSelection,
{
    /// Selector snapshot currently used by requests.
    selector: ArcSwap<PublishedSelector<S>>,
    /// Configuration used to build this selector.
    config: Option<S::Config>,
    /// Backend generation served by the published selector.
    generation: AtomicU64,
    /// Active worker and newest pending rebuild request.
    rebuild_state: Mutex<SelectorRebuildState>,
    /// Timing from the most recently published rebuild.
    last_update_timing: ArcSwap<Option<SelectorUpdateTimings>>,
    /// Number of pending requests replaced by newer generations.
    coalesced_rebuilds: AtomicU64,
    /// Number of rebuild attempts that failed.
    failed_rebuilds: AtomicU64,
    /// Interrupts retry backoff when a newer request arrives.
    interrupt_retry: Notify,
}

/// Signals when a retired selector and all of its readers have been released.
struct SelectorReleaseSignal {
    /// Whether the retired selector and all readers have been dropped.
    released: AtomicBool,
    /// Wakes the rebuild gate when release completes.
    notify: Notify,
}

impl SelectorReleaseSignal {
    fn new() -> Self {
        Self {
            released: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    async fn wait_for_release(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.released.load(Acquire) {
                return;
            }
            notified.await;
        }
    }
}

/// Field-drop guard that signals a selector's release.
///
/// Kept as the final field of [`PublishedSelector`] so its [`Drop`] runs
/// *after* the `Arc<S>` selector field has been dropped. A manual
/// `impl Drop for PublishedSelector` would instead run before any field is
/// dropped, signaling release while the selector is still alive and violating
/// the one-additional-generation memory bound.
struct SelectorReleaseGuard {
    /// Signal updated when this final field is dropped.
    release_signal: Arc<SelectorReleaseSignal>,
}

impl Drop for SelectorReleaseGuard {
    fn drop(&mut self) {
        self.release_signal.released.store(true, Release);
        self.release_signal.notify.notify_one();
    }
}

/// A built selector snapshot published to request readers through [`ArcSwap`].
///
/// It pairs the selection data with the readiness snapshot for its generation
/// and a signal used to track when a replaced snapshot is no longer referenced.
/// Keeping readiness here lets a retired selector keep serving its own backends
/// with their own readiness, independently of the current view state.
struct PublishedSelector<S> {
    /// Declared before `release_guard` so the shared selector is dropped (and,
    /// when this holds the last reference, destroyed) before release is
    /// signaled.
    selector: Arc<S>,
    /// Readiness for the generation this selector was built from.
    readiness: ReadinessSnapshot,
    /// Signals after `selector` and all published references are dropped.
    release_guard: SelectorReleaseGuard,
}

impl<S> PublishedSelector<S> {
    fn new(selector: S, readiness: ReadinessSnapshot) -> Self {
        Self {
            selector: Arc::new(selector),
            readiness,
            release_guard: SelectorReleaseGuard {
                release_signal: Arc::new(SelectorReleaseSignal::new()),
            },
        }
    }

    fn release_signal(&self) -> Arc<SelectorReleaseSignal> {
        Arc::clone(&self.release_guard.release_signal)
    }
}

/// A serial rebuild gate shared by one or more [`LoadBalancerGroup`]s.
///
/// The gate permits one selector build at a time. After a replacement is
/// published, it also waits for all readers of the retired selector to release
/// it before permitting another build. Groups that share one gate therefore
/// retain at most one additional selector generation beyond their currently
/// published selectors: either one replacement under construction or one
/// retired selector still held by readers, never both.
///
/// Retired selectors notify the gate when their final reader releases them, so
/// one gate can coordinate groups with different selector implementations
/// without polling.
pub struct SelectorRebuildGate {
    /// Allows only one selector build through this gate at a time.
    semaphore: Arc<Semaphore>,
    /// Release signal that must complete before the next build starts.
    retired: Mutex<Option<Arc<SelectorReleaseSignal>>>,
}

impl Default for SelectorRebuildGate {
    fn default() -> Self {
        Self::new()
    }
}

impl SelectorRebuildGate {
    /// Create a serial selector rebuild gate.
    pub fn new() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(1)),
            retired: Mutex::new(None),
        }
    }

    async fn acquire(self: &Arc<Self>) -> OwnedSemaphorePermit {
        let permit = Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .expect("selector rebuild gate semaphore is never closed");
        let retired = self
            .retired
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(retired) = retired {
            retired.wait_for_release().await;
            let mut registered = self
                .retired
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Clear only the signal we waited for, not a newer retired selector.
            if registered
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &retired))
            {
                registered.take();
            }
        }
        permit
    }

    /// Register `selector` as the generation that must be released before the
    /// next rebuild can start.
    ///
    /// The caller must hold the permit returned by [`Self::acquire`] and call
    /// this before dropping it. Otherwise another rebuild could acquire the
    /// gate without observing the retired selector's release signal.
    fn retire<S>(&self, selector: &Arc<PublishedSelector<S>>) {
        let release_signal = selector.release_signal();
        *self
            .retired
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(release_signal);
    }
}

/// A collection of eventually consistent load-balancing selectors that share
/// one backend pool.
///
/// Discovery membership and readiness are published independently from
/// selector construction. Each selector continues serving its previous
/// generation while its replacement is built on a blocking worker. Pending
/// updates are coalesced so that at most one newer generation waits behind an
/// in-progress build or a shared rebuild gate. Selector builds and retired
/// generations are bounded by a [`SelectorRebuildGate`].
///
/// Each published selector owns the readiness snapshot for its generation, so a
/// removed backend stays selectable only through selectors still serving an
/// older generation. That readiness is released when the selector is replaced
/// and its last reader drops it; no separate pruning step is needed.
pub struct LoadBalancerGroup<S>
where
    S: BackendSelection,
{
    /// Backend membership and readiness shared by every selector.
    backends: Backends,
    /// Independently configured selectors and their rebuild state.
    selectors: Box<[Arc<SelectorSlot<S>>]>,
    /// Limits selector builds and waits for retired selectors to be released.
    rebuild_gate: Arc<SelectorRebuildGate>,
    /// Wakes startup readiness checks when a selector rebuild changes state.
    rebuild_notify: Arc<Notify>,
    /// Stops selector rebuild tasks when the group is dropped.
    rebuild_cancellation: Arc<SelectorRebuildCancellation>,

    /// Timing information from the most recent [`update`](Self::update) call.
    ///
    /// `None` until the first successful update completes.
    last_update_timing: ArcSwap<Option<UpdateTimings>>,

    /// How frequently the health check logic (if set) should run.
    ///
    /// If `None`, the health check logic will only run once at the beginning.
    /// This setting is ignored for views created with
    /// [`BackendView::new_with_health_registry`]; use [`HealthCheckService`]
    /// for those views.
    pub health_check_frequency: Option<Duration>,
    /// How frequently service discovery should run.
    ///
    /// If `None`, service discovery will only run once at the beginning.
    pub update_frequency: Option<Duration>,
    /// Whether to run health checks for all backends in parallel. Default is false.
    pub parallel_health_check: bool,
}

fn lock_rebuild_state(state: &Mutex<SelectorRebuildState>) -> MutexGuard<'_, SelectorRebuildState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Initial delay before retrying a failed selector rebuild.
///
/// Failed builds (e.g. a panicking selector constructor) are retried so a
/// transient failure cannot strand a selector at a stale generation when
/// discovery membership does not change again. The delay backs off
/// exponentially up to [`MAX_SELECTOR_REBUILD_BACKOFF`] to bound retries and
/// avoid a hot loop when a build fails persistently.
const INITIAL_SELECTOR_REBUILD_BACKOFF: Duration = Duration::from_millis(10);
/// Upper bound for the retry delay after repeated selector rebuild failures.
const MAX_SELECTOR_REBUILD_BACKOFF: Duration = Duration::from_secs(1);

async fn run_selector_rebuilds<S>(
    slot: Arc<SelectorSlot<S>>,
    rebuild_gate: Arc<SelectorRebuildGate>,
    rebuild_notify: Arc<Notify>,
    rebuild_cancellation: Arc<SelectorRebuildCancellation>,
) where
    S: BackendSelection + Send + Sync + 'static,
    S::Config: 'static,
{
    // This future can be dropped at any await. The guard restores an in-flight
    // request and clears `running` so a later rebuild can start a new worker.
    let mut task_guard =
        SelectorRebuildTaskGuard::new(Arc::clone(&slot), Arc::clone(&rebuild_notify));
    let mut backoff = INITIAL_SELECTOR_REBUILD_BACKOFF;
    loop {
        if rebuild_cancellation.is_cancelled() {
            // rebuild cancelled already, exit
            return;
        }
        {
            let mut rebuild_state = lock_rebuild_state(&slot.rebuild_state);
            if rebuild_state.pending_request.is_none() {
                // nothing to do, exit
                rebuild_state.is_running = false;
                task_guard.disarm();
                return;
            }
        }

        let permit = tokio::select! {
            // wait for exclusive rebuild access and for readers to release the retired selector
            permit = rebuild_gate.acquire() => permit,
            _ = rebuild_cancellation.wait_for_cancel() => return, // cancelled
        };

        let Some(request) = lock_rebuild_state(&slot.rebuild_state)
            .pending_request
            .take()
        else {
            // another worker took the job already
            drop(permit);
            continue;
        };
        // consume the wakeup associated with the request now being processed
        // so we do not incorrectly interrupt a later retry
        let _ = slot.interrupt_retry.notified().now_or_never();
        let build_start = Instant::now();
        let queue_duration = build_start.saturating_duration_since(request.requested_at);
        let generation = request.generation;
        let requested_at = request.requested_at;
        let backends = Arc::clone(&request.backends);
        let readiness = request.readiness.clone();
        task_guard.in_flight = Some(request);
        let build_backends = Arc::clone(&backends);
        let build_slot = Arc::clone(&slot);
        let result = tokio::task::spawn_blocking(move || {
            build_selector::<S>(&build_backends, build_slot.config.as_ref())
        })
        .await;
        let build_duration = build_start.elapsed();

        if rebuild_cancellation.is_cancelled() {
            // cancelled during construction
            if let Ok(selector) = result {
                let _drop_task = tokio::task::spawn_blocking(move || {
                    drop(selector);
                    drop(permit);
                });
            } else {
                drop(permit);
            }
            return;
        }

        match result {
            Ok(selector) => {
                let retired = slot
                    .selector
                    .swap(Arc::new(PublishedSelector::new(selector, readiness)));
                // Track the replaced selector until all readers release it.
                rebuild_gate.retire(&retired);
                let _drop_task = tokio::task::spawn_blocking(move || drop(retired));
                slot.last_update_timing
                    .store(Arc::new(Some(SelectorUpdateTimings {
                        generation,
                        queue_duration,
                        build_duration,
                    })));
                slot.generation.store(generation, Release);
                task_guard.in_flight = None;
                backoff = INITIAL_SELECTOR_REBUILD_BACKOFF;
                drop(permit);
                // notify load balancer group
                rebuild_notify.notify_one();
            }
            Err(error) => {
                slot.failed_rebuilds.fetch_add(1, Relaxed);
                if error.is_panic() {
                    log::error!(
                        "load-balancing selector rebuild panicked for generation {generation}: {error}"
                    );
                } else if error.is_cancelled() {
                    log::error!(
                        "load-balancing selector rebuild was cancelled for generation {generation}: {error}"
                    );
                } else {
                    log::error!(
                        "load-balancing selector rebuild failed for generation {generation}: {error}"
                    );
                }
                // Reschedule this generation unless a newer request already
                // superseded it, then release the gate and retry after a
                // bounded backoff so the selector can still converge even when
                // discovery membership does not change again.
                let retry_failed_generation = {
                    let mut state = lock_rebuild_state(&slot.rebuild_state);
                    if state
                        .pending_request
                        .as_ref()
                        .is_some_and(|pending| pending.generation > generation)
                    {
                        false
                    } else {
                        state.pending_request = Some(SelectorRebuildRequest {
                            generation,
                            backends,
                            readiness,
                            requested_at,
                        });
                        true
                    }
                };
                task_guard.in_flight = None;
                drop(permit);
                if retry_failed_generation {
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {
                            // The failed generation still needs retrying; increase
                            // the delay if its next attempt also fails.
                            backoff = (backoff * 2).min(MAX_SELECTOR_REBUILD_BACKOFF);
                        }
                        _ = slot.interrupt_retry.notified() => {
                            // A newer generation is pending, so process it now
                            // instead of waiting on the older failure's backoff.
                            backoff = INITIAL_SELECTOR_REBUILD_BACKOFF;
                        }
                        // The group was dropped while this worker was waiting.
                        _ = rebuild_cancellation.wait_for_cancel() => return,
                    }
                } else {
                    // Consume the notification associated with the pending newer
                    // generation so it cannot skip a later retry delay.
                    let _ = slot.interrupt_retry.notified().now_or_never();
                    backoff = INITIAL_SELECTOR_REBUILD_BACKOFF;
                }
            }
        }
    }
}

impl<S> LoadBalancerGroup<S>
where
    S: BackendSelection + Send + Sync + 'static,
    S::Config: 'static,
    S::Iter: BackendIter,
{
    /// Build a group of selectors over one shared backend pool.
    ///
    /// Each item in `configs` creates one selector. `None` uses
    /// [`BackendSelection::build`], while `Some(config)` uses
    /// [`BackendSelection::build_with_config`].
    ///
    /// # Panics
    ///
    /// Panics if `backends` has already been updated. A group owns backend
    /// updates and must start with selector generation zero.
    pub fn from_backends_with_configs(
        backends: Backends,
        configs: impl IntoIterator<Item = Option<S::Config>>,
    ) -> Self {
        assert_eq!(
            backends.generation(),
            0,
            "backends must not be updated before constructing a load balancer group"
        );
        let current_backends = backends.get_backend();
        let current_readiness = backends.readiness_snapshot();
        let selectors = configs
            .into_iter()
            .map(|config| {
                Arc::new(SelectorSlot {
                    selector: ArcSwap::new(Arc::new(PublishedSelector::new(
                        build_selector::<S>(&current_backends, config.as_ref()),
                        current_readiness.clone(),
                    ))),
                    config,
                    generation: AtomicU64::new(0),
                    rebuild_state: Mutex::new(SelectorRebuildState::default()),
                    last_update_timing: ArcSwap::new(Arc::new(None)),
                    coalesced_rebuilds: AtomicU64::new(0),
                    failed_rebuilds: AtomicU64::new(0),
                    interrupt_retry: Notify::new(),
                })
            })
            .collect();

        Self {
            backends,
            selectors,
            rebuild_gate: Arc::new(SelectorRebuildGate::new()),
            rebuild_notify: Arc::new(Notify::new()),
            rebuild_cancellation: Arc::new(SelectorRebuildCancellation::new()),
            last_update_timing: ArcSwap::new(Arc::new(None)),
            health_check_frequency: None,
            update_frequency: None,
            parallel_health_check: false,
        }
    }

    /// Use a rebuild gate shared with other selector groups.
    ///
    /// A group uses a private serial gate by default. Supplying the same gate
    /// to multiple groups extends the one-extra-generation memory bound across
    /// all of them.
    pub fn with_rebuild_gate(mut self, rebuild_gate: Arc<SelectorRebuildGate>) -> Self {
        self.rebuild_gate = rebuild_gate;
        self
    }

    /// Return the number of selectors in this group.
    pub fn selector_count(&self) -> usize {
        self.selectors.len()
    }

    fn schedule_selector_rebuild(
        &self,
        slot: &Arc<SelectorSlot<S>>,
        update: &BackendUpdate,
        requested_at: Instant,
    ) {
        let should_spawn = {
            let mut rebuild_state = lock_rebuild_state(&slot.rebuild_state);
            // update selector rebuild request if another one happens while we were already pending
            if rebuild_state
                .pending_request
                .replace(SelectorRebuildRequest {
                    generation: update.generation,
                    backends: Arc::clone(&update.backends),
                    readiness: update.readiness.clone(),
                    requested_at,
                })
                .is_some()
            {
                slot.coalesced_rebuilds.fetch_add(1, Relaxed);
            }

            if rebuild_state.is_running {
                // already spawned and running
                false
            } else {
                // spawn it
                rebuild_state.is_running = true;
                true
            }
        };

        if should_spawn {
            let task = run_selector_rebuilds(
                Arc::clone(slot),
                Arc::clone(&self.rebuild_gate),
                Arc::clone(&self.rebuild_notify),
                Arc::clone(&self.rebuild_cancellation),
            );
            let _rebuild_task = tokio::spawn(task);
        } else {
            slot.interrupt_retry.notify_one();
        }
    }

    /// Run service discovery and enqueue selector rebuilds when membership changes.
    ///
    /// The discovered backend membership is published before this method returns.
    /// Selector rebuilds run asynchronously. A removed backend stays selectable
    /// through selectors still serving an older generation, via the readiness
    /// snapshot each of those selectors owns.
    ///
    /// To wait for convergence, read [`backend_generation`](Self::backend_generation)
    /// after this call and poll [`selectors_ready_for`](Self::selectors_ready_for).
    /// Calls on the same group must not overlap. [`Self::run`] serializes them.
    pub async fn update(&self) -> Result<()> {
        let start = Instant::now();
        let changed = self.backends.update_backends().await?;
        let discovery_duration = start.elapsed();

        if let Some(update) = changed {
            for slot in &self.selectors {
                self.schedule_selector_rebuild(slot, &update, Instant::now());
            }
        }

        self.last_update_timing.store(Arc::new(Some(UpdateTimings {
            discovery_duration,
            // Selector builds continue asynchronously and report their own timing.
            build_duration: Duration::ZERO,
        })));

        Ok(())
    }

    /// Return the first healthy backend from the selected load-balancing configuration.
    ///
    /// Returns `None` when `selector_index` is out of bounds.
    pub fn select(
        &self,
        selector_index: usize,
        key: &[u8],
        max_iterations: usize,
    ) -> Option<Backend> {
        self.select_with(selector_index, key, max_iterations, |_, health| health)
    }

    /// Select a backend using one selector and an additional acceptance function.
    ///
    /// Each selector consults the readiness snapshot published with it, so a
    /// selector serving an older generation keeps using that generation's
    /// readiness. Returns `None` when `selector_index` is out of bounds.
    pub fn select_with<F>(
        &self,
        selector_index: usize,
        key: &[u8],
        max_iterations: usize,
        accept: F,
    ) -> Option<Backend>
    where
        F: Fn(&Backend, bool) -> bool,
    {
        // `published` is an `ArcSwap` guard held for the whole selection so the
        // selector data and its matching readiness snapshot share one snapshot
        // without a per-request `Arc` clone.
        //
        // Declaration order matters for the release invariant: `published` is
        // declared before `iter`, so `iter` (and the per-iteration `Arc<S>`
        // clone it holds) is dropped before the guard. The guard's drop can
        // destroy the retired selector and fire its release signal, so release
        // must not be signaled while an iterator still references the selector.
        let published = self.selectors.get(selector_index)?.selector.load();
        let mut iter = UniqueIterator::new(published.selector.iter(key), max_iterations);
        while let Some(backend) = iter.get_next() {
            if accept(&backend, published.readiness.ready(&backend)) {
                return Some(backend);
            }
        }
        None
    }

    /// Set the health check implementation shared by every selector.
    pub fn set_health_check(
        &mut self,
        hc: Box<dyn health_check::HealthCheck + Send + Sync + 'static>,
    ) {
        self.backends.set_health_check(hc);
    }

    /// Access the shared backend pool.
    pub fn backends(&self) -> &Backends {
        &self.backends
    }

    /// Return the latest backend membership generation.
    pub fn backend_generation(&self) -> u64 {
        self.backends.generation()
    }

    /// Return the generation currently served by one selector.
    pub fn selector_generation(&self, selector_index: usize) -> Option<u64> {
        self.selectors
            .get(selector_index)
            .map(|slot| slot.generation.load(Acquire))
    }

    /// Return whether every selector serves at least `generation`.
    pub fn selectors_ready_for(&self, generation: u64) -> bool {
        self.selectors
            .iter()
            .all(|slot| slot.generation.load(Acquire) >= generation)
    }

    /// Return timing information for the most recently published selector generation.
    pub fn selector_last_update_timing(
        &self,
        selector_index: usize,
    ) -> Option<SelectorUpdateTimings> {
        self.selectors
            .get(selector_index)
            .and_then(|slot| **slot.last_update_timing.load())
    }

    /// Return how many pending selector generations were replaced by a newer one.
    pub fn selector_coalesced_rebuilds(&self, selector_index: usize) -> Option<u64> {
        self.selectors
            .get(selector_index)
            .map(|slot| slot.coalesced_rebuilds.load(Relaxed))
    }

    /// Return how many selector rebuild tasks failed.
    pub fn selector_failed_rebuilds(&self, selector_index: usize) -> Option<u64> {
        self.selectors
            .get(selector_index)
            .map(|slot| slot.failed_rebuilds.load(Relaxed))
    }

    /// Wait for a selector rebuild to complete or terminate unexpectedly.
    pub(crate) fn rebuild_notified(&self) -> impl Future<Output = ()> + '_ {
        self.rebuild_notify.notified()
    }

    /// Return timing information from the most recent successful [`update`](Self::update).
    pub fn last_update_timing(&self) -> Option<UpdateTimings> {
        **self.last_update_timing.load()
    }
}

impl<S> Drop for LoadBalancerGroup<S>
where
    S: BackendSelection,
{
    fn drop(&mut self) {
        self.rebuild_cancellation.cancel();
    }
}
