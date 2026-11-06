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

//! Implement [BackgroundService] for [LoadBalancer]

use std::future::Future;
use std::time::{Duration, Instant};

use super::{BackendIter, BackendSelection, HealthCheckService, LoadBalancer, LoadBalancerGroup};
use async_trait::async_trait;
use pingora_core::{
    server::ShutdownWatch,
    services::{background::BackgroundService, ServiceReadyNotifier},
};

/// Why a [`ShutdownWatch`] woke a service loop.
enum WatchChange {
    /// Shutdown was signaled.
    ShuttingDown,
    /// The watch changed to a non-shutdown value. Nothing needs to stop.
    Spurious,
    /// Every sender was dropped, so shutdown can never be signaled from here.
    ///
    /// Distinct from [`WatchChange::ShuttingDown`] on purpose. Treating a
    /// dropped sender as shutdown would make a service abandon work that
    /// nothing is ever going to ask it to stop doing.
    Closed,
}

/// Await the next change to `shutdown` and classify it.
async fn shutdown_changed(shutdown: &mut ShutdownWatch) -> WatchChange {
    match shutdown.changed().await {
        // Read the latest value rather than the one that triggered the change,
        // so a `false` immediately followed by a `true` still stops the service.
        Ok(()) if *shutdown.borrow() => WatchChange::ShuttingDown,
        Ok(()) => WatchChange::Spurious,
        Err(_) => WatchChange::Closed,
    }
}

/// The outcome of racing a unit of background work against shutdown.
///
/// Returned by [`race_shutdown`]. Matching this exhaustively keeps each service
/// loop explicit about both outcomes.
enum Raced<T> {
    /// The work ran to completion, yielding its output.
    Completed(T),
    /// Shutdown was signaled. The work was dropped mid-flight and the service
    /// loop should return.
    ShuttingDown,
}

/// Run `work`, returning early if shutdown is signaled.
///
/// Shutdown is polled first, but [`tokio::sync::watch::Receiver::changed`] only
/// reports versions this receiver has not already seen, so callers must check
/// `*shutdown.borrow()` themselves as well.
///
/// A shutdown drops `work` mid-flight, cancelling an in-flight discovery or
/// health check. Any other outcome resumes the *same* `work` future rather than
/// restarting it, so repeated watch changes can neither starve it nor repeat
/// effects it already applied.
async fn race_shutdown<F: Future>(shutdown: &mut ShutdownWatch, work: F) -> Raced<F::Output> {
    tokio::pin!(work);
    loop {
        tokio::select! {
            biased;
            change = shutdown_changed(&mut *shutdown) => match change {
                WatchChange::ShuttingDown => return Raced::ShuttingDown,
                WatchChange::Spurious => continue,
                // Nothing can signal shutdown any more, so stop racing
                // altogether and let the work finish.
                WatchChange::Closed => break,
            },
            output = &mut work => return Raced::Completed(output),
        }
    }
    Raced::Completed(work.await)
}

/// Timing state shared by update and health-check loops.
struct TaskSchedule {
    frequency: Option<Duration>,
    next: Option<Instant>,
}

/// The independently optional tasks run by a background service.
struct BackgroundSchedule {
    update: Option<TaskSchedule>,
    health_check: Option<TaskSchedule>,
}

impl TaskSchedule {
    fn new(frequency: Option<Duration>, now: Instant) -> Self {
        Self {
            frequency,
            next: Some(now),
        }
    }

    fn is_due(&self, now: Instant) -> bool {
        self.next.is_some_and(|next| next <= now)
    }

    fn finished_at(&mut self, base: Instant) {
        self.next = self.frequency.map(|frequency| base + frequency);
    }

    fn next(&self) -> Option<Instant> {
        self.next
    }

    fn is_once(&self) -> bool {
        self.frequency.is_none()
    }
}

impl BackgroundSchedule {
    // 136 years, used when no scheduled work remains but another event can wake the service.
    const NEVER: Duration = Duration::from_secs(u32::MAX as u64);

    fn new(
        update_frequency: Option<Option<Duration>>,
        health_check_frequency: Option<Option<Duration>>,
        now: Instant,
    ) -> Self {
        Self {
            update: update_frequency.map(|frequency| TaskSchedule::new(frequency, now)),
            health_check: health_check_frequency.map(|frequency| TaskSchedule::new(frequency, now)),
        }
    }

    fn update_is_due(&self, now: Instant) -> bool {
        self.update
            .as_ref()
            .is_some_and(|schedule| schedule.is_due(now))
    }

    fn health_check_is_due(&self, now: Instant) -> bool {
        self.health_check
            .as_ref()
            .is_some_and(|schedule| schedule.is_due(now))
    }

    fn update_finished_at(&mut self, base: Instant) {
        if let Some(schedule) = self.update.as_mut() {
            schedule.finished_at(base);
        }
    }

    fn health_check_finished_at(&mut self, base: Instant) {
        if let Some(schedule) = self.health_check.as_mut() {
            schedule.finished_at(base);
        }
    }

    fn next_scheduled(&self) -> Option<Instant> {
        self.update
            .iter()
            .chain(self.health_check.iter())
            .filter_map(TaskSchedule::next)
            .min()
    }

    fn next(&self, now: Instant) -> Instant {
        self.next_scheduled().unwrap_or(now + Self::NEVER)
    }

    fn next_health_check(&self) -> Option<Instant> {
        self.health_check.as_ref().and_then(TaskSchedule::next)
    }

    fn health_check_is_once(&self) -> bool {
        self.health_check
            .as_ref()
            .is_some_and(TaskSchedule::is_once)
    }

    fn is_idle(&self) -> bool {
        self.next_scheduled().is_none()
    }
}

impl<S: Send + Sync + BackendSelection + 'static> LoadBalancer<S>
where
    S::Iter: BackendIter,
{
    pub async fn run(
        &self,
        mut shutdown: ShutdownWatch,
        mut ready_opt: Option<ServiceReadyNotifier>,
    ) -> () {
        let mut now = Instant::now();
        let mut schedule = BackgroundSchedule::new(
            Some(self.update_frequency),
            // Private views schedule probes here. Shared views are probed once by
            // their registry's HealthCheckService.
            self.backends
                .owns_health_checks()
                .then_some(self.health_check_frequency),
            now,
        );
        loop {
            if *shutdown.borrow() {
                return;
            }

            if schedule.update_is_due(now) {
                // TODO: log err
                match race_shutdown(&mut shutdown, self.update()).await {
                    Raced::ShuttingDown => return,
                    Raced::Completed(_) => schedule.update_finished_at(now),
                }
            }

            // After the first update, discovery and selection setup will be
            // done, so dependent services can start receiving traffic.
            if let Some(ready) = ready_opt.take() {
                ServiceReadyNotifier::notify_ready(ready)
            }

            if schedule.health_check_is_due(now) {
                let health_check = self.backends.run_health_check(self.parallel_health_check);
                match race_shutdown(&mut shutdown, health_check).await {
                    Raced::ShuttingDown => return,
                    Raced::Completed(()) => schedule.health_check_finished_at(now),
                }
            }

            if schedule.is_idle() {
                return;
            }
            let to_wake = schedule.next(now);
            match race_shutdown(&mut shutdown, tokio::time::sleep_until(to_wake.into())).await {
                Raced::ShuttingDown => return,
                Raced::Completed(()) => {}
            }
            now = Instant::now();
        }
    }
}

/// Implement [BackgroundService] for [LoadBalancer]. For backward-compatibility
/// reasons, we implement both the `start` and `start_with_ready_notifier`
/// methods.
#[async_trait]
impl<S: Send + Sync + BackendSelection + 'static> BackgroundService for LoadBalancer<S>
where
    S::Iter: BackendIter,
{
    async fn start_with_ready_notifier(
        &self,
        shutdown: pingora_core::server::ShutdownWatch,
        ready: ServiceReadyNotifier,
    ) -> () {
        self.run(shutdown, Some(ready)).await
    }

    async fn start(&self, shutdown: pingora_core::server::ShutdownWatch) -> () {
        self.run(shutdown, None).await
    }
}

impl<S: Send + Sync + BackendSelection + 'static> LoadBalancerGroup<S>
where
    S::Config: 'static,
    S::Iter: BackendIter,
{
    /// Run discovery, selector rebuilds, and privately managed health checks
    /// until shutdown.
    pub async fn run(
        &self,
        mut shutdown: pingora_core::server::ShutdownWatch,
        mut ready_opt: Option<ServiceReadyNotifier>,
    ) {
        let mut now = Instant::now();
        let mut schedule = BackgroundSchedule::new(
            Some(self.update_frequency),
            // Private groups schedule probes here. Shared groups only consume the
            // health state maintained by their registry's HealthCheckService.
            self.backends()
                .owns_health_checks()
                .then_some(self.health_check_frequency),
            now,
        );
        let mut ready_generation = None;

        loop {
            if *shutdown.borrow() {
                return;
            }

            if schedule.update_is_due(now) {
                match race_shutdown(&mut shutdown, self.update()).await {
                    Raced::ShuttingDown => return,
                    Raced::Completed(Ok(())) => {
                        // Until readiness is signaled, always target the latest
                        // backend generation. Pinning to the first successful
                        // update would let a burst of updates satisfy readiness
                        // with selectors that are already stale relative to the
                        // current membership.
                        if ready_opt.is_some() {
                            ready_generation = Some(self.backend_generation());
                        }
                        schedule.update_finished_at(now);
                    }
                    Raced::Completed(Err(error)) => {
                        log::error!("load balancer group update failed: {error}");
                        schedule.update_finished_at(now);
                    }
                }
            }

            if ready_generation.is_some_and(|generation| self.selectors_ready_for(generation)) {
                if let Some(ready) = ready_opt.take() {
                    // Every selector reached the target generation, so dependent
                    // services can start receiving traffic.
                    ServiceReadyNotifier::notify_ready(ready)
                }
            }

            if schedule.health_check_is_due(now) {
                let health_check = self.backends().run_health_check(self.parallel_health_check);
                match race_shutdown(&mut shutdown, health_check).await {
                    Raced::ShuttingDown => return,
                    Raced::Completed(()) => schedule.health_check_finished_at(now),
                }
            }

            // Discovery and health checks have independent schedules. One-shot
            // discovery can still feed recurring checks over its last membership.
            if ready_opt.is_none() && schedule.is_idle() {
                // No readiness notification or periodic work remains.
                // Any queued selector rebuilds finish independently.
                return;
            }

            let to_wake = schedule.next(now);
            // Selector completion may satisfy startup readiness before the next
            // scheduled task. After readiness, rebuilds no longer wake this loop.
            let wake = async {
                tokio::select! {
                    _ = tokio::time::sleep_until(to_wake.into()) => {}
                    _ = self.rebuild_notified(), if ready_opt.is_some() => {} // re-trigger loop to notify waiters
                }
            };
            match race_shutdown(&mut shutdown, wake).await {
                Raced::ShuttingDown => return,
                Raced::Completed(()) => {}
            }
            now = Instant::now();
        }
    }
}

#[async_trait]
impl<S: Send + Sync + BackendSelection + 'static> BackgroundService for LoadBalancerGroup<S>
where
    S::Config: 'static,
    S::Iter: BackendIter,
{
    async fn start_with_ready_notifier(
        &self,
        shutdown: pingora_core::server::ShutdownWatch,
        ready: ServiceReadyNotifier,
    ) {
        self.run(shutdown, Some(ready)).await
    }

    async fn start(&self, shutdown: pingora_core::server::ShutdownWatch) {
        self.run(shutdown, None).await
    }
}

impl HealthCheckService {
    /// Run health checks for the shared registry until shutdown.
    pub async fn run(
        &self,
        mut shutdown: pingora_core::server::ShutdownWatch,
        mut ready_opt: Option<ServiceReadyNotifier>,
    ) {
        if !self.registry.has_health_check() {
            log::error!("HealthCheckService requires a configured HealthRegistry health check");
            // Keep the notifier alive so dependents cannot observe a false-ready
            // signal from its Drop implementation. A non-shutdown change must
            // not release it early; a closed watch has no server left to
            // mislead, so parking on it would only leak this task.
            if ready_opt.is_some() && !*shutdown.borrow() {
                while let WatchChange::Spurious = shutdown_changed(&mut shutdown).await {}
            }
            return;
        }

        let mut schedule =
            BackgroundSchedule::new(None, Some(self.health_check_frequency), Instant::now());
        loop {
            if *shutdown.borrow() {
                return;
            }

            // One-shot mode (no frequency) runs a single pass and returns, so it
            // must observe at least one target first. Otherwise it would check
            // an empty registry, signal ready, and never look at targets
            // published afterwards. Periodic mode instead signals ready eagerly
            // and relies on later passes to pick up newly published targets.
            if schedule.health_check_is_once() && self.registry.target_count() == 0 {
                match race_shutdown(&mut shutdown, self.registry.wait_for_targets()).await {
                    Raced::ShuttingDown => return,
                    Raced::Completed(()) => {}
                }
                // A shutdown already observed by an earlier `changed()` will not
                // wake the race above, so re-check the current value before
                // starting a pass.
                if *shutdown.borrow() {
                    return;
                }
            }

            let health_check = self.registry.run_health_check(self.parallel_health_check);
            match race_shutdown(&mut shutdown, health_check).await {
                Raced::ShuttingDown => return,
                Raced::Completed(()) => {
                    if let Some(ready) = ready_opt.take() {
                        // The initial health pass completed, so services depending on
                        // this registry can start receiving traffic.
                        ServiceReadyNotifier::notify_ready(ready);
                    }
                    schedule.health_check_finished_at(Instant::now());
                }
            }

            let Some(next_health_check) = schedule.next_health_check() else {
                // no more checks
                return;
            };
            loop {
                let has_targets = self.registry.target_count() > 0;
                // `true` means the next pass is due; a view removal only
                // re-evaluates whether the registry still has targets.
                let wake = async {
                    tokio::select! {
                        _ = self.registry.wait_for_targets(), if !has_targets => true,
                        _ = tokio::time::sleep_until(next_health_check.into()), if has_targets => true,
                        _ = self.registry.wait_for_view_removal() => false,
                    }
                };
                match race_shutdown(&mut shutdown, wake).await {
                    Raced::ShuttingDown => return,
                    Raced::Completed(true) => break,
                    Raced::Completed(false) => {}
                }
            }
        }
    }
}

#[async_trait]
impl BackgroundService for HealthCheckService {
    async fn start_with_ready_notifier(
        &self,
        shutdown: pingora_core::server::ShutdownWatch,
        ready: ServiceReadyNotifier,
    ) {
        self.run(shutdown, Some(ready)).await
    }

    async fn start(&self, shutdown: pingora_core::server::ShutdownWatch) {
        self.run(shutdown, None).await
    }
}
