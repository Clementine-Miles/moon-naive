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

//! The service interface
//!
//! A service to the pingora server is just something runs forever until the server is shutting
//! down.
//!
//! Two types of services are particularly useful
//! - services that are listening to some (TCP) endpoints
//! - services that are just running in the background.

use async_trait::async_trait;
use daggy::Walker;
use daggy::{petgraph::visit::Topo, Dag, NodeIndex};
use log::{error, info, warn};
use parking_lot::Mutex;
use std::borrow::Borrow;
use std::sync::Arc;
use std::sync::Weak;
use std::time::Duration;
use tokio::sync::watch;

#[cfg(unix)]
use crate::server::ListenFds;
use crate::server::RuntimeOpts;
use crate::server::ShutdownWatch;

pub mod background;
pub mod listening;

/// A notification channel for signaling when a service has become ready.
///
/// Services can use this to notify other services that may depend on them
/// that they have successfully started and are ready to serve requests.
///
/// # Example
///
/// ```rust,ignore
/// use pingora_core::services::ServiceReadyNotifier;
///
/// async fn my_service(ready_notifier: ServiceReadyNotifier) {
///     // Perform initialization...
///
///     // Signal that the service is ready
///     ready_notifier.notify_ready();
///
///     // Continue with main service loop...
/// }
/// ```
pub struct ServiceReadyNotifier {
    sender: watch::Sender<bool>,
}

impl Drop for ServiceReadyNotifier {
    /// In the event that the notifier is dropped before notifying that the
    /// service is ready, we opt to signal ready anyway
    fn drop(&mut self) {
        // Ignore errors - if there are no receivers, that's fine
        let _ = self.sender.send(true);
    }
}

impl ServiceReadyNotifier {
    /// Creates a new ServiceReadyNotifier from a watch sender.
    /// You will not need to create one of these for normal usage, but being
    /// able to is useful for testing.
    pub fn new(sender: watch::Sender<bool>) -> Self {
        Self { sender }
    }

    /// Notifies dependent services that this service is ready.
    ///
    /// Consumes the notifier to ensure ready is only signaled once.
    pub fn notify_ready(self) {
        // Dropping the notifier will signal that the service is ready
        drop(self);
    }
}

/// A receiver for watching when a service becomes ready.
pub type ServiceReadyWatch = watch::Receiver<bool>;

/// A handle to a service in the server.
///
/// This is returned by [`crate::server::Server::add_service()`] and provides
/// methods to declare that other services depend on this one.
///
/// # Example
///
/// ```rust,ignore
/// let db_handle = server.add_service(database_service);
/// let cache_handle = server.add_service(cache_service);
///
/// let api_handle = server.add_service(api_service);
/// api_handle.add_dependency(&db_handle);
/// api_handle.add_dependency(&cache_handle);
/// ```
#[derive(Debug, Clone)]
pub struct ServiceHandle {
    pub(crate) id: NodeIndex,
    name: String,
    ready_watch: ServiceReadyWatch,
    dependencies: Weak<Mutex<DependencyGraph>>,
}

/// Internal representation of a dependency relationship.
#[derive(Debug, Clone)]
pub(crate) struct ServiceDependency {
    pub name: String,
    pub ready_watch: ServiceReadyWatch,
}

impl ServiceHandle {
    /// Creates a new ServiceHandle with the given ID, name, and readiness watcher.
    pub(crate) fn new(
        id: NodeIndex,
        name: String,
        ready_watch: ServiceReadyWatch,
        dependencies: &Arc<Mutex<DependencyGraph>>,
    ) -> Self {
        Self {
            id,
            name,
            ready_watch,
            dependencies: Arc::downgrade(dependencies),
        }
    }



    /// Returns the name of the service.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a clone of the readiness watcher for this service.
    #[allow(dead_code)]
    pub(crate) fn ready_watch(&self) -> ServiceReadyWatch {
        self.ready_watch.clone()
    }

    /// Declares that this service depends on another service.
    ///
    /// This service will not start until the specified dependency has started
    /// and signaled readiness.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let db_id = server.add_service(database_service);
    /// let api_id = server.add_service(api_service);
    ///
    /// // API service depends on database
    /// api_id.add_dependency(&db_id);
    /// ```
    pub fn add_dependency(&self, dependency: impl Borrow<ServiceHandle>) {
        let Some(deps_lock) = self.dependencies.upgrade() else {
            warn!("Attempted to add a dependency after the dependency tree was dropped");
            return;
        };

        let mut deps = deps_lock.lock();
        if let Err(e) = deps.add_dependency(self.id, dependency.borrow().id) {
            error!("Error creating dependency edge: {e}");
        }
    }

    /// Declares that this service depends on the given other services.
    ///
    /// This service will not start until the specified dependencies have
    /// started and signaled readiness.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let db_id = server.add_service(database_service);
    /// let cache_id = server.add_service(cache_service);
    /// let api_id = server.add_service(api_service);
    ///
    /// // API service depends on database
    /// api_id.add_dependencies(&[&db_id, &cache_id]);
    /// ```
    pub fn add_dependencies<'a, D>(&self, dependencies: impl IntoIterator<Item = D>)
    where
        D: Borrow<ServiceHandle> + 'a,
    {
        for dependency in dependencies {
            self.add_dependency(dependency);
        }
    }
}

/// Helper for validating service dependency graphs using daggy.
pub(crate) struct DependencyGraph {
    /// The directed acyclic graph structure from daggy.
    dag: Dag<ServiceDependency, ()>,
}

impl DependencyGraph {
    /// Creates a new dependency graph.
    pub(crate) fn new() -> Self {
        Self { dag: Dag::new() }
    }

    /// Adds a service node to the graph.
    ///
    /// This should be called for all services first, before adding edges.
    pub(crate) fn add_node(&mut self, name: String, ready_watch: ServiceReadyWatch) -> NodeIndex {
        self.dag.add_node(ServiceDependency { name, ready_watch })
    }
    /// Adds a dependency edge from one service to another.
    ///
    /// Returns an error if adding this dependency would create a cycle or reference
    /// a non-existent service.
    pub(crate) fn add_dependency(
        &mut self,
        dependent_service_node_idx: NodeIndex,
        dependency_service_node_idx: NodeIndex,
    ) -> Result<(), String> {
        // Try to add edge (from dependency to dependent)
        // daggy will return an error if this would create a cycle
        if let Err(cycle) =
            self.dag
                .add_edge(dependency_service_node_idx, dependent_service_node_idx, ())
        {
            return Err(format!(
                "Circular service dependency detected between {} and {} creating cycle: {cycle}",
                self.dag[dependency_service_node_idx].name,
                self.dag[dependent_service_node_idx].name
            ));
        }

        Ok(())
    }

    /// Returns services in topological order (dependencies before dependents).
    ///
    /// This ordering ensures that services are started in the correct order.
    /// Returns service IDs in the correct startup order.
    pub(crate) fn topological_sort(&self) -> Result<Vec<(NodeIndex, ServiceDependency)>, String> {
        // Use daggy's built-in topological walker
        let mut sorted = Vec::new();
        let mut topo = Topo::new(&self.dag);

        while let Some(service_id) = topo.next(&self.dag) {
            sorted.push((service_id, self.dag[service_id].clone()));
        }

        Ok(sorted)
    }

    pub(crate) fn get_dependencies(&self, service_id: NodeIndex) -> Vec<ServiceDependency> {
        self.dag
            .parents(service_id)
            .iter(&self.dag)
            .map(|(_, n)| self.dag[n].clone())
            .collect()
    }
}

impl Default for DependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait ServiceWithDependents: Send + Sync {
    /// This function will be called when the server is ready to start the service.
    ///
    /// Override this method if you need to control exactly when the service signals readiness
    /// (e.g., after async initialization is complete).
    ///
    /// # Arguments
    ///
    /// - `fds` (Unix only): a collection of listening file descriptors. During zero downtime restart
    ///   the `fds` would contain the listening sockets passed from the old service, services should
    ///   take the sockets they need to use then. If the sockets the service looks for don't appear in
    ///   the collection, the service should create its own listening sockets and then put them into
    ///   the collection in order for them to be passed to the next server.
    /// - `shutdown`: the shutdown signal this server would receive.
    /// - `listeners_per_fd`: number of listener tasks to spawn per file descriptor.
    /// - `ready_notifier`: notifier to signal when the service is ready. Services with
    ///   dependents should call `ready_notifier.notify_ready()` once they are fully initialized.
    async fn start_service(
        &mut self,
        #[cfg(unix)] fds: Option<ListenFds>,
        shutdown: ShutdownWatch,
        listeners_per_fd: usize,
        ready_notifier: ServiceReadyNotifier,
    );

    /// The name of the service, just for logging and naming the threads assigned to this service
    ///
    /// Note that due to the limit of the underlying system, only the first 16 chars will be used
    fn name(&self) -> &str;

    /// The preferred number of threads to run this service
    ///
    /// If `None`, the global setting will be used
    fn threads(&self) -> Option<usize> {
        None
    }

    /// Override the runtime options for this service.
    ///
    /// Returning [`None`] uses the global runtime options derived from
    /// [`ServerConf`](crate::server::configuration::ServerConf).
    fn runtime_opts_override(&self, global: &RuntimeOpts) -> Option<RuntimeOpts> {
        let _ = global;
        None
    }

    /// This is currently called to inform the service about the delay it
    /// experienced from between waiting on its dependencies. Default behavior
    /// is to log the time.
    ///
    /// TODO. It would be nice if this function was called intermittently by
    /// the server while the service was waiting to give live updates while the
    /// service was waiting and allow the service to decide whether to keep
    /// waiting, continue anyway, or exit
    fn on_startup_delay(&self, time_waited: Duration) {
        info!(
            "Service {} spent {}ms waiting on dependencies",
            self.name(),
            time_waited.as_millis()
        );
    }

    /// See [`Service::listen_addresses`].
    fn listen_addresses(&self) -> Option<Vec<String>> {
        None
    }
}

#[async_trait]
impl<S> ServiceWithDependents for S
where
    S: Service,
{
    async fn start_service(
        &mut self,
        #[cfg(unix)] fds: Option<ListenFds>,
        shutdown: ShutdownWatch,
        listeners_per_fd: usize,
        ready_notifier: ServiceReadyNotifier,
    ) {
        // Signal ready immediately
        ready_notifier.notify_ready();

        S::start_service(
            self,
            #[cfg(unix)]
            fds,
            shutdown,
            listeners_per_fd,
        )
        .await
    }

    fn name(&self) -> &str {
        S::name(self)
    }

    fn threads(&self) -> Option<usize> {
        S::threads(self)
    }

    fn runtime_opts_override(&self, global: &RuntimeOpts) -> Option<RuntimeOpts> {
        S::runtime_opts_override(self, global)
    }

    fn on_startup_delay(&self, time_waited: Duration) {
        S::on_startup_delay(self, time_waited)
    }

    fn listen_addresses(&self) -> Option<Vec<String>> {
        S::listen_addresses(self)
    }
}

/// The service interface
#[async_trait]
pub trait Service: Sync + Send {
    /// Start the service without readiness notification.
    ///
    /// This is a simpler version of [`Self::start_service()`] for services that don't need
    /// to control when they signal readiness. The default implementation does nothing.
    ///
    /// Most services should override this method instead of [`Self::start_service()`].
    ///
    /// # Arguments
    ///
    /// - `fds` (Unix only): a collection of listening file descriptors.
    /// - `shutdown`: the shutdown signal this server would receive.
    /// - `listeners_per_fd`: number of listener tasks to spawn per file descriptor.
    async fn start_service(
        &mut self,
        #[cfg(unix)] _fds: Option<ListenFds>,
        _shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        // Default: do nothing
    }

    /// The name of the service, just for logging and naming the threads assigned to this service
    ///
    /// Note that due to the limit of the underlying system, only the first 16 chars will be used
    fn name(&self) -> &str;

    /// The preferred number of threads to run this service
    ///
    /// If `None`, the global setting will be used
    fn threads(&self) -> Option<usize> {
        None
    }

    /// Override the runtime options for this service.
    ///
    /// Returning [`None`] uses the global runtime options derived from
    /// [`ServerConf`](crate::server::configuration::ServerConf).
    fn runtime_opts_override(&self, global: &RuntimeOpts) -> Option<RuntimeOpts> {
        let _ = global;
        None
    }

    /// This is currently called to inform the service about the delay it
    /// experienced from between waiting on its dependencies. Default behavior
    /// is to log the time.
    ///
    /// TODO. It would be nice if this function was called intermittently by
    /// the server while the service was waiting to give live updates while the
    /// service was waiting and allow the service to decide whether to keep
    /// waiting, continue anyway, or exit
    fn on_startup_delay(&self, time_waited: Duration) {
        info!(
            "Service {} spent {}ms waiting on dependencies",
            self.name(),
            time_waited.as_millis()
        );
    }

    /// The bind addresses of the listening sockets this service owns.
    ///
    /// Addresses must match the keys used for transferred listening fds. Return [`None`] (the
    /// default) if the service may consume fds without declaring every key; this disables cleanup.
    fn listen_addresses(&self) -> Option<Vec<String>> {
        None
    }
}
