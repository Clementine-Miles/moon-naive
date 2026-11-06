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

//! Health Check interface and methods.

use crate::Backend;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::connectors::http::custom;
use pingora_core::connectors::{http::Connector as HttpConnector, TransportConnector};
use pingora_core::custom_session;
use pingora_core::protocols::http::custom::client::Session;
use pingora_core::upstreams::peer::{BasicPeer, HttpPeer, Peer};
use pingora_error::{Error, ErrorType::CustomCode, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use std::sync::Arc;
use std::time::Duration;

/// [HealthObserve] is an interface for observing health changes of backends,
/// this is what's used for our health observation callback.
#[async_trait]
pub trait HealthObserve {
    /// Observes the health of a [Backend], can be used for monitoring purposes.
    async fn observe(&self, target: &Backend, healthy: bool);
}
/// Provided to a [HealthCheck] to observe changes to [Backend] health.
pub type HealthObserveCallback = Box<dyn HealthObserve + Send + Sync>;

/// Provided to a [HealthCheck] to fetch [Backend] summary for detailed logging.
pub type BackendSummary = Box<dyn Fn(&Backend) -> String + Send + Sync>;

/// [HealthCheck] is the interface to implement health check for backends
#[async_trait]
pub trait HealthCheck {
    /// Check the given backend.
    ///
    /// `Ok(())`` if the check passes, otherwise the check fails.
    ///
    /// A health-check pass drops this future to cancel the check on shutdown,
    /// so an implementation must not rely on running to completion once polled.
    async fn check(&self, target: &Backend) -> Result<()>;

    /// Called when the health changes for a [Backend].
    async fn health_status_change(&self, _target: &Backend, _healthy: bool) {}

    /// Called when a detailed [Backend] summary is needed.
    fn backend_summary(&self, target: &Backend) -> String {
        format!("{target:?}")
    }

    /// This function defines how many *consecutive* checks should flip the health of a backend.
    ///
    /// For example: with `success``: `true`: this function should return the
    /// number of check need to flip from unhealthy to healthy.
    fn health_threshold(&self, success: bool) -> usize;
}

/// TCP health check
///
/// This health check checks if a TCP (or TLS) connection can be established to a given backend.
pub struct TcpHealthCheck {
    /// Number of successful checks to flip from unhealthy to healthy.
    pub consecutive_success: usize,
    /// Number of failed checks to flip from healthy to unhealthy.
    pub consecutive_failure: usize,
    /// How to connect to the backend.
    ///
    /// This field defines settings like the connect timeout and src IP to bind.
    /// The SocketAddr of `peer_template` is just a placeholder which will be replaced by the
    /// actual address of the backend when the health check runs.
    ///
    /// By default, this check will try to establish a TCP connection. When the `sni` field is
    /// set, it will also try to establish a TLS connection on top of the TCP connection.
    pub peer_template: BasicPeer,
    connector: TransportConnector,
    /// A callback that is invoked when the `healthy` status changes for a [Backend].
    pub health_changed_callback: Option<HealthObserveCallback>,
}

impl Default for TcpHealthCheck {
    fn default() -> Self {
        let mut peer_template = BasicPeer::new("0.0.0.0:1");
        peer_template.options.connection_timeout = Some(Duration::from_secs(1));
        TcpHealthCheck {
            consecutive_success: 1,
            consecutive_failure: 1,
            peer_template,
            connector: TransportConnector::new(None),
            health_changed_callback: None,
        }
    }
}

impl TcpHealthCheck {
    /// Create a new [TcpHealthCheck] with the following default values
    /// * connect timeout: 1 second
    /// * consecutive_success: 1
    /// * consecutive_failure: 1
    pub fn new() -> Box<Self> {
        Box::<TcpHealthCheck>::default()
    }

    /// Create a new [TcpHealthCheck] that tries to establish a TLS connection.
    ///
    /// The default values are the same as [Self::new()].
    pub fn new_tls(sni: &str) -> Box<Self> {
        let mut new = Self::default();
        new.peer_template.sni = sni.into();
        Box::new(new)
    }

    /// Replace the internal tcp connector with the given [TransportConnector]
    pub fn set_connector(&mut self, connector: TransportConnector) {
        self.connector = connector;
    }
}

#[async_trait]
impl HealthCheck for TcpHealthCheck {
    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    async fn check(&self, target: &Backend) -> Result<()> {
        let mut peer = self.peer_template.clone();
        peer._address = target.addr.clone();
        self.connector.get_stream(&peer).await.map(|_| {})
    }

    async fn health_status_change(&self, target: &Backend, healthy: bool) {
        if let Some(callback) = &self.health_changed_callback {
            callback.observe(target, healthy).await;
        }
    }
}

type Validator = Box<dyn Fn(&ResponseHeader) -> Result<()> + Send + Sync>;

/// HTTP health check
///
/// This health check checks if it can receive the expected HTTP(s) response from the given backend.
pub struct HttpHealthCheck<C = ()>
where
    C: custom::Connector,
{
    /// Number of successful checks to flip from unhealthy to healthy.
    pub consecutive_success: usize,
    /// Number of failed checks to flip from healthy to unhealthy.
    pub consecutive_failure: usize,
    /// How to connect to the backend.
    ///
    /// This field defines settings like the connect timeout and src IP to bind.
    /// The SocketAddr of `peer_template` is just a placeholder which will be replaced by the
    /// actual address of the backend when the health check runs.
    ///
    /// Set the `scheme` field to use HTTPs.
    pub peer_template: HttpPeer,
    /// Whether the underlying TCP/TLS connection can be reused across checks.
    ///
    /// * `false` will make sure that every health check goes through TCP (and TLS) handshakes.
    ///   Established connections sometimes hide the issue of firewalls and L4 LB.
    /// * `true` will try to reuse connections across checks, this is the more efficient and fast way
    ///   to perform health checks.
    pub reuse_connection: bool,
    /// The request header to send to the backend
    pub req: RequestHeader,
    connector: HttpConnector<C>,
    /// Optional field to define how to validate the response from the server.
    ///
    /// If not set, any response with a `200 OK` is considered a successful check.
    pub validator: Option<Validator>,
    /// Sometimes the health check endpoint lives one a different port than the actual backend.
    /// Setting this option allows the health check to perform on the given port of the backend IP.
    pub port_override: Option<u16>,
    /// A callback that is invoked when the `healthy` status changes for a [Backend].
    pub health_changed_callback: Option<HealthObserveCallback>,
    /// An optional callback for backend summary reporting.
    pub backend_summary_callback: Option<BackendSummary>,
}

impl HttpHealthCheck<()> {
    /// Create a new [HttpHealthCheck] with the following default settings
    /// * connect timeout: 1 second
    /// * read timeout: 1 second
    /// * req: a GET to the `/` of the given host name
    /// * consecutive_success: 1
    /// * consecutive_failure: 1
    /// * reuse_connection: false
    /// * validator: `None`, any 200 response is considered successful
    pub fn new(host: &str, tls: bool) -> Self {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.append_header("Host", host).unwrap();
        let sni = if tls { host.into() } else { String::new() };
        let mut peer_template = HttpPeer::new("0.0.0.0:1", tls, sni);
        peer_template.options.connection_timeout = Some(Duration::from_secs(1));
        peer_template.options.read_timeout = Some(Duration::from_secs(1));
        HttpHealthCheck {
            consecutive_success: 1,
            consecutive_failure: 1,
            peer_template,
            connector: HttpConnector::new(None),
            reuse_connection: false,
            req,
            validator: None,
            port_override: None,
            health_changed_callback: None,
            backend_summary_callback: None,
        }
    }
}

impl<C> HttpHealthCheck<C>
where
    C: custom::Connector,
{
    /// Create a new [HttpHealthCheck] with the following default settings
    /// * connect timeout: 1 second
    /// * read timeout: 1 second
    /// * req: a GET to the `/` of the given host name
    /// * consecutive_success: 1
    /// * consecutive_failure: 1
    /// * reuse_connection: false
    /// * validator: `None`, any 200 response is considered successful
    pub fn new_custom(host: &str, tls: bool, custom: HttpConnector<C>) -> Self {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.append_header("Host", host).unwrap();
        let sni = if tls { host.into() } else { String::new() };
        let mut peer_template = HttpPeer::new("0.0.0.0:1", tls, sni);
        peer_template.options.connection_timeout = Some(Duration::from_secs(1));
        peer_template.options.read_timeout = Some(Duration::from_secs(1));
        HttpHealthCheck {
            consecutive_success: 1,
            consecutive_failure: 1,
            peer_template,
            connector: custom,
            reuse_connection: false,
            req,
            validator: None,
            port_override: None,
            health_changed_callback: None,
            backend_summary_callback: None,
        }
    }

    /// Replace the internal http connector with the given [HttpConnector]
    pub fn set_connector(&mut self, connector: HttpConnector<C>) {
        self.connector = connector;
    }

    pub fn set_backend_summary<F>(&mut self, callback: F)
    where
        F: Fn(&Backend) -> String + Send + Sync + 'static,
    {
        self.backend_summary_callback = Some(Box::new(callback));
    }
}

#[async_trait]
impl<C> HealthCheck for HttpHealthCheck<C>
where
    C: custom::Connector,
{
    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    async fn check(&self, target: &Backend) -> Result<()> {
        let mut peer = self.peer_template.clone();
        peer._address = target.addr.clone();
        if let Some(port) = self.port_override {
            peer._address.set_port(port);
        }
        let session = self.connector.get_http_session(&peer).await?;

        let mut session = session.0;

        session.set_write_timeout(peer.options.write_timeout);

        let req = Box::new(self.req.clone());
        session.write_request_header(req).await?;
        session.finish_request_body().await?;

        custom_session!(session.finish_custom().await?);

        session.set_read_timeout(peer.options.read_timeout);

        session.read_response_header().await?;

        let resp = session.response_header().expect("just read");

        if let Some(validator) = self.validator.as_ref() {
            validator(resp)?;
        } else if resp.status != 200 {
            return Error::e_explain(
                CustomCode("non 200 code", resp.status.as_u16()),
                "during http healthcheck",
            );
        };

        while session.read_response_body().await?.is_some() {
            // drain the body if any
        }

        // TODO(slava): do it concurrently wtih body drain?
        custom_session!(session.drain_custom_messages().await?);

        if self.reuse_connection {
            let idle_timeout = peer.idle_timeout();
            self.connector
                .release_http_session(session, &peer, idle_timeout)
                .await;
        }

        Ok(())
    }
    async fn health_status_change(&self, target: &Backend, healthy: bool) {
        if let Some(callback) = &self.health_changed_callback {
            callback.observe(target, healthy).await;
        }
    }
    fn backend_summary(&self, target: &Backend) -> String {
        if let Some(callback) = &self.backend_summary_callback {
            callback(target)
        } else {
            format!("{target:?}")
        }
    }
}

#[derive(Clone)]
struct HealthInner {
    /// Whether the endpoint is healthy to serve traffic
    healthy: bool,
    /// The counter for stateful transition between healthy and unhealthy.
    /// When [healthy] is true, this counts the number of consecutive health check failures
    /// so that the caller can flip the healthy when a certain threshold is met, and vise versa.
    consecutive_counter: usize,
}

/// Health of backends that can be updated atomically.
///
/// Clones share the same state so registry reconciliation cannot lose a health
/// observation that completes concurrently.
#[derive(Clone)]
pub(crate) struct Health(Arc<ArcSwap<HealthInner>>);

impl Default for Health {
    fn default() -> Self {
        Health(Arc::new(ArcSwap::new(Arc::new(HealthInner {
            healthy: true, // TODO: allow to start with unhealthy
            consecutive_counter: 0,
        }))))
    }
}

impl Health {
    pub fn ready(&self) -> bool {
        self.0.load().healthy
    }

    // return true when the health is flipped
    pub fn observe_health(&self, health: bool, flip_threshold: usize) -> bool {
        let h = self.0.load();
        let mut flipped = false;
        if h.healthy != health {
            // opposite health observed, ready to increase the counter
            // clone the inner
            let mut new_health = (**h).clone();
            new_health.consecutive_counter += 1;
            if new_health.consecutive_counter >= flip_threshold {
                new_health.healthy = health;
                new_health.consecutive_counter = 0;
                flipped = true;
            }
            self.0.store(Arc::new(new_health));
        } else if h.consecutive_counter > 0 {
            // observing the same health as the current state.
            // reset the counter, if it is non-zero, because it is no longer consecutive
            let mut new_health = (**h).clone();
            new_health.consecutive_counter = 0;
            self.0.store(Arc::new(new_health));
        }
        flipped
    }
}
