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

//! Connecting to HTTP servers

use crate::connectors::http::custom::Connection;
use crate::connectors::ConnectorOptions;
use crate::listeners::ALPN;
use crate::protocols::http::client::HttpSession;
use crate::protocols::http::v1::client::HttpSession as Http1Session;
use crate::upstreams::peer::Peer;
use pingora_error::Result;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

pub mod custom;
pub mod v1;
pub mod v2;

pub struct Connector<C = ()>
where
    C: custom::Connector,
{
    h1: v1::Connector,
    h2: v2::Connector,
    custom: C,
}

impl Connector<()> {
    pub fn new(options: Option<ConnectorOptions>) -> Self {
        Connector {
            h1: v1::Connector::new(options.clone()),
            h2: v2::Connector::new(options.clone()),
            custom: Default::default(),
        }
    }
}

impl<C> Connector<C>
where
    C: custom::Connector,
{
    pub fn new_custom(options: Option<ConnectorOptions>, custom: C) -> Self {
        Connector {
            h1: v1::Connector::new(options.clone()),
            h2: v2::Connector::new(options.clone()),
            custom,
        }
    }

    /// Get an [HttpSession] to the given server.
    ///
    /// The second return value indicates whether the session is connected via a reused stream.
    pub async fn get_http_session<P: Peer + Send + Sync + 'static>(
        &self,
        peer: &P,
    ) -> Result<(HttpSession<C::Session>, bool)> {
        let peer_opts = peer.get_peer_options();

        // Switch to custom protocol as early as possible
        if peer_opts.is_some_and(|o| matches!(o.alpn, ALPN::Custom(_))) {
            // We create the Connector before TLS, so we need to make sure that the server also supports the same custom protocol.
            // We will first check for sessions that we can reuse, if not we will create a new one based on the negotiated protocol

            // Step 1: Look for reused Custom Session
            if let Some(session) = self.custom.reused_http_session(peer).await {
                return Ok((HttpSession::Custom(session), true));
            }
            // Step 2: Check reuse pool for reused H1 session
            if let Some(h1) = self.h1.reused_http_session(peer).await {
                return Ok((HttpSession::H1(h1), true));
            }
            // Step 3: Try and create a new Custom session
            let (connection, reused) = self.custom.get_http_session(peer).await?;
            // We create the Connector before TLS, so we need to make sure that the server also supports the same custom protocol
            match connection {
                Connection::Session(s) => {
                    return Ok((HttpSession::Custom(s), reused));
                }
                // Negotiated ALPN is not custom, create a new H1 session
                Connection::Stream(s) => {
                    return Ok((
                        HttpSession::H1(Http1Session::new_with_options(s, peer)),
                        false,
                    ));
                }
            }
        }

        // NOTE: maybe TODO: we do not yet enforce that only TLS traffic can use h2, which is the
        // de facto requirement for h2, because non TLS traffic lack the negotiation mechanism.

        // We assume no peer option == no ALPN == h1 only
        let h1_only = peer
            .get_peer_options()
            .is_none_or(|o| o.alpn.get_max_http_version() == 1);
        if h1_only {
            let (h1, reused) = self.h1.get_http_session(peer).await?;
            Ok((HttpSession::H1(h1), reused))
        } else {
            // the peer allows h2, we first check the h2 reuse pool
            let reused_h2 = self.h2.reused_http_session(peer).await?;
            if let Some(h2) = reused_h2 {
                return Ok((HttpSession::H2(h2), true));
            }
            let h2_only = peer
                .get_peer_options()
                .is_some_and(|o| o.alpn.get_min_http_version() == 2)
                && !self.h2.h1_is_preferred(peer);
            if !h2_only {
                // We next check the reuse pool for h1 before creating a new h2 connection.
                // This is because the server may not support h2 at all, connections to
                // the server could all be h1.
                if let Some(h1) = self.h1.reused_http_session(peer).await {
                    return Ok((HttpSession::H1(h1), true));
                }
            }
            let session = self.h2.new_http_session(peer).await?;
            Ok((session, false))
        }
    }

    pub async fn release_http_session<P: Peer + Send + Sync + 'static>(
        &self,
        session: HttpSession<C::Session>,
        peer: &P,
        idle_timeout: Option<Duration>,
    ) {
        match session {
            HttpSession::H1(h1) => self.h1.release_http_session(h1, peer, idle_timeout).await,
            HttpSession::H2(h2) => self.h2.release_http_session(h2, peer, idle_timeout),
            HttpSession::Custom(c) => {
                self.custom
                    .release_http_session(c, peer, idle_timeout)
                    .await;
            }
        }
    }

    /// Tell the connector to always send h1 for ALPN for the given peer in the future.
    pub fn prefer_h1(&self, peer: &impl Peer) {
        self.h2.prefer_h1(peer);
    }

    /// Return the number of times a pooled connection was found to contain
    /// unexpected data from the server.
    pub fn unexpected_data_connection_count(&self) -> u64 {
        self.h1.unexpected_data_connection_count()
    }

    /// Return a shared reference to the unexpected data connection counter for periodic metric reporting.
    pub fn unexpected_data_connection_counter(&self) -> Arc<AtomicU64> {
        self.h1.unexpected_data_connection_counter()
    }
}



// Used for disabling certificate/hostname verification in rustls for tests and custom ALPN/self-signed scenarios.
