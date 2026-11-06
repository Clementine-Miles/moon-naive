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

use crate::connectors::{ConnectorOptions, TransportConnector};
use crate::protocols::http::v1::client::HttpSession;
use crate::upstreams::peer::Peer;

use pingora_error::Result;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

pub struct Connector {
    transport: TransportConnector,
}

impl Connector {
    pub fn new(options: Option<ConnectorOptions>) -> Self {
        Connector {
            transport: TransportConnector::new(options),
        }
    }

    pub async fn get_http_session<P: Peer + Send + Sync + 'static>(
        &self,
        peer: &P,
    ) -> Result<(HttpSession, bool)> {
        let (stream, reused) = self.transport.get_stream(peer).await?;
        let http = HttpSession::new_with_options(stream, peer);
        Ok((http, reused))
    }

    pub async fn reused_http_session<P: Peer + Send + Sync + 'static>(
        &self,
        peer: &P,
    ) -> Option<HttpSession> {
        let stream = self.transport.reused_stream(peer).await?;
        let http = HttpSession::new_with_options(stream, peer);
        Some(http)
    }

    pub async fn release_http_session<P: Peer + Send + Sync + 'static>(
        &self,
        mut session: HttpSession,
        peer: &P,
        idle_timeout: Option<Duration>,
    ) {
        session.respect_keepalive();
        if let Some(stream) = session.reuse().await {
            self.transport
                .release_stream(stream, peer.reuse_hash(), idle_timeout);
        }
    }

    /// Return the number of times a pooled connection was found to contain
    /// unexpected data from the server.
    pub fn unexpected_data_connection_count(&self) -> u64 {
        self.transport.unexpected_data_connection_count()
    }

    /// Return a shared reference to the unexpected data connection counter for periodic metric reporting.
    pub fn unexpected_data_connection_counter(&self) -> Arc<AtomicU64> {
        self.transport.unexpected_data_connection_counter()
    }
}
