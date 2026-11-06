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

//! Connecting to servers

pub mod http;
pub mod l4;
#[cfg(feature = "any_tls")]
mod tls;

#[cfg(not(feature = "any_tls"))]
use crate::tls::connectors as tls;

use crate::protocols::l4::ext::attach_connect_local_addr;
use crate::protocols::{GetSocketDigest, Stream};
use crate::server::configuration::ServerConf;
use crate::upstreams::peer::{Peer, ALPN};

use crate::offload::OffloadRuntime;
pub use l4::Connect as L4Connect;
use l4::{connect as l4_connect, BindTo};
use log::{debug, error, warn};
use parking_lot::RwLock;
use pingora_error::{Error, ErrorType::*, OrErr, Result};
use pingora_pool::{ConnectionMeta, ConnectionPool};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tls::TlsConnector;
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub(crate) struct IdleConnection {
    connection: ConnectionMeta,
    idle_since: Instant,
}

impl IdleConnection {
    pub(crate) fn new(connection: ConnectionMeta) -> Self {
        Self {
            connection,
            idle_since: Instant::now(),
        }
    }

    fn elapsed(&self) -> Duration {
        self.idle_since.elapsed()
    }
}

/// Callback invoked when an idle upstream connection leaves the keep-alive pool
/// without being reused.
pub type PoolCallback = Arc<dyn Fn(Duration) + Send + Sync>;

/// The options to configure a [TransportConnector]
#[derive(Clone)]
pub struct ConnectorOptions {
    /// Path to the CA file used to validate server certs.
    ///
    /// If `None`, the CA in the [default](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_default_verify_paths.html)
    /// locations will be loaded
    pub ca_file: Option<String>,
    /// The maximum number of unique s2n configs to cache. Creating a new s2n config is an
    /// expensive operation, so we cache and re-use config objects with identical configurations.
    /// Defaults to a cache size of 10. A value of 0 disables the cache.
    ///
    /// WARNING: Disabling the s2n config cache can result in poor performance
    #[cfg(feature = "s2n")]
    pub s2n_config_cache_size: Option<usize>,
    /// The default client cert and key to use for mTLS
    ///
    /// Each individual connection can use their own cert key to override this.
    pub cert_key_file: Option<(String, String)>,
    /// When enabled allows TLS keys to be written to a file specified by the SSLKEYLOG
    /// env variable. This can be used by tools like Wireshark to decrypt traffic
    /// for debugging purposes.
    pub debug_ssl_keylog: bool,
    /// Effective global cap for the keepalive pool. Derived from
    /// `server_conf.upstream_keepalive_pool_size * server_conf.threads`
    /// in [`Self::from_server_conf`] so that operator-facing config keeps
    /// its per-worker meaning even though the pool itself now uses a single
    /// global LRU.
    pub keepalive_pool_size: usize,
    /// Optionally offload the connection establishment to dedicated thread pools
    ///
    /// TCP and TLS connection establishment can be CPU intensive. Sometimes such tasks can slow
    /// down the entire service, which causes timeouts which leads to more connections which
    /// snowballs the issue. Use this option to isolate these CPU intensive tasks from impacting
    /// other traffic.
    ///
    /// Syntax: (#pools, #thread in each pool)
    pub offload_threadpool: Option<(usize, usize)>,
    /// Bind to any of the given source IPv6 addresses
    pub bind_to_v4: Vec<SocketAddr>,
    /// Bind to any of the given source IPv4 addresses
    pub bind_to_v6: Vec<SocketAddr>,
    /// Optional callback for observing how long upstream connections stayed idle
    /// before leaving the keep-alive pool without reuse.
    pub keepalive_pool_callback: Option<PoolCallback>,
}

impl ConnectorOptions {
    /// Derive the [ConnectorOptions] from a [ServerConf]
    pub fn from_server_conf(server_conf: &ServerConf) -> Self {
        // create SocketAddrs with port 0 for src addr bind

        let bind_to_v4 = server_conf
            .client_bind_to_ipv4
            .iter()
            .map(|v4| {
                let ip = v4.parse().unwrap();
                SocketAddr::new(ip, 0)
            })
            .collect();

        let bind_to_v6 = server_conf
            .client_bind_to_ipv6
            .iter()
            .map(|v6| {
                let ip = v6.parse().unwrap();
                SocketAddr::new(ip, 0)
            })
            .collect();
        ConnectorOptions {
            ca_file: server_conf.ca_file.clone(),
            cert_key_file: None, // TODO: use it
            #[cfg(feature = "s2n")]
            s2n_config_cache_size: server_conf.s2n_config_cache_size,
            debug_ssl_keylog: server_conf.upstream_debug_ssl_keylog,
            keepalive_pool_size: server_conf
                .upstream_keepalive_pool_size
                .saturating_mul(server_conf.threads.max(1)),
            offload_threadpool: server_conf.upstream_connect_offload_threadpool(),
            bind_to_v4,
            bind_to_v6,
            keepalive_pool_callback: None,
        }
    }

    /// Create a new [ConnectorOptions] with the given keepalive pool size
    pub fn new(keepalive_pool_size: usize) -> Self {
        ConnectorOptions {
            ca_file: None,
            #[cfg(feature = "s2n")]
            s2n_config_cache_size: None,
            cert_key_file: None,
            debug_ssl_keylog: false,
            keepalive_pool_size,
            offload_threadpool: None,
            bind_to_v4: vec![],
            bind_to_v6: vec![],
            keepalive_pool_callback: None,
        }
    }
}

/// [TransportConnector] provides APIs to connect to servers via TCP or TLS with connection reuse
pub struct TransportConnector {
    tls_ctx: tls::Connector,
    connection_pool: Arc<ConnectionPool<Arc<Mutex<Stream>>>>,
    offload: Option<OffloadRuntime>,
    bind_to_v4: Vec<SocketAddr>,
    bind_to_v6: Vec<SocketAddr>,
    preferred_http_version: PreferredHttpVersion,
    /// Wrapped in `Arc` so external consumers (e.g. proxy services) can clone a reference
    /// for periodic metric reporting without needing access to the connector itself.
    unexpected_data_conn_count: Arc<AtomicU64>,
    keepalive_pool_callback: Option<PoolCallback>,
}

const DEFAULT_POOL_SIZE: usize = 128;

impl TransportConnector {
    /// Create a new [TransportConnector] with the given [ConnectorOptions]
    pub fn new(mut options: Option<ConnectorOptions>) -> Self {
        let pool_size = options
            .as_ref()
            .map_or(DEFAULT_POOL_SIZE, |c| c.keepalive_pool_size);
        // Take the offloading setting there because this layer has implement offloading,
        // so no need for stacks at lower layer to offload again.
        let offload = options.as_mut().and_then(|o| o.offload_threadpool.take());
        let bind_to_v4 = options
            .as_ref()
            .map_or_else(Vec::new, |o| o.bind_to_v4.clone());
        let bind_to_v6 = options
            .as_ref()
            .map_or_else(Vec::new, |o| o.bind_to_v6.clone());
        let keepalive_pool_callback = options
            .as_ref()
            .and_then(|o| o.keepalive_pool_callback.clone());
        TransportConnector {
            tls_ctx: tls::Connector::new(options),
            connection_pool: Arc::new(ConnectionPool::new(pool_size)),
            offload: offload.map(|v| OffloadRuntime::new("upstream connect offload", v.0, v.1)),
            bind_to_v4,
            bind_to_v6,
            preferred_http_version: PreferredHttpVersion::new(),
            unexpected_data_conn_count: Arc::new(AtomicU64::new(0)),
            keepalive_pool_callback,
        }
    }

    /// Connect to the given server [Peer]
    ///
    /// No connection is reused.
    pub async fn new_stream<P: Peer + Send + Sync + 'static>(&self, peer: &P) -> Result<Stream> {
        let rt = self
            .offload
            .as_ref()
            .map(|o| o.get_runtime(peer.reuse_hash()));
        let bind_to = l4::bind_to_random(peer, &self.bind_to_v4, &self.bind_to_v6);
        let alpn_override = self.preferred_http_version.get(peer);
        let stream = if let Some(rt) = rt {
            let peer = peer.clone();
            let tls_ctx = self.tls_ctx.clone();
            let offload_start = Instant::now();
            rt.spawn(async move {
                let offload_wait = offload_start.elapsed();
                do_connect(
                    &peer,
                    bind_to,
                    alpn_override,
                    &tls_ctx.ctx,
                    Some(offload_wait),
                )
                .await
            })
            .await
            .or_err(InternalError, "offload runtime failure")??
        } else {
            do_connect(peer, bind_to, alpn_override, &self.tls_ctx.ctx, None).await?
        };

        Ok(stream)
    }

    /// Try to find a reusable connection to the given server [Peer]
    pub async fn reused_stream<P: Peer + Send + Sync>(&self, peer: &P) -> Option<Stream> {
        match self.connection_pool.get(&peer.reuse_hash()) {
            Some(s) => {
                debug!("find reusable stream, trying to acquire it");
                {
                    let _ = s.lock().await;
                } // wait for the idle poll to release it
                match Arc::try_unwrap(s) {
                    Ok(l) => {
                        let mut stream = l.into_inner();
                        // test_reusable_stream: we assume server would never actively send data
                        // first on an idle stream.
                        #[cfg(unix)]
                        if peer.matches_fd(stream.id())
                            && test_reusable_stream(&mut stream, &self.unexpected_data_conn_count)
                        {
                            Some(stream)
                        } else {
                            None
                        }
                        #[cfg(windows)]
                        {
                            use std::os::windows::io::{AsRawSocket, RawSocket};
                            struct WrappedRawSocket(RawSocket);
                            impl AsRawSocket for WrappedRawSocket {
                                fn as_raw_socket(&self) -> RawSocket {
                                    self.0
                                }
                            }
                            if peer.matches_sock(WrappedRawSocket(stream.id() as RawSocket))
                                && test_reusable_stream(
                                    &mut stream,
                                    &self.unexpected_data_conn_count,
                                )
                            {
                                Some(stream)
                            } else {
                                None
                            }
                        }
                    }
                    Err(_) => {
                        error!("failed to acquire reusable stream");
                        None
                    }
                }
            }
            None => {
                debug!("No reusable connection found for {peer}");
                None
            }
        }
    }

    /// Return the [Stream] to the [TransportConnector] for connection reuse.
    ///
    /// Not all TCP/TLS connections can be reused. It is the caller's responsibility to make sure
    /// that protocol over the [Stream] supports connection reuse and the [Stream] itself is ready
    /// to be reused.
    ///
    /// If a [Stream] is dropped instead of being returned via this function. it will be closed.
    pub fn release_stream(
        &self,
        mut stream: Stream,
        key: u64, // usually peer.reuse_hash()
        idle_timeout: Option<Duration>,
    ) {
        if !test_reusable_stream(&mut stream, &self.unexpected_data_conn_count) {
            return;
        }
        let id = stream.id();
        let meta = ConnectionMeta::new(key, id);
        debug!("Try to keepalive client session");
        let stream = Arc::new(Mutex::new(stream));
        let locked_stream = stream.clone().try_lock_owned().unwrap(); // safe as we just created it
        let (notify_close, watch_use) = self.connection_pool.put(&meta, stream);
        let idle_meta = IdleConnection::new(meta);
        let pool = self.connection_pool.clone(); //clone the arc
        let keepalive_pool_callback = self.keepalive_pool_callback.clone();
        let rt = pingora_runtime::current_handle();
        rt.spawn(async move {
            if pool
                .idle_poll(
                    locked_stream,
                    &idle_meta.connection,
                    idle_timeout,
                    notify_close,
                    watch_use,
                )
                .await
            {
                if let Some(callback) = keepalive_pool_callback {
                    callback(idle_meta.elapsed());
                }
            }
        });
    }

    /// Get a stream to the given server [Peer]
    ///
    /// This function will try to find a reusable [Stream] first. If there is none, a new connection
    /// will be made to the server.
    ///
    /// The returned boolean will indicate whether the stream is reused.
    pub async fn get_stream<P: Peer + Send + Sync + 'static>(
        &self,
        peer: &P,
    ) -> Result<(Stream, bool)> {
        let reused_stream = self.reused_stream(peer).await;
        if let Some(s) = reused_stream {
            Ok((s, true))
        } else {
            let s = self.new_stream(peer).await?;
            Ok((s, false))
        }
    }

    /// Tell the connector to always send h1 for ALPN for the given peer in the future.
    pub fn prefer_h1(&self, peer: &impl Peer) {
        self.preferred_http_version.add(peer, 1);
    }

    /// Return the number of times a pooled connection was found to contain unexpected data
    /// from the server.
    pub fn unexpected_data_connection_count(&self) -> u64 {
        self.unexpected_data_conn_count.load(Ordering::Relaxed)
    }

    /// Return a shared reference to the unexpected data connection counter.
    ///
    /// This allows external consumers (e.g. proxy services) to clone the `Arc` and
    /// periodically read the counter for metric reporting without needing ongoing
    /// access to the connector.
    pub fn unexpected_data_connection_counter(&self) -> Arc<AtomicU64> {
        self.unexpected_data_conn_count.clone()
    }
}

// Perform the actual L4 and tls connection steps while respecting the peer's
// connection timeout if there is one
async fn do_connect<P: Peer + Send + Sync>(
    peer: &P,
    bind_to: Option<BindTo>,
    alpn_override: Option<ALPN>,
    tls_ctx: &TlsConnector,
    offload_wait_duration: Option<Duration>,
) -> Result<Stream> {
    // Create the future that does the connections, but don't evaluate it until
    // we decide if we need a timeout or not
    let connect_future = async {
        let custom = peer.get_peer_options().and_then(|o| o.custom_l4.as_ref());
        let attempts = custom.map_or(1, |c| c.connection_attempts()).clamp(1, 32);
        let phase_timeout = custom.and_then(|c| c.attempt_timeout());
        let mut last = None;
        for _ in 0..attempts {
            let attempt = do_connect_inner(
                peer,
                bind_to.clone(),
                alpn_override.clone(),
                tls_ctx,
                offload_wait_duration,
            );
            let result = match phase_timeout {
                Some(t) => match pingora_timeout::timeout(t, attempt).await {
                    Ok(result) => result,
                    Err(_) => Error::e_explain(ConnectTimedout, "candidate TCP/TLS deadline"),
                },
                None => attempt.await,
            };
            match result {
                Ok(stream) => return Ok(stream),
                Err(error) => last = Some(error),
            }
        }
        Err(last.expect("at least one connection attempt"))
    };

    match peer.total_connection_timeout() {
        Some(t) => match pingora_timeout::timeout(t, connect_future).await {
            Ok(res) => res,
            Err(_) => Error::e_explain(
                ConnectTimedout,
                format!("connecting to server {peer}, total-connection timeout {t:?}"),
            ),
        },
        None => connect_future.await,
    }
}

// Perform the actual L4 and tls connection steps with no timeout
async fn do_connect_inner<P: Peer + Send + Sync>(
    peer: &P,
    bind_to: Option<BindTo>,
    alpn_override: Option<ALPN>,
    tls_ctx: &TlsConnector,
    offload_wait_duration: Option<Duration>,
) -> Result<Stream> {
    let l4_connect_start = Instant::now();
    let mut stream = l4_connect(peer, bind_to).await?;
    stream.set_establishment_timing(l4_connect_start.elapsed(), offload_wait_duration);
    if peer.tls() {
        // Capture the local address before the handshake consumes the stream, so a TLS failure
        // can still report the address we connected from.
        // Arc clone plus a copy of the small SocketAddr, negligible next to the handshake.
        let local_addr = stream
            .get_socket_digest()
            .and_then(|digest| digest.local_addr().and_then(|addr| addr.as_inet()).copied());
        let tls_stream = tls::connect(stream, peer, alpn_override, tls_ctx)
            .await
            .map_err(|e| attach_connect_local_addr(e, local_addr))?;
        Ok(Box::new(tls_stream))
    } else {
        Ok(Box::new(stream))
    }
}

struct PreferredHttpVersion {
    // TODO: shard to avoid the global lock
    versions: RwLock<HashMap<u64, u8>>, // <hash of peer, version>
}

// TODO: limit the size of this

impl PreferredHttpVersion {
    pub fn new() -> Self {
        PreferredHttpVersion {
            versions: RwLock::default(),
        }
    }

    pub fn add(&self, peer: &impl Peer, version: u8) {
        let key = peer.reuse_hash();
        let mut v = self.versions.write();
        v.insert(key, version);
    }

    pub fn get(&self, peer: &impl Peer) -> Option<ALPN> {
        let key = peer.reuse_hash();
        let v = self.versions.read();
        v.get(&key)
            .copied()
            .map(|v| if v == 1 { ALPN::H1 } else { ALPN::H2H1 })
    }
}

use futures::future::FutureExt;
use tokio::io::AsyncReadExt;

/// Test whether a stream is already closed or not reusable (server sent unexpected data)
fn test_reusable_stream(stream: &mut Stream, unexpected_data_conn_count: &AtomicU64) -> bool {
    let mut buf = [0; 1];
    // tokio::task::unconstrained because now_or_never may yield None when the future is ready
    let result = tokio::task::unconstrained(stream.read(&mut buf[..])).now_or_never();
    if let Some(data_result) = result {
        match data_result {
            Ok(n) => {
                if n == 0 {
                    debug!("Idle connection is closed");
                } else {
                    warn!("Unexpected data read in idle connection");
                    unexpected_data_conn_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(e) => {
                debug!("Idle connection is broken: {e:?}");
            }
        }
        false
    } else {
        true
    }
}
