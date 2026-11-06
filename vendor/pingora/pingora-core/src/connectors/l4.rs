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

#[cfg(unix)]
use crate::protocols::l4::ext::connect_uds;
use crate::protocols::l4::ext::{
    connect_error_local_addr, connect_with_attempt as tcp_connect, set_dscp, set_recv_buf,
    set_tcp_fastopen_connect, ConnectAttempt, ConnectErrorDetails,
};
use crate::protocols::l4::socket::SocketAddr;
use crate::protocols::l4::stream::Stream;
use crate::protocols::{GetSocketDigest, SocketDigest};
use crate::upstreams::peer::Peer;
use async_trait::async_trait;
use log::debug;
use pingora_error::{Context, Error, ErrorType::*, OrErr, Result};
use rand::seq::SliceRandom;
use std::net::SocketAddr as InetSocketAddr;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

/// The interface to establish a L4 connection
#[async_trait]
pub trait Connect: std::fmt::Debug {
    /// Opt-in retry of TCP+TLS before any HTTP request is sent. Implementations
    /// must advance concrete candidates on each connect() call.
    fn connection_attempts(&self) -> usize {
        1
    }
    fn attempt_timeout(&self) -> Option<std::time::Duration> {
        None
    }
    async fn connect(&self, addr: &SocketAddr) -> Result<Stream>;
}

/// Additional metadata available on errors from TCP connection attempts.
pub trait ConnectErrorExt {
    /// Returns the local address assigned to the failed connection attempt, if one was recorded.
    ///
    /// Returns `None` for unrelated errors, non-TCP connections, or failures that occurred before
    /// the operating system assigned a local address or port.
    fn connect_local_addr(&self) -> Option<InetSocketAddr>;
}

impl ConnectErrorExt for Error {
    fn connect_local_addr(&self) -> Option<InetSocketAddr> {
        connect_error_local_addr(self)
    }
}

/// Settings for binding on connect
#[derive(Clone, Debug, Default)]
pub struct BindTo {
    // local ip address
    pub addr: Option<InetSocketAddr>,
    // port range
    port_range: Option<(u16, u16)>,
    // whether we fallback and try again on bind errors when a port range is set
    fallback: bool,
}

impl BindTo {
    /// Sets the port range we will bind to where the first item in the tuple is the lower bound
    /// and the second item is the upper bound.
    ///
    /// Note this bind option is only supported on Linux since 6.3, this is a no-op on other systems.
    /// To reset the range, pass a `None` or `Some((0,0))`, more information can be found [here](https://man7.org/linux/man-pages/man7/ip.7.html)
    pub fn set_port_range(&mut self, range: Option<(u16, u16)>) -> Result<()> {
        if range.is_none() && self.port_range.is_none() {
            // nothing to do
            return Ok(());
        }

        match range {
            // 0,0 is valid for resets
            None | Some((0, 0)) => self.port_range = Some((0, 0)),
            // set the port range if valid
            Some((low, high)) if low > 0 && low < high => {
                self.port_range = Some((low, high));
            }
            _ => return Error::e_explain(SocketError, "invalid port range: {range}"),
        }
        Ok(())
    }

    /// Set whether we fallback on no address available if a port range is set
    pub fn set_fallback(&mut self, fallback: bool) {
        self.fallback = fallback
    }

    /// Configured bind port range
    pub fn port_range(&self) -> Option<(u16, u16)> {
        self.port_range
    }

    /// Whether we attempt to fallback on no address available
    pub fn will_fallback(&self) -> bool {
        self.fallback && self.port_range.is_some()
    }
}

/// Establish a connection (l4) to the given peer using its settings and an optional bind address.
pub(crate) async fn connect<P>(peer: &P, bind_to: Option<BindTo>) -> Result<Stream>
where
    P: Peer + Send + Sync,
{
    if peer.get_proxy().is_some() {
        return proxy_connect(peer)
            .await
            .err_context(|| format!("Fail to establish CONNECT proxy: {}", peer));
    }
    let peer_addr = peer.address();
    let mut local_addr = None;
    let mut stream: Stream =
        if let Some(custom_l4) = peer.get_peer_options().and_then(|o| o.custom_l4.as_ref()) {
            custom_l4.connect(peer_addr).await?
        } else {
            match peer_addr {
                SocketAddr::Inet(addr) => {
                    let mut connect_attempt = ConnectAttempt::default();
                    let connect_future = tcp_connect(
                        addr,
                        bind_to.as_ref(),
                        |socket| {
                            #[cfg(unix)]
                            let raw = socket.as_raw_fd();
                            #[cfg(windows)]
                            let raw = socket.as_raw_socket();

                            if peer.tcp_fast_open() {
                                set_tcp_fastopen_connect(raw)?;
                            }
                            if let Some(recv_buf) = peer.tcp_recv_buf() {
                                debug!("Setting recv buf size");
                                set_recv_buf(raw, recv_buf)?;
                            }
                            if let Some(dscp) = peer.dscp() {
                                debug!("Setting dscp");
                                set_dscp(raw, dscp)?;
                            }

                            if let Some(tweak_hook) = peer
                                .get_peer_options()
                                .and_then(|o| o.upstream_tcp_sock_tweak_hook.clone())
                            {
                                tweak_hook(socket)?;
                            }

                            Ok(())
                        },
                        &mut connect_attempt,
                    );
                    let conn_res = match peer.connection_timeout() {
                        Some(t) => match pingora_timeout::timeout(t, connect_future).await {
                            Ok(result) => result,
                            Err(e) => {
                                let context = format!("timeout {t:?} connecting to server {peer}");
                                return Err(match connect_attempt.local_addr() {
                                    Some(local_addr) => Error::because(
                                        ConnectTimedout,
                                        context,
                                        ConnectErrorDetails::new(e, Some(local_addr)),
                                    ),
                                    None => Error::because(ConnectTimedout, context, e),
                                });
                            }
                        },
                        None => connect_future.await,
                    };
                    match conn_res {
                        Ok(socket) => {
                            local_addr = connect_attempt.local_addr();
                            debug!("connected to new server: {}", peer.address());
                            Ok(socket.into())
                        }
                        Err(e) => {
                            let c = format!("Fail to connect to {peer}");
                            match e.etype() {
                                SocketError | BindError => Error::e_because(InternalError, c, e),
                                _ => Err(e.more_context(c)),
                            }
                        }
                    }
                }
                #[cfg(unix)]
                SocketAddr::Unix(addr) => {
                    let connect_future = connect_uds(
                        addr.as_pathname()
                            .expect("non-pathname unix sockets not supported as peer"),
                    );
                    let conn_res = match peer.connection_timeout() {
                        Some(t) => pingora_timeout::timeout(t, connect_future)
                            .await
                            .explain_err(ConnectTimedout, |_| {
                                format!("timeout {t:?} connecting to server {peer}")
                            })?,
                        None => connect_future.await,
                    };
                    match conn_res {
                        Ok(socket) => {
                            debug!("connected to new server: {}", peer.address());
                            Ok(socket.into())
                        }
                        Err(e) => {
                            let c = format!("Fail to connect to {peer}");
                            match e.etype() {
                                SocketError | BindError => Error::e_because(InternalError, c, e),
                                _ => Err(e.more_context(c)),
                            }
                        }
                    }
                }
            }?
        };

    let tracer = peer.get_tracer();
    if let Some(t) = tracer {
        t.0.on_connected();
        stream.tracer = Some(t);
    }

    // settings applied based on stream type
    if let Some(ka) = peer.tcp_keepalive() {
        stream.set_keepalive(ka)?;
    }
    stream.set_nodelay()?;

    #[cfg(unix)]
    let digest = SocketDigest::from_raw_fd(stream.as_raw_fd());
    #[cfg(windows)]
    let digest = SocketDigest::from_raw_socket(stream.as_raw_socket());
    digest
        .peer_addr
        .set(Some(peer_addr.clone()))
        .expect("newly created OnceCell must be empty");
    if let Some(local_addr) = local_addr {
        digest
            .local_addr
            .set(Some(SocketAddr::Inet(local_addr)))
            .expect("newly created OnceCell must be empty");
    }
    stream.set_socket_digest(digest);

    Ok(stream)
}

pub(crate) fn bind_to_random<P: Peer>(
    peer: &P,
    v4_list: &[InetSocketAddr],
    v6_list: &[InetSocketAddr],
) -> Option<BindTo> {
    // helper function for randomly picking address
    fn bind_to_ips(ips: &[InetSocketAddr]) -> Option<InetSocketAddr> {
        match ips.len() {
            0 => None,
            1 => Some(ips[0]),
            _ => {
                // pick a random bind ip
                ips.choose(&mut rand::thread_rng()).copied()
            }
        }
    }

    let mut bind_to = peer.get_peer_options().and_then(|o| o.bind_to.clone());
    if bind_to.as_ref().map(|b| b.addr).is_some() {
        // already have a bind address selected
        return bind_to;
    }

    let addr = match peer.address() {
        SocketAddr::Inet(sockaddr) => match sockaddr {
            InetSocketAddr::V4(_) => bind_to_ips(v4_list),
            InetSocketAddr::V6(_) => bind_to_ips(v6_list),
        },
        #[cfg(unix)]
        SocketAddr::Unix(_) => None,
    };

    if addr.is_some() {
        if let Some(bind_to) = bind_to.as_mut() {
            bind_to.addr = addr;
        } else {
            bind_to = Some(BindTo {
                addr,
                ..Default::default()
            });
        }
    }
    bind_to
}

use crate::protocols::raw_connect;

#[cfg(unix)]
async fn proxy_connect<P: Peer>(peer: &P) -> Result<Stream> {
    // safe to unwrap
    let proxy = peer.get_proxy().unwrap();
    let options = peer.get_peer_options().unwrap();

    // combine required and optional headers
    let mut headers = proxy
        .headers
        .iter()
        .chain(options.extra_proxy_headers.iter());

    // not likely to timeout during connect() to UDS
    let stream: Box<Stream> = Box::new(
        connect_uds(&proxy.next_hop)
            .await
            .or_err_with(ConnectError, || {
                format!("CONNECT proxy connect() error to {:?}", proxy.next_hop)
            })?
            .into(),
    );

    let req_header = raw_connect::generate_connect_header(&proxy.host, proxy.port, &mut headers)?;
    let fut = raw_connect::connect(stream, &req_header, peer);
    let (mut stream, digest) = match peer.connection_timeout() {
        Some(t) => pingora_timeout::timeout(t, fut)
            .await
            .explain_err(ConnectTimedout, |_| "establishing CONNECT proxy")?,
        None => fut.await,
    }
    .map_err(|mut e| {
        // http protocol may ask to retry if reused client
        e.retry.decide_reuse(false);
        e
    })?;
    debug!("CONNECT proxy established: {:?}", proxy);
    stream.set_proxy_digest(digest);
    let stream = stream.into_any().downcast::<Stream>().unwrap(); // safe, it is Stream from above
    Ok(*stream)
}

#[cfg(windows)]
async fn proxy_connect<P: Peer>(peer: &P) -> Result<Stream> {
    panic!("peer proxy not supported on windows")
}
