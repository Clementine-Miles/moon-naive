//! Authenticated forward HTTP uses Pingora with the same checked egress dialer as CONNECT.
use super::{Result, Website};
use crate::net::{egress::Egress, outbound};
use moon_naive_core::policy::{Authority, allows_ip};
use pingora_core::{
    connectors::L4Connect,
    protocols::l4::{stream::Stream as L4, virt::VirtualSocketStream},
    upstreams::peer::HttpPeer,
};
use std::{sync::Arc, time::Duration};
pub(super) struct Origin {
    authority: Authority,
    tls: bool,
    user: usize,
    egress: Egress,
}
impl Origin {
    pub fn new(origin: &str, user: usize, egress: Egress) -> Result<Self> {
        let uri: http::Uri = origin.parse()?;
        let host = uri.host().ok_or("forward host missing")?;
        let tls = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err("unsupported forward scheme".into()),
        };
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        let authority = Authority::parse(&format!("{host}:{port}"))?;
        Ok(Self {
            authority,
            tls,
            user,
            egress,
        })
    }
    pub async fn peer(&self, config: &Website) -> pingora_core::Result<Box<HttpPeer>> {
        let fail = || pingora_core::Error::new(pingora_core::ErrorType::HTTPStatus(502));
        if self.egress.is_self(&self.authority.host) {
            return Err(fail());
        }
        let addresses = tokio::time::timeout(
            Duration::from_secs(config.connect_timeout_secs),
            tokio::net::lookup_host((self.authority.host.as_str(), self.authority.port)),
        )
        .await
        .map_err(|_| fail())?
        .map_err(|_| fail())?
        .take(33)
        .collect::<Vec<_>>();
        if addresses.len() > 32 {
            return Err(fail());
        }
        let addr = addresses
            .into_iter()
            .find(|a| allows_ip(a.ip(), &self.egress.own))
            .ok_or_else(fail)?;
        let mut peer = HttpPeer::new(addr, self.tls, self.authority.host.clone());
        peer.group_key = self.user as u64 + 1;
        peer.options.custom_l4 = Some(Arc::new(Connector(self.egress.clone())));
        peer.options.verify_cert = true;
        peer.options.verify_hostname = true;
        if self.tls {
            peer.options.ca = self.egress.roots.get().await.map_err(|_| fail())?;
        }
        peer.options.alpn = if self.tls {
            pingora_core::protocols::ALPN::H2H1
        } else {
            pingora_core::protocols::ALPN::H1
        };
        peer.options.connection_timeout = Some(Duration::from_secs(config.connect_timeout_secs));
        peer.options.read_timeout = Some(Duration::from_secs(config.read_timeout_secs));
        peer.options.write_timeout = Some(Duration::from_secs(config.write_timeout_secs));
        peer.options.idle_timeout = Some(Duration::from_secs(config.upstream_idle_secs));
        Ok(Box::new(peer))
    }
}
struct Connector(Egress);
impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CheckedEgress")
    }
}
#[async_trait::async_trait]
impl L4Connect for Connector {
    async fn connect(
        &self,
        addr: &pingora_core::protocols::l4::socket::SocketAddr,
    ) -> pingora_core::Result<L4> {
        let target = Authority::parse(&addr.to_string())
            .map_err(|_| pingora_core::Error::new(pingora_core::ErrorType::ConnectError))?;
        let stream: outbound::Stream = self
            .0
            .dial(&target)
            .await
            .map_err(|_| pingora_core::Error::new(pingora_core::ErrorType::ConnectError))?;
        Ok(L4::from(VirtualSocketStream::new(Box::new(stream))))
    }
}
