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

//! Consistent Hashing

use super::*;
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_ketama::{Bucket, Continuum, Version};
use std::collections::HashMap;

/// Weighted Ketama consistent hashing
pub struct KetamaHashing {
    ring: Continuum,
    // TODO: update Ketama to just store this
    backends: HashMap<SocketAddr, Backend>,
}

#[derive(Clone, Debug, Copy, Default)]
pub struct KetamaConfig {
    pub point_multiple: Option<u32>,
}

impl BackendSelection for KetamaHashing {
    type Iter = OwnedNodeIterator;

    type Config = KetamaConfig;

    fn build_with_config(backends: &BTreeSet<Backend>, config: &Self::Config) -> Self {
        let KetamaConfig { point_multiple } = *config;

        let buckets: Vec<_> = backends
            .iter()
            .filter_map(|b| {
                // FIXME: ketama only supports Inet addr, UDS addrs are ignored here
                if let SocketAddr::Inet(addr) = b.addr {
                    Some(Bucket::new(addr, b.weight as u32))
                } else {
                    None
                }
            })
            .collect();
        let new_backends = backends
            .iter()
            .map(|b| (b.addr.clone(), b.clone()))
            .collect();

        #[allow(unused)]
        let version = if let Some(point_multiple) = point_multiple {
            match () {
                #[cfg(feature = "v2")]
                () => Version::V2 { point_multiple },
                #[cfg(not(feature = "v2"))]
                () => Version::V1,
            }
        } else {
            Version::V1
        };

        KetamaHashing {
            ring: Continuum::new_with_version(&buckets, version),
            backends: new_backends,
        }
    }

    fn build(backends: &BTreeSet<Backend>) -> Self {
        Self::build_with_config(backends, &KetamaConfig::default())
    }

    fn iter(self: &Arc<Self>, key: &[u8]) -> Self::Iter {
        OwnedNodeIterator {
            idx: self.ring.node_idx(key),
            ring: self.clone(),
        }
    }
}

/// Iterator over a Continuum
pub struct OwnedNodeIterator {
    idx: usize,
    ring: Arc<KetamaHashing>,
}

impl BackendIter for OwnedNodeIterator {
    fn next(&mut self) -> Option<&Backend> {
        self.ring.ring.get_addr(&mut self.idx).and_then(|addr| {
            let addr = SocketAddr::Inet(*addr);
            self.ring.backends.get(&addr)
        })
    }
}
