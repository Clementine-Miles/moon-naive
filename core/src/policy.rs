use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn valid_dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.is_ascii()
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    pub host: String,
    pub port: u16,
}
impl Authority {
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        if s.bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b"/@?#\\".contains(&b))
        {
            return Err("invalid CONNECT authority");
        }
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (host, port) = rest
                .split_once("]:")
                .ok_or("invalid bracketed IPv6 authority")?;
            host.parse::<Ipv6Addr>()
                .map_err(|_| "invalid IPv6 address")?;
            (host, port)
        } else {
            let (host, port) = s.rsplit_once(':').ok_or("explicit port required")?;
            if !valid_dns_name(host) {
                return Err("invalid host");
            }
            (host, port)
        };
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err("invalid port");
        }
        let port: u16 = port.parse().map_err(|_| "invalid port")?;
        if port == 0 {
            return Err("port zero is forbidden");
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

/// Conservative starting policy, plus explicit local/listener addresses.
/// The dialer must apply this to *every resolved candidate*, then dial that IP.
/// Special routing/NAT64 still requires deployment-specific egress rules.
pub fn allows_ip(ip: IpAddr, own_addresses: &[IpAddr]) -> bool {
    let normalize = |i: IpAddr| match i {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(i),
        _ => i,
    };
    let ip = normalize(ip);
    if own_addresses.iter().any(|i| normalize(*i) == ip) {
        return false;
    }
    match ip {
        IpAddr::V4(v) => {
            let n = u32::from(v);
            let blocked = [
                (Ipv4Addr::new(0, 0, 0, 0), 8),
                (Ipv4Addr::new(10, 0, 0, 0), 8),
                (Ipv4Addr::new(100, 64, 0, 0), 10),
                (Ipv4Addr::new(127, 0, 0, 0), 8),
                (Ipv4Addr::new(169, 254, 0, 0), 16),
                (Ipv4Addr::new(172, 16, 0, 0), 12),
                (Ipv4Addr::new(192, 0, 0, 0), 24),
                (Ipv4Addr::new(192, 0, 2, 0), 24),
                (Ipv4Addr::new(192, 168, 0, 0), 16),
                (Ipv4Addr::new(198, 18, 0, 0), 15),
                (Ipv4Addr::new(198, 51, 100, 0), 24),
                (Ipv4Addr::new(203, 0, 113, 0), 24),
                (Ipv4Addr::new(224, 0, 0, 0), 3),
            ];
            !blocked
                .iter()
                .any(|(base, prefix)| n >> (32 - prefix) == u32::from(*base) >> (32 - prefix))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            // Accept only global-unicast 2000::/3, excluding documentation,
            // transition and protocol-assignment ranges (conservative).
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_bracketed_ipv6_and_rejects_ambiguity() {
        assert_eq!(Authority::parse("[2606:4700::1111]:443").unwrap().port, 443);
        assert_eq!(
            Authority::parse("Example.COM:22").unwrap().host,
            "example.com"
        );
        for s in [
            "host",
            "host:0",
            "host:65536",
            "host:+80",
            "u@host:80",
            "host:80/a",
            "host:80\r\n",
            "::1:80",
            "[fe80::1%eth0]:80",
        ] {
            assert!(Authority::parse(s).is_err(), "{s:?}");
        }
    }
    #[test]
    fn acl_blocks_private_metadata_mapped_and_self() {
        for s in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "100.64.1.1",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "64:ff9b::7f00:1",
        ] {
            assert!(!allows_ip(s.parse().unwrap(), &[]), "{s}");
        }
        for s in ["1.1.1.1", "2606:4700::1111"] {
            assert!(allows_ip(s.parse().unwrap(), &[]));
        }
        assert!(!allows_ip(
            "1.1.1.1".parse().unwrap(),
            &["::ffff:1.1.1.1".parse().unwrap()]
        ));
    }
}

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// Compose separate pools for global, user and connection budgets.
/// Dropping earlier permits rolls back partially acquired admission.
#[derive(Clone)]
pub struct Budget {
    shared: Arc<Inner>,
}
struct Inner {
    active: AtomicUsize,
    maximum: usize,
}
pub struct Permit {
    shared: Arc<Inner>,
}
impl Budget {
    pub fn new(maximum: usize) -> Result<Self, &'static str> {
        if maximum == 0 {
            return Err("zero budget");
        }
        Ok(Self {
            shared: Arc::new(Inner {
                active: AtomicUsize::new(0),
                maximum,
            }),
        })
    }
    pub fn acquire(&self) -> Option<Permit> {
        // Explicit CAS keeps the declared MSRV while avoiding the newer
        // fetch_update/try_update rename on Rust 1.99.
        let mut active = self.shared.active.load(Ordering::Acquire);
        loop {
            if active >= self.shared.maximum {
                return None;
            }
            match self.shared.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(Permit {
                        shared: self.shared.clone(),
                    });
                }
                Err(observed) => active = observed,
            }
        }
    }
    pub fn active(&self) -> usize {
        self.shared.active.load(Ordering::Acquire)
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.shared.active.fetch_sub(1, Ordering::AcqRel);
    }
}
#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    fn cancellation_and_exhaustion_release_permits() {
        let b = Budget::new(1).unwrap();
        let p = b.acquire().unwrap();
        assert!(b.acquire().is_none());
        drop(p);
        assert_eq!(b.active(), 0);
    }
    #[test]
    fn concurrent_budget_never_overcommits() {
        let b = Budget::new(4).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let b = b.clone();
                scope.spawn(move || {
                    for _ in 0..1000 {
                        if let Some(_p) = b.acquire() {
                            assert!(b.active() <= 4);
                            std::thread::yield_now();
                        }
                    }
                });
            }
        });
        assert_eq!(b.active(), 0);
    }
}
