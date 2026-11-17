//! Optional ordered destination ACL. This only narrows the mandatory egress policy.
use crate::policy::{Authority, valid_dns_name};
use serde::Deserialize;
use std::net::IpAddr;

pub const MAX_FILE_BYTES: usize = 256 * 1024;
const MAX_RULES: usize = 4096;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Action {
    Allow,
    #[default]
    Deny,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(default)]
    default: Action,
    #[serde(default)]
    rules: Vec<RuleSpec>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    action: Action,
    domain: Option<String>,
    suffix: Option<String>,
    ip: Option<IpAddr>,
    cidr: Option<String>,
    #[serde(default)]
    ports: Vec<String>,
}
#[derive(Clone)]
enum Selector {
    Any,
    Domain(String),
    Suffix(String),
    Network(Network),
}
#[derive(Clone)]
struct Network {
    ip: IpAddr,
    prefix: u8,
}
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
impl Network {
    fn parse(text: &str) -> Result<Self, &'static str> {
        let (ip, prefix) = text.split_once('/').ok_or("ACL CIDR requires a prefix")?;
        let mut ip = ip
            .parse::<IpAddr>()
            .map_err(|_| "invalid ACL CIDR address")?;
        let mut prefix = prefix
            .parse::<u8>()
            .map_err(|_| "invalid ACL CIDR prefix")?;
        if let IpAddr::V6(v) = ip
            && let Some(v4) = v.to_ipv4_mapped()
        {
            prefix = prefix
                .checked_sub(96)
                .ok_or("mapped ACL CIDR prefix must be at least 96")?;
            ip = IpAddr::V4(v4);
        }
        let network = Self { ip, prefix };
        let canonical = match ip {
            IpAddr::V4(v) if prefix <= 32 => {
                u32::from(v) & (!u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0))
                    == u32::from(v)
            }
            IpAddr::V6(v) if prefix <= 128 => {
                u128::from(v) & (!u128::MAX.checked_shr(u32::from(prefix)).unwrap_or(0))
                    == u128::from(v)
            }
            _ => false,
        };
        if !canonical {
            return Err("ACL CIDR has an invalid prefix or host bits");
        }
        Ok(network)
    }
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.ip, normalize(ip)) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                self.prefix == 0
                    || u32::from(network) >> (32 - self.prefix)
                        == u32::from(ip) >> (32 - self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                self.prefix == 0
                    || u128::from(network) >> (128 - self.prefix)
                        == u128::from(ip) >> (128 - self.prefix)
            }
            _ => false,
        }
    }
}
#[derive(Clone)]
struct Rule {
    action: Action,
    selector: Selector,
    ports: Vec<(u16, u16)>,
}
impl Rule {
    fn port_matches(&self, port: u16) -> bool {
        self.ports.is_empty()
            || self
                .ports
                .iter()
                .any(|&(low, high)| (low..=high).contains(&port))
    }
    fn host_matches(&self, host: &str) -> bool {
        match &self.selector {
            Selector::Any => true,
            Selector::Domain(domain) => host.eq_ignore_ascii_case(domain),
            Selector::Suffix(suffix) => {
                host.eq_ignore_ascii_case(suffix)
                    || host.len() > suffix.len()
                        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
                        && host.as_bytes()[host.len() - suffix.len()..]
                            .eq_ignore_ascii_case(suffix.as_bytes())
            }
            Selector::Network(_) => false,
        }
    }
}
/// Immutable, validated policy shared by every listener and egress clone.
#[derive(Clone)]
pub struct Policy {
    default: Action,
    rules: Vec<Rule>,
}
impl Policy {
    /// No optional ACL file: retain the existing mandatory public-address policy.
    pub fn unrestricted() -> Self {
        Self {
            default: Action::Allow,
            rules: Vec::new(),
        }
    }
    /// Configured files default to deny. Errors never return a permissive policy.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        if text.len() > MAX_FILE_BYTES {
            return Err("ACL file too large");
        }
        let document: Document = toml::from_str(text).map_err(|_| "invalid ACL TOML")?;
        if document.rules.len() > MAX_RULES {
            return Err("too many ACL rules");
        }
        let mut rules = Vec::with_capacity(document.rules.len());
        for spec in document.rules {
            let selectors = [
                spec.domain.is_some(),
                spec.suffix.is_some(),
                spec.ip.is_some(),
                spec.cidr.is_some(),
            ];
            if selectors.into_iter().filter(|present| *present).count() > 1 {
                return Err("ACL rule supports only one destination selector");
            }
            let domain = |value: String| {
                if !valid_dns_name(&value) || value.parse::<IpAddr>().is_ok() {
                    return Err("invalid ACL domain selector");
                }
                Ok(value.to_ascii_lowercase())
            };
            let selector = if let Some(value) = spec.domain {
                Selector::Domain(domain(value)?)
            } else if let Some(value) = spec.suffix {
                Selector::Suffix(domain(value)?)
            } else if let Some(ip) = spec.ip {
                let ip = normalize(ip);
                Selector::Network(Network {
                    ip,
                    prefix: if ip.is_ipv4() { 32 } else { 128 },
                })
            } else if let Some(value) = spec.cidr {
                Selector::Network(Network::parse(&value)?)
            } else {
                Selector::Any
            };
            if spec.ports.len() > 128 {
                return Err("too many ACL port ranges");
            }
            let mut ports = Vec::with_capacity(spec.ports.len());
            for value in spec.ports {
                let number = |text: &str| {
                    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                        return Err("invalid ACL port");
                    }
                    text.parse::<u16>()
                        .ok()
                        .filter(|n| *n != 0)
                        .ok_or("invalid ACL port")
                };
                let (low, high) = match value.split_once('-') {
                    Some((low, high)) => (number(low)?, number(high)?),
                    None => {
                        let port = number(&value)?;
                        (port, port)
                    }
                };
                if low > high {
                    return Err("reversed ACL port range");
                }
                ports.push((low, high));
            }
            rules.push(Rule {
                action: spec.action,
                selector,
                ports,
            });
        }
        Ok(Self {
            default: document.default,
            rules,
        })
    }
    /// Early authority gate. IP-dependent rules defer the decision until resolution;
    /// they must never turn an ordered domain rule into a separate unordered policy.
    pub fn allows_request(&self, target: &Authority) -> bool {
        let literal = target.host.parse::<IpAddr>().ok();
        for rule in &self.rules {
            if !rule.port_matches(target.port) {
                continue;
            }
            let matches = match &rule.selector {
                Selector::Network(network) => match literal {
                    Some(ip) => network.contains(ip),
                    None => return true,
                },
                _ => rule.host_matches(&target.host),
            };
            if matches {
                return rule.action == Action::Allow;
            }
        }
        self.default == Action::Allow
    }
    /// First matching rule over the original authority and one concrete dial IP.
    /// Call again on every resolution result; never dial the hostname afterwards.
    pub fn allows_candidate(&self, target: &Authority, ip: IpAddr) -> bool {
        self.rules
            .iter()
            .find(|rule| {
                rule.port_matches(target.port)
                    && match &rule.selector {
                        Selector::Network(network) => network.contains(ip),
                        _ => rule.host_matches(&target.host),
                    }
            })
            .map_or(self.default, |rule| rule.action)
            == Action::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn target(host: &str, port: u16) -> Authority {
        Authority {
            host: host.into(),
            port,
        }
    }
    fn allowed(policy: &Policy, host: &str, port: u16, ip: &str) -> bool {
        let target = target(host, port);
        policy.allows_request(&target) && policy.allows_candidate(&target, ip.parse().unwrap())
    }
    #[test]
    fn absent_policy_preserves_public_default_but_configured_empty_denies() {
        assert!(allowed(
            &Policy::unrestricted(),
            "example.com",
            443,
            "1.1.1.1"
        ));
        assert!(!allowed(
            &Policy::parse("").unwrap(),
            "example.com",
            443,
            "1.1.1.1"
        ));
    }
    #[test]
    fn first_match_precedence_and_suffix_boundaries() {
        let policy = Policy::parse(
            r#"
[[rules]]
action = "deny"
domain = "blocked.example.com"
[[rules]]
action = "allow"
suffix = "Example.COM"
ports = ["443", "8000-8080"]
"#,
        )
        .unwrap();
        assert!(!allowed(&policy, "blocked.example.com", 443, "1.1.1.1"));
        for name in ["example.com", "a.example.com", "A.EXAMPLE.COM"] {
            assert!(allowed(&policy, name, 443, "1.1.1.1"));
            assert!(allowed(&policy, name, 8080, "2606:4700::1111"));
            assert!(!allowed(&policy, name, 8081, "1.1.1.1"));
        }
        assert!(!allowed(&policy, "badexample.com", 443, "1.1.1.1"));
        assert!(!allowed(&policy, "example.com.evil", 443, "1.1.1.1"));
    }
    #[test]
    fn dns_changes_and_ordered_ip_rules_are_rechecked() {
        let policy = Policy::parse(
            r#"
[[rules]]
action = "deny"
cidr = "8.8.8.0/24"
[[rules]]
action = "allow"
domain = "example.com"
ports = ["443"]
"#,
        )
        .unwrap();
        assert!(policy.allows_request(&target("example.com", 443)));
        assert!(allowed(&policy, "example.com", 443, "1.1.1.1"));
        assert!(!allowed(&policy, "example.com", 443, "8.8.8.8"));
        let policy = Policy::parse(
            r#"
[[rules]]
action = "allow"
ip = "1.1.1.1"
[[rules]]
action = "deny"
domain = "example.com"
"#,
        )
        .unwrap();
        // An earlier candidate rule must remain able to match before the deny.
        assert!(allowed(&policy, "example.com", 443, "1.1.1.1"));
        assert!(!allowed(&policy, "example.com", 443, "8.8.8.8"));
    }
    #[test]
    fn ipv4_ipv6_mapped_and_cidr_edges() {
        let policy = Policy::parse(
            r#"
[[rules]]
action = "allow"
cidr = "1.1.1.0/24"
[[rules]]
action = "allow"
cidr = "2606:4700::/32"
[[rules]]
action = "allow"
ip = "::ffff:8.8.8.8"
"#,
        )
        .unwrap();
        for ip in [
            "1.1.1.0",
            "1.1.1.255",
            "::ffff:1.1.1.1",
            "2606:4700::1111",
            "8.8.8.8",
        ] {
            assert!(allowed(&policy, ip, 443, ip), "{ip}");
        }
        for ip in ["1.1.2.0", "2606:4701::1", "8.8.4.4"] {
            assert!(!allowed(&policy, ip, 443, ip));
        }
        let all = Policy::parse("[[rules]]\naction='allow'\ncidr='::/0'").unwrap();
        assert!(allowed(&all, "2606:4700::1", 443, "2606:4700::1"));
        assert!(!allowed(&all, "1.1.1.1", 443, "::ffff:1.1.1.1"));
    }
    #[test]
    fn invalid_or_unsupported_files_never_fall_back_to_allow() {
        for text in [
            "default='invalid'",
            "unknown=true",
            "[[rules]]\naction='allow'\nscript='true'",
            "[[rules]]\naction='allow'\ncidr='1.1.1.1/24'",
            "[[rules]]\naction='allow'\ncidr='1.1.1.0/33'",
            "[[rules]]\naction='allow'\ncidr='::ffff:0.0.0.0/80'",
            "[[rules]]\naction='allow'\nsuffix='*.example.com'",
            "[[rules]]\naction='allow'\ndomain='1.1.1.1'",
            "[[rules]]\naction='allow'\ndomain='example.com'\nip='1.1.1.1'",
            "[[rules]]\naction='allow'\nports=['0']",
            "[[rules]]\naction='allow'\nports=['8080-80']",
            "[[rules]]\naction='allow'\nports=['65536']",
            "[[rules]]\naction='allow'\nports=[443]",
        ] {
            assert!(Policy::parse(text).is_err(), "{text}");
        }
        assert!(Policy::parse(&" ".repeat(MAX_FILE_BYTES + 1)).is_err());
        assert!(Policy::parse(&"[[rules]]\naction='allow'\n".repeat(MAX_RULES + 1)).is_err());
    }
}
