//! Administrator-defined website routing, separate from Naive destination ACLs.
use serde::Deserialize;
use std::{collections::HashSet, path::PathBuf};

#[derive(Debug, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct Website {
    pub compression_level: u32,
    pub max_request_body_bytes: usize,
    pub connect_timeout_secs: u64,
    pub read_timeout_secs: u64,
    pub write_timeout_secs: u64,
    pub upstream_idle_secs: u64,
    pub dns_ttl_secs: u64,
    pub upstreams: Vec<Upstream>,
    pub routes: Vec<Route>,
}
impl Default for Website {
    fn default() -> Self {
        Self {
            compression_level: 5,
            max_request_body_bytes: 64 * 1024 * 1024,
            connect_timeout_secs: 5,
            read_timeout_secs: 30,
            write_timeout_secs: 30,
            upstream_idle_secs: 60,
            dns_ttl_secs: 60,
            upstreams: vec![],
            routes: vec![],
        }
    }
}
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    pub origins: Vec<String>,
    #[serde(default)]
    pub tls_server_name: Option<String>,
    #[serde(default)]
    pub host_header: Option<String>,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default = "h2")]
    pub http2: bool,
}
fn h2() -> bool {
    true
}
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub path_prefix: String,
    pub upstream: String,
    #[serde(default)]
    pub strip_prefix: bool,
}
impl Website {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.compression_level > 6
            || self.max_request_body_bytes == 0
            || self.max_request_body_bytes > 1024 * 1024 * 1024
            || [
                self.connect_timeout_secs,
                self.read_timeout_secs,
                self.write_timeout_secs,
                self.upstream_idle_secs,
                self.dns_ttl_secs,
            ]
            .iter()
            .any(|n| !(1..=3600).contains(n))
            || self.routes.len() > 128
            || self.upstreams.len() > 32
        {
            return Err("invalid website resource limits");
        }
        let mut names = HashSet::new();
        for pool in &self.upstreams {
            if pool.name.is_empty()
                || pool.name.len() > 64
                || !pool
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || !names.insert(pool.name.as_str())
                || pool.origins.is_empty()
                || pool.origins.len() > 16
            {
                return Err("invalid or duplicate website upstream");
            }
            for origin in &pool.origins {
                let uri = origin
                    .parse::<http::Uri>()
                    .map_err(|_| "invalid website origin URI")?;
                if !matches!(uri.scheme_str(), Some("http" | "https"))
                    || uri.authority().is_none()
                    || uri.authority().is_some_and(|a| !valid_authority(a))
                    || !matches!(
                        uri.path_and_query().map(|p| p.as_str()),
                        None | Some("/") | Some("")
                    )
                    || uri.port_u16() == Some(0)
                    || uri.host().is_none_or(str::is_empty)
                {
                    return Err(
                        "website origins require http(s), an authority and no credentials/path/query",
                    );
                }
            }
            if pool.tls_server_name.as_ref().is_some_and(|name| {
                !crate::policy::valid_dns_name(name) && name.parse::<std::net::IpAddr>().is_err()
            }) || pool.host_header.as_ref().is_some_and(|host| {
                host.parse::<http::uri::Authority>()
                    .map_or(true, |authority| !valid_authority(&authority))
            }) || pool.ca_file.as_ref().is_some_and(|p| {
                !p.is_absolute() || p.components().any(|c| c == std::path::Component::ParentDir)
            }) {
                return Err("invalid website upstream TLS/Host/CA settings");
            }
        }
        let mut prefixes = HashSet::new();
        for route in &self.routes {
            if !names.contains(route.upstream.as_str())
                || !prefixes.insert(route.path_prefix.as_str())
                || !route.path_prefix.starts_with('/')
                || route.path_prefix.len() > 1024
                || !route
                    .path_prefix
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && !b"?%#\\".contains(&b))
                || route.path_prefix.split('/').any(|s| s == ".." || s == ".")
            {
                return Err(
                    "website routes require unique literal path prefixes and a configured upstream",
                );
            }
        }
        Ok(())
    }
}
/// Expand the operator's single-origin shorthand once, before runtime setup.
/// Runtime routing continues to use the same validated pools and routes.
pub fn deserialize_config<'de, D>(deserializer: D) -> Result<Website, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let mut table = toml::Table::deserialize(deserializer)?;
    let origin = table.remove("origin");
    if origin.is_some() && (table.contains_key("upstreams") || table.contains_key("routes")) {
        return Err(D::Error::custom(
            "website.origin cannot be combined with upstreams/routes",
        ));
    }
    let mut website: Website = table
        .try_into()
        .map_err(|_| D::Error::custom("invalid or unknown website field"))?;
    if let Some(origin) = origin {
        let origin = origin
            .as_str()
            .ok_or_else(|| D::Error::custom("website.origin must be a URL string"))?;
        let uri = origin
            .parse::<http::Uri>()
            .map_err(|_| D::Error::custom("invalid website origin URI"))?;
        website.upstreams.push(Upstream {
            name: "default".into(),
            origins: vec![origin.to_owned()],
            tls_server_name: None,
            // External origins commonly require their own virtual-host name.
            host_header: uri.authority().map(|a| a.as_str().to_owned()),
            ca_file: None,
            http2: true,
        });
        website.routes.push(Route {
            path_prefix: "/".into(),
            upstream: "default".into(),
            strip_prefix: false,
        });
    }
    website.validate().map_err(D::Error::custom)?;
    Ok(website)
}

fn valid_authority(authority: &http::uri::Authority) -> bool {
    let target = if authority.as_str() == authority.host() {
        format!("{authority}:443")
    } else {
        authority.as_str().to_owned()
    };
    crate::policy::Authority::parse(&target).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn website_rejects_open_proxy_targets_and_ambiguous_routes() {
        let mut w = Website::default();
        let pool = Upstream {
            name: "app".into(),
            origins: vec!["https://example.org".into()],
            tls_server_name: None,
            host_header: None,
            ca_file: None,
            http2: true,
        };
        w.upstreams.push(pool);
        w.routes.push(Route {
            path_prefix: "/api/".into(),
            upstream: "app".into(),
            strip_prefix: true,
        });
        assert!(w.validate().is_ok());
        for bad in [
            "file:///etc/passwd",
            "http://user:password@example.org",
            "http://example.org/base",
            "http://example.org/?target=x",
            "http://example.org:0",
            "http://example.org:99999",
            "http://example.org:wrong",
            "http://bad_host.test",
        ] {
            w.upstreams[0].origins = vec![bad.into()];
            assert!(w.validate().is_err());
        }
        w.upstreams[0].origins = vec!["http://127.0.0.1:3000".into()];
        assert!(w.validate().is_ok());
        w.routes.push(w.routes[0].clone());
        assert!(w.validate().is_err());
    }
    #[test]
    fn single_origin_sets_host_and_rejects_ambiguous_or_unsafe_urls() {
        let sample = include_str!("../../config.example.toml");
        let c = crate::config::Config::parse(&sample.replace(
            "origin = \"http://127.0.0.1:8080\"",
            "origin = \"https://origin.example.net:8443/\"",
        ))
        .unwrap();
        assert_eq!(
            c.website.upstreams[0].host_header.as_deref(),
            Some("origin.example.net:8443")
        );
        assert_eq!(c.website.routes[0].path_prefix, "/");
        assert!(!c.website.routes[0].strip_prefix);
        for origin in [
            "https://user:secret@host.test",
            "https://host.test/path",
            "https://host.test/?q=x",
            "http://host.test:0",
            "ftp://host.test",
        ] {
            assert!(
                crate::config::Config::parse(&sample.replace("http://127.0.0.1:8080", origin))
                    .is_err()
            );
        }
        for extra in ["routes=[]", "upstreams=[]", "compression_levell=5"] {
            assert!(
                crate::config::Config::parse(
                    &sample.replace("[website]", &format!("[website]\n{extra}"))
                )
                .is_err()
            );
        }
    }
    #[test]
    fn website_example_merges_with_strict_main_toml() {
        let example = include_str!("../../docs/PROJECT.md")
            .split("## 网站路由示例")
            .nth(1)
            .unwrap()
            .split("```toml\n")
            .nth(1)
            .unwrap()
            .split("```")
            .next()
            .unwrap();
        let sample = include_str!("../../config.example.toml");
        let mut doc: toml::Value = toml::from_str(sample).unwrap();
        let example: toml::Value = toml::from_str(example).unwrap();
        doc["website"] = example["website"].clone();
        let text = toml::to_string(&doc).unwrap();
        assert!(crate::config::Config::parse(&text).is_ok());
        assert!(
            crate::config::Config::parse(
                &text.replace("compression_level = 5", "compression_levell = 5")
            )
            .is_err()
        );
    }
}
