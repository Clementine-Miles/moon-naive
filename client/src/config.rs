//! Client configuration (TOML). Secrets never appear in Debug output or logs.
use serde::Deserialize;
use std::{fmt, net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    /// HTTP/2 over TLS 1.3 on TCP.
    #[default]
    H2,
    /// HTTP/3 over QUIC.
    H3,
    /// Prefer HTTP/3; use HTTP/2 only when a QUIC connection cannot be
    /// established. Authentication, certificate and ECH policy are identical
    /// on both transports, so the fallback never weakens security.
    H3ThenH2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Server `host:port` to connect to (DNS name, IPv4, or `[IPv6]:port`).
    pub server: String,
    /// TLS server name used for SNI (or the ECH inner name) and certificate
    /// verification. Defaults to the host part of `server`.
    #[serde(default)]
    pub server_name: Option<String>,
    /// Local listener accepting both SOCKS5 and HTTP CONNECT.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub transport: Transport,
    /// PEM trust anchors. Defaults to the system trust store. Certificate
    /// verification cannot be disabled.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Base64 ECHConfigList (as printed by `moon-naive ech dns`). When set,
    /// ECH is mandatory: a connection the server does not accept with ECH
    /// fails instead of falling back to a cleartext server name.
    #[serde(default)]
    pub ech_config_list: Option<String>,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_handshake_timeout")]
    pub local_handshake_timeout_secs: u64,
    #[serde(default = "default_max_tunnels")]
    pub max_tunnels: usize,
    /// QUIC idle timeout; the connection is re-established on demand.
    #[serde(default = "default_quic_idle")]
    pub quic_idle_timeout_secs: u64,
    /// `error`, `info` or `debug`. Logs never contain credentials or proofs.
    #[serde(default = "default_log")]
    pub log_level: String,
}
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("server", &self.server)
            .field("server_name", &self.server_name)
            .field("listen", &self.listen)
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("transport", &self.transport)
            .field("ca_file", &self.ca_file)
            .field("ech", &self.ech_config_list.is_some())
            .finish_non_exhaustive()
    }
}
fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 1080))
}
fn default_connect_timeout() -> u64 {
    15
}
fn default_handshake_timeout() -> u64 {
    10
}
fn default_max_tunnels() -> usize {
    256
}
fn default_quic_idle() -> u64 {
    30
}
fn default_log() -> String {
    "info".into()
}

/// Validated, ready-to-use settings derived from [`Config`].
pub struct Settings {
    pub host: String,
    pub port: u16,
    pub server_name: String,
    pub listen: SocketAddr,
    pub credentials: moon_naive_core::auth::Credentials,
    pub transport: Transport,
    pub ca_file: Option<PathBuf>,
    pub ech_config_list: Option<Vec<u8>>,
    pub connect_timeout: Duration,
    pub local_handshake_timeout: Duration,
    pub max_tunnels: usize,
    pub quic_idle_timeout: Duration,
    pub log: LogLevel,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Info,
    Debug,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| format!("invalid client configuration: {}", e.message()))
    }
    pub fn settings(&self) -> Result<Settings, String> {
        let (host, port) = split_host_port(&self.server)?;
        let server_name = self.server_name.clone().unwrap_or_else(|| host.clone());
        if server_name.is_empty()
            || server_name.parse::<std::net::IpAddr>().is_ok()
            || !moon_naive_core::policy::valid_dns_name(&server_name.to_ascii_lowercase())
        {
            return Err("server_name must be an ASCII DNS name matching the certificate".into());
        }
        let credentials =
            moon_naive_core::auth::Credentials::new(&[(&self.username, &self.password)])
                .map_err(str::to_owned)?;
        let ech_config_list = match &self.ech_config_list {
            None => None,
            Some(text) => {
                use base64::Engine;
                let list = base64::engine::general_purpose::STANDARD
                    .decode(text.trim())
                    .map_err(|_| "ech_config_list must be standard Base64")?;
                validate_ech_config_list(&list)?;
                Some(list)
            }
        };
        let bounded = |value: u64, range: std::ops::RangeInclusive<u64>, name: &str| {
            if range.contains(&value) {
                Ok(Duration::from_secs(value))
            } else {
                Err(format!("{name} must be within {range:?} seconds"))
            }
        };
        if !(1..=4096).contains(&self.max_tunnels) {
            return Err("max_tunnels must be within 1..=4096".into());
        }
        let log = match self.log_level.as_str() {
            "error" => LogLevel::Error,
            "info" => LogLevel::Info,
            "debug" => LogLevel::Debug,
            _ => return Err("log_level must be error, info or debug".into()),
        };
        Ok(Settings {
            host,
            port,
            server_name,
            listen: self.listen,
            credentials,
            transport: self.transport,
            ca_file: self.ca_file.clone(),
            ech_config_list,
            connect_timeout: bounded(self.connect_timeout_secs, 1..=120, "connect_timeout_secs")?,
            local_handshake_timeout: bounded(
                self.local_handshake_timeout_secs,
                1..=120,
                "local_handshake_timeout_secs",
            )?,
            max_tunnels: self.max_tunnels,
            quic_idle_timeout: bounded(
                self.quic_idle_timeout_secs,
                5..=600,
                "quic_idle_timeout_secs",
            )?,
            log,
        })
    }
}

/// Split `host:port`, accepting `[v6]:port`. The port is mandatory.
pub fn split_host_port(value: &str) -> Result<(String, u16), String> {
    let invalid = || format!("invalid host:port {value:?}");
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").ok_or_else(invalid)?;
        host.parse::<std::net::Ipv6Addr>().map_err(|_| invalid())?;
        (host, port)
    } else {
        let (host, port) = value.rsplit_once(':').ok_or_else(invalid)?;
        if host.contains(':') || host.is_empty() {
            return Err(invalid());
        }
        (host, port)
    };
    let port: u16 = port.parse().map_err(|_| invalid())?;
    if port == 0 {
        return Err(invalid());
    }
    Ok((host.to_owned(), port))
}

/// Structural check of an ECHConfigList (RFC 9849, section 4): a u16 length
/// covering one or more `u16 version, u16 length, contents` entries. BoringSSL
/// performs the full parse; this rejects obviously truncated input early.
pub fn validate_ech_config_list(list: &[u8]) -> Result<(), String> {
    let invalid = || "malformed ECHConfigList".to_string();
    let (length, mut rest) = list.split_first_chunk::<2>().ok_or_else(invalid)?;
    if usize::from(u16::from_be_bytes(*length)) != rest.len() || rest.is_empty() {
        return Err(invalid());
    }
    while !rest.is_empty() {
        let (header, tail) = rest.split_first_chunk::<4>().ok_or_else(invalid)?;
        let size = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if tail.len() < size {
            return Err(invalid());
        }
        rest = &tail[size..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const MINIMAL: &str = "server = 'proxy.example.com:443'\nusername = 'alice'\npassword = 'a-long-high-entropy-secret'\n";
    #[test]
    fn defaults_are_conservative_and_secrets_are_redacted() {
        let config = Config::parse(MINIMAL).unwrap();
        let settings = config.settings().unwrap();
        assert_eq!(settings.server_name, "proxy.example.com");
        assert_eq!(settings.listen, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(settings.transport, Transport::H2);
        assert!(settings.ech_config_list.is_none());
        let debug = format!("{config:?}");
        assert!(!debug.contains("a-long-high-entropy-secret") && !debug.contains("alice"));
    }
    #[test]
    fn rejects_weak_secrets_bad_servers_and_unknown_keys() {
        let weak = MINIMAL.replace("a-long-high-entropy-secret", "short");
        assert!(Config::parse(&weak).unwrap().settings().is_err());
        for server in [
            "proxy.example.com",
            "proxy.example.com:0",
            "::1:443",
            "[::1]",
        ] {
            let text = MINIMAL.replace("proxy.example.com:443", server);
            assert!(
                Config::parse(&text).unwrap().settings().is_err(),
                "{server}"
            );
        }
        let ip = MINIMAL.replace("proxy.example.com:443", "[2001:db8::1]:443");
        assert!(
            Config::parse(&ip).unwrap().settings().is_err(),
            "IP needs server_name"
        );
        let named = format!("{ip}server_name = 'proxy.example.com'\n");
        assert_eq!(Config::parse(&named).unwrap().settings().unwrap().port, 443);
        assert!(Config::parse(&format!("{MINIMAL}insecure = true\n")).is_err());
        let fast = format!("{MINIMAL}transport = 'h3-then-h2'\n");
        assert_eq!(
            Config::parse(&fast).unwrap().settings().unwrap().transport,
            Transport::H3ThenH2
        );
    }
    #[test]
    fn shipped_example_is_valid() {
        let settings = Config::parse(include_str!("../../client.example.toml"))
            .unwrap()
            .settings()
            .unwrap();
        assert_eq!(settings.transport, Transport::H3ThenH2);
        assert!(settings.listen.ip().is_loopback());
    }
    #[test]
    fn ech_config_list_structure_is_checked() {
        assert!(validate_ech_config_list(&[0, 4, 0xfe, 0x0d, 0, 0]).is_ok());
        assert!(validate_ech_config_list(&[0, 5, 0xfe, 0x0d, 0, 1]).is_err());
        assert!(validate_ech_config_list(&[0, 0]).is_err());
        assert!(validate_ech_config_list(&[0, 4, 0xfe, 0x0d, 0, 9]).is_err());
    }
}
