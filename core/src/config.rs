use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    pub domain: String,
    #[serde(default)]
    pub credentials_file: PathBuf,
    #[serde(default)]
    pub proxy: Proxy,
    #[serde(default = "state_dir")]
    pub state_dir: PathBuf,
    #[serde(default)]
    pub listener: Listener,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub traffic: Traffic,
    #[serde(default)]
    pub ech: Option<Ech>,
    #[serde(default, deserialize_with = "crate::website::deserialize_config")]
    pub website: crate::website::Website,
    #[serde(default)]
    pub limits: Limits,
    pub acme: Acme,
}

fn schema_version() -> u32 {
    2
}
fn state_dir() -> PathBuf {
    "/var/lib/moon-naive".into()
}

/// Locally permitted features; each CONNECT still needs authenticated negotiation.
#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(default, deny_unknown_fields)]
pub struct Traffic {
    pub initial_records: u8,
    pub sparse_padding: bool,
}
impl Default for Traffic {
    fn default() -> Self {
        Self {
            initial_records: 16,
            sparse_padding: true,
        }
    }
}
impl Traffic {
    pub fn select(self, offer: crate::codec::Offer) -> crate::codec::Mode {
        offer.select(self.initial_records, self.sparse_padding)
    }
}
/// ECH secrets remain separate from the public DNS ECHConfigList.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ech {
    pub keys_file: PathBuf,
    pub public_name: String,
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    #[serde(default)]
    pub quic_congestion: QuicCongestion,
    #[serde(default)]
    pub tcp_congestion: TcpCongestion,
}
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QuicCongestion {
    #[default]
    Cubic,
    Bbr2,
}
impl QuicCongestion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cubic => "cubic",
            Self::Bbr2 => "bbr2",
        }
    }
}
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TcpCongestion {
    #[default]
    System,
    Bbr,
}
impl TcpCongestion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Bbr => "bbr",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Listener {
    /// Public/NAT frontend addresses not discoverable by binding a local socket.
    pub public_addresses: Vec<std::net::IpAddr>,
    #[serde(default = "https_listener")]
    pub tcp: SocketAddr,
    #[serde(default = "https_listener")]
    pub udp: SocketAddr,
    pub h2: bool,
    pub h3: bool,
    pub h1: bool,
    #[serde(default)]
    pub http_redirect: Option<SocketAddr>,
}
impl Default for Listener {
    fn default() -> Self {
        Self {
            public_addresses: Vec::new(),
            tcp: https_listener(),
            udp: https_listener(),
            h2: true,
            h3: true,
            h1: true,
            http_redirect: None,
        }
    }
}
fn https_listener() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 443))
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_streams: usize,
    pub max_connections: usize,
    pub max_pending_requests: usize,
    pub max_tunnels_per_user: usize,
    pub max_early_data_bytes: usize,
    pub max_buffer_bytes_per_stream: usize,
    #[serde(default = "receive_budget")]
    pub max_total_receive_bytes: usize,
    pub max_total_buffer_bytes: usize,
    pub connect_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub graceful_timeout_secs: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_streams: 100,
            max_connections: 128,
            max_pending_requests: 100,
            max_tunnels_per_user: 100,
            max_early_data_bytes: 65536,
            max_buffer_bytes_per_stream: 262144,
            max_total_receive_bytes: receive_budget(),
            max_total_buffer_bytes: receive_budget(),
            connect_timeout_secs: 15,
            idle_timeout_secs: 600,
            graceful_timeout_secs: 300,
        }
    }
}
fn receive_budget() -> usize {
    64 * 1024 * 1024
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Acme {
    #[serde(default)]
    pub issuer: Issuer,
    pub enabled: bool,
    pub environment: Environment,
    pub challenge: Challenge,
    pub dns_provider: String,
    #[serde(default)]
    pub dns_token_file: PathBuf,
    #[serde(default)]
    pub dns_credentials: Option<DnsCredentials>,
    #[serde(default)]
    pub eab: Option<EabCredentials>,
    pub contact: String,
    pub accept_terms: bool,
    pub renew_before_secs: u64,
    pub retry_initial_secs: u64,
    pub retry_max_secs: u64,
    #[serde(default)]
    pub directory_url: Option<String>,
    #[serde(default)]
    pub directory_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub certificate_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub dns_zone_id: Option<String>,
    #[serde(default)]
    pub dns_zone: Option<String>,
    #[serde(default)]
    pub eab_credentials_file: Option<PathBuf>,
    #[serde(default = "request_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default = "operation_timeout")]
    pub operation_timeout_secs: u64,
    #[serde(default = "poll_interval")]
    pub poll_interval_secs: u64,
}
impl Default for Acme {
    fn default() -> Self {
        Self {
            // Preserve the historical issuer default. The unified example
            // selects Google explicitly; existing LE accounts must not move.
            issuer: Issuer::Letsencrypt,
            enabled: true,
            environment: Environment::Staging,
            challenge: Challenge::Dns01,
            dns_provider: "porkbun".into(),
            dns_token_file: PathBuf::new(),
            dns_credentials: None,
            eab: None,
            contact: String::new(),
            accept_terms: false,
            renew_before_secs: 2592000,
            retry_initial_secs: 60,
            retry_max_secs: 21600,
            directory_url: None,
            directory_ca_file: None,
            certificate_ca_file: None,
            dns_zone_id: None,
            dns_zone: None,
            eab_credentials_file: None,
            request_timeout_secs: request_timeout(),
            operation_timeout_secs: operation_timeout(),
            poll_interval_secs: poll_interval(),
        }
    }
}
#[derive(Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Issuer {
    #[default]
    Letsencrypt,
    Google,
}
impl Acme {
    pub fn directory(&self) -> &str {
        self.directory_url
            .as_deref()
            .unwrap_or_else(|| match (&self.issuer, &self.environment) {
                (Issuer::Google, Environment::Staging) => {
                    "https://dv.acme-v02.test-api.pki.goog/directory"
                }
                (Issuer::Google, Environment::Production) => {
                    "https://dv.acme-v02.api.pki.goog/directory"
                }
                (Issuer::Letsencrypt, _) => self.environment.directory(),
            })
    }
}
fn request_timeout() -> u64 {
    30
}
fn operation_timeout() -> u64 {
    900
}
fn poll_interval() -> u64 {
    5
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Staging,
    Production,
}

impl Environment {
    pub fn directory(&self) -> &'static str {
        match self {
            Self::Staging => "https://acme-staging-v02.api.letsencrypt.org/directory",
            Self::Production => "https://acme-v02.api.letsencrypt.org/directory",
        }
    }
}

#[derive(Debug, Deserialize)]
pub enum Challenge {
    #[serde(rename = "dns-01")]
    Dns01,
}

impl Config {
    /// Return the configured canonical website name, never an arbitrary Host.
    pub fn site_name(&self, host: &str) -> Option<&str> {
        if host.eq_ignore_ascii_case(&self.domain) {
            return Some(&self.domain);
        }
        self.ech
            .as_ref()
            .filter(|ech| host.eq_ignore_ascii_case(&ech.public_name))
            .map(|ech| ech.public_name.as_str())
    }

    pub fn parse(text: &str) -> Result<Self, &'static str> {
        // Do not echo arbitrary config text, which could contain misplaced secrets.
        let cfg: Self =
            toml::from_str(text).map_err(|_| "invalid TOML, missing or unknown field")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        self.website.validate()?;
        if !matches!(self.traffic.initial_records, 8 | 16) {
            return Err("traffic initial_records must be 8 or 16");
        }
        if let Some(ech) = &self.ech
            && (!crate::policy::valid_dns_name(&ech.public_name)
                || !ech.public_name.contains('.')
                || !ech.keys_file.is_absolute()
                || !ech.certificate_file.is_absolute()
                || !ech.private_key_file.is_absolute())
        {
            return Err("ECH requires a public DNS name and absolute file paths");
        }
        if !matches!(self.schema_version, 1 | 2) {
            return Err("unsupported schema_version");
        }
        if !crate::policy::valid_dns_name(&self.domain) || !self.domain.contains('.') {
            return Err("domain must be an ASCII DNS name (use punycode for IDNs)");
        }
        if !self.listener.h2 || !self.listener.h3 {
            return Err("both h2 and h3 are required");
        }
        if self.listener.tcp.port() == 0 || self.listener.udp.port() == 0 {
            return Err("listener port cannot be zero");
        }
        let l = &self.limits;
        if l.max_streams == 0
            || l.max_streams > 1024
            || u32::try_from(l.max_streams).is_err()
            || l.max_connections == 0
            || l.max_connections > 4096
            || l.max_pending_requests == 0
            || l.max_pending_requests > 4096
            || l.max_tunnels_per_user == 0
            || l.max_tunnels_per_user > 4096
            || l.max_early_data_bytes == 0
            || l.max_early_data_bytes > 1024 * 1024
            || l.max_buffer_bytes_per_stream < l.max_early_data_bytes
            || l.max_buffer_bytes_per_stream > 4 * 1024 * 1024
            || l.max_buffer_bytes_per_stream < 16 * 1024
            || l.max_total_receive_bytes < 65_535
            || l.max_total_receive_bytes > 1024 * 1024 * 1024
            || l.max_total_buffer_bytes < 2 * 16 * 1024
            || l.max_total_buffer_bytes > 1024 * 1024 * 1024
            || l.connect_timeout_secs == 0
            || l.idle_timeout_secs == 0
            || l.idle_timeout_secs.checked_mul(1000).is_none()
            || l.graceful_timeout_secs == 0
        {
            return Err("invalid or unbounded resource limits");
        }
        let a = &self.acme;
        if !a.enabled
            || a.dns_provider.is_empty()
            || !a.contact.contains('@')
            || a.contact.chars().any(char::is_control)
            || a.renew_before_secs == 0
            || a.retry_initial_secs == 0
            || a.retry_max_secs < a.retry_initial_secs
        {
            return Err("automatic DNS-01 ACME and bounded retry settings are required");
        }
        // Parsing/check-config is offline, even with terms declined. Manager::open
        // requires explicit acceptance before any live ACME work in either environment.
        if !matches!(a.dns_provider.as_str(), "porkbun" | "cloudflare") {
            return Err("DNS provider must be porkbun or cloudflare");
        }
        if a.dns_provider == "cloudflare"
            && a.dns_zone_id
                .as_ref()
                .is_none_or(|zone| zone.len() != 32 || !zone.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("Cloudflare requires a 32-character dns_zone_id");
        }
        if a.issuer == Issuer::Google && a.eab_credentials_file.is_none() && a.eab.is_none() {
            return Err("Google Trust Services requires acme.eab or eab_credentials_file");
        }
        if a.dns_provider == "porkbun"
            && a.dns_zone.as_ref().is_none_or(|zone| {
                let zone = zone.to_ascii_lowercase();
                let domain = self.domain.to_ascii_lowercase();
                !crate::policy::valid_dns_name(&zone)
                    || !zone.contains('.')
                    || (domain != zone && !domain.ends_with(&format!(".{zone}")))
            })
        {
            return Err("Porkbun requires dns_zone containing the configured domain");
        }
        if !(1..=300).contains(&a.request_timeout_secs)
            || !(30..=3600).contains(&a.operation_timeout_secs)
            || !(1..=60).contains(&a.poll_interval_secs)
            || a.directory_url.as_ref().is_some_and(|url| {
                url.parse::<http::Uri>().map_or(true, |uri| {
                    uri.scheme_str() != Some("https")
                        || uri.authority().is_none_or(|a| a.as_str().contains('@'))
                        || uri.host().is_none_or(str::is_empty)
                        || uri.port_u16() == Some(0)
                })
            })
        {
            return Err("invalid ACME endpoint or deadline settings");
        }
        if self.credentials_file.as_os_str().is_empty() == self.proxy.users.is_empty() {
            return Err("configure exactly one proxy credential source");
        }
        if a.dns_token_file.as_os_str().is_empty() == a.dns_credentials.is_none() {
            return Err("configure exactly one DNS credential source");
        }
        if a.eab.is_some() && a.eab_credentials_file.is_some() {
            return Err("configure exactly one EAB credential source");
        }
        if let Some(eab) = &a.eab {
            eab.validate()?;
        }
        if let Some(credentials) = &a.dns_credentials {
            let nonempty = |value: &Option<String>| {
                value.as_ref().is_some_and(|s| {
                    !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control)
                })
            };
            let valid = match a.dns_provider.as_str() {
                "porkbun" => {
                    nonempty(&credentials.apikey)
                        && nonempty(&credentials.secretapikey)
                        && credentials.api_token.is_none()
                }
                "cloudflare" => {
                    nonempty(&credentials.api_token)
                        && credentials.apikey.is_none()
                        && credentials.secretapikey.is_none()
                }
                _ => false,
            };
            if !valid {
                return Err("invalid inline DNS credentials for selected provider");
            }
        }
        self.proxy.validate()?;
        if self
            .listener
            .http_redirect
            .is_some_and(|a| a.port() == 0 || a == self.listener.tcp)
        {
            return Err("invalid HTTP redirect listener");
        }
        if !self.state_dir.is_absolute() {
            return Err("state_dir must be an absolute persistent directory");
        }
        for path in [&self.credentials_file, &self.state_dir, &a.dns_token_file]
            .into_iter()
            .filter(|p| !p.as_os_str().is_empty())
            .chain(a.directory_ca_file.iter())
            .chain(a.certificate_ca_file.iter())
            .chain(a.eab_credentials_file.iter())
        {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|c| c == std::path::Component::ParentDir)
            {
                return Err("configured paths must be absolute without parent traversal");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SAMPLE: &str = include_str!("../../config.example.toml");

    #[test]
    fn minimal_single_file_defaults_and_partial_overrides() {
        let c = Config::parse(SAMPLE).unwrap();
        assert_eq!(c.schema_version, 2);
        assert_eq!(c.state_dir, PathBuf::from("/var/lib/moon-naive"));
        assert_eq!(c.listener.tcp, "0.0.0.0:443".parse().unwrap());
        assert_eq!(c.listener.udp, c.listener.tcp);
        assert!(c.listener.h1 && c.listener.h2 && c.listener.h3);
        assert!(c.listener.http_redirect.is_none());
        assert_eq!(c.limits.max_streams, 100);
        assert_eq!(c.acme.dns_provider, "porkbun");
        assert_eq!(c.acme.retry_max_secs, 21600);
        assert_eq!(c.acme.environment, Environment::Production);
        assert!(!c.acme.accept_terms); // Offline parsing never accepts terms on behalf of the user.
        let c = Config::parse(&format!("{SAMPLE}\n[listener]\ntcp='127.0.0.1:8443'\nh1=false\n[limits]\nidle_timeout_secs=900\n")).unwrap();
        assert_eq!(c.listener.tcp.port(), 8443);
        assert_eq!(c.listener.udp.port(), 443);
        assert!(!c.listener.h1);
        assert_eq!(c.limits.idle_timeout_secs, 900);
        assert_eq!(c.limits.max_streams, 100);
    }
    #[test]
    fn transport_defaults_and_explicit_bbr_versions_are_unambiguous() {
        let c = Config::parse(SAMPLE).unwrap();
        assert_eq!(c.transport.quic_congestion, QuicCongestion::Cubic);
        assert_eq!(c.transport.tcp_congestion, TcpCongestion::System);
        let c = Config::parse(&format!(
            "{SAMPLE}\n[transport]\nquic_congestion='bbr2'\ntcp_congestion='bbr'\n"
        ))
        .unwrap();
        assert_eq!(c.transport.quic_congestion, QuicCongestion::Bbr2);
        assert_eq!(c.transport.tcp_congestion, TcpCongestion::Bbr);
        for transport in [
            "backend='rustls-quinn'",
            "quic_congestion='bbr'",
            "quic_congestion='bbr3'",
            "tcp_congestion='quic-bbr'",
            "typo=true",
        ] {
            assert!(Config::parse(&format!("{SAMPLE}\n[transport]\n{transport}")).is_err());
        }
    }
    #[test]
    fn receive_window_budget_defaults_and_cannot_underfund_one_connection() {
        let mut c = Config::parse(SAMPLE).unwrap();
        assert_eq!(c.limits.max_total_receive_bytes, 64 * 1024 * 1024);
        c.limits.max_total_receive_bytes = 1024;
        assert!(c.validate().is_err());
        c.limits.max_total_receive_bytes = 2 * 1024 * 1024 * 1024;
        assert!(c.validate().is_err());
    }
    #[test]
    fn google_directory_selection_and_porkbun_zone_boundaries() {
        let mut c = Config::parse(SAMPLE).unwrap();
        assert_eq!(
            c.acme.directory(),
            "https://dv.acme-v02.api.pki.goog/directory"
        );
        c.acme.environment = Environment::Staging;
        assert_eq!(
            c.acme.directory(),
            "https://dv.acme-v02.test-api.pki.goog/directory"
        );
        c.domain = "example.dev".into();
        assert!(c.validate().is_ok());
        for domain in ["badexample.dev", "proxy.other.dev"] {
            c.domain = domain.into();
            assert!(c.validate().is_err());
        }
        c.domain = "proxy.example.dev".into();
        c.acme.eab = None;
        assert!(c.validate().is_err());
        c.acme.eab_credentials_file = Some("relative.toml".into());
        assert!(c.validate().is_err());
    }
    #[test]
    fn offline_validation_checks_credentials_and_ca_without_exposing_secrets() {
        let mut c = Config::parse(SAMPLE).unwrap();
        c.acme.eab.as_mut().unwrap().b64_mac_key = "not!base64-secret".into();
        assert_eq!(c.validate(), Err("invalid EAB base64url MAC key"));
        assert!(!format!("{c:?}").contains("not!base64-secret"));
        c.acme.eab = None;
        c.acme.issuer = Issuer::Letsencrypt;
        c.acme.dns_provider = "typo".into();
        assert!(c.validate().is_err());
        c.acme.dns_provider = "cloudflare".into();
        c.acme.dns_credentials = Some(DnsCredentials {
            api_token: Some("test-token".into()),
            apikey: None,
            secretapikey: None,
        });
        assert!(c.validate().is_err());
        c.acme.dns_zone_id = Some("0123456789abcdef0123456789abcdef".into());
        assert!(c.validate().is_ok());
        for url in [
            "http://ca.test/dir",
            "https://",
            "https://user:pass@ca.test/dir",
            "https://ca.test:0/dir",
        ] {
            c.acme.directory_url = Some(url.into());
            assert!(c.validate().is_err());
        }
    }
    #[test]
    fn omitted_issuer_preserves_legacy_letsencrypt_default() {
        let c = Config::parse(&SAMPLE.replace("issuer = \"google\"", "")).unwrap();
        assert_eq!(c.acme.issuer, Issuer::Letsencrypt);
        assert_eq!(
            c.acme.directory(),
            "https://acme-v02.api.letsencrypt.org/directory"
        );
    }
    #[test]
    fn rejects_unknown_keys_retired_toggles_and_unbounded_settings() {
        for extra in [
            "[listener]\nh2=false",
            "[listener]\nh3=false",
            "[listener]\nfast_open=false",
            "[listener]\nzero_rtt=true",
            "[limits]\nmax_streams=0",
            "[limits]\nmax_streams=99999",
            "[limits]\nidle_timeout_sec=10",
        ] {
            assert!(
                Config::parse(&format!("{SAMPLE}\n{extra}")).is_err(),
                "{extra}"
            );
        }
        for field in [
            "unexpected=true",
            "state_dir='relative'",
            "state_dir=''",
            "schema_version=99",
            "credentials_file='/etc/users.toml'",
        ] {
            assert!(Config::parse(&format!("{field}\n{SAMPLE}")).is_err());
        }
        for field in [
            "enabled=false",
            "challenge='http-01'",
            "challenge='tls-alpn-01'",
        ] {
            assert!(Config::parse(&SAMPLE.replace("[acme]", &format!("[acme]\n{field}"))).is_err());
        }
    }
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct Proxy {
    pub users: Vec<User>,
    pub upstream: Option<ProxyUpstream>,
}
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub username: String,
    pub password: String,
}
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DnsCredentials {
    pub apikey: Option<String>,
    pub secretapikey: Option<String>,
    pub api_token: Option<String>,
}
#[derive(Deserialize, serde::Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct EabCredentials {
    pub key_id: String,
    pub b64_mac_key: String,
}
impl EabCredentials {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.mac().map(|_| ())
    }
    pub fn mac(&self) -> Result<Vec<u8>, &'static str> {
        use base64::{
            Engine,
            engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
        };
        if self.key_id.is_empty()
            || self.key_id.len() > 1024
            || self.key_id.chars().any(char::is_control)
        {
            return Err("invalid EAB key ID");
        }
        let key = URL_SAFE_NO_PAD
            .decode(&self.b64_mac_key)
            .or_else(|_| URL_SAFE.decode(&self.b64_mac_key))
            .map_err(|_| "invalid EAB base64url MAC key")?;
        if !(16..=4096).contains(&key.len()) {
            return Err("invalid EAB MAC key length");
        }
        Ok(key)
    }
}
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProxyUpstream {
    pub kind: ProxyKind,
    pub address: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls_server_name: Option<String>,
    pub ca_file: Option<PathBuf>,
}
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    Http,
    Https,
    Socks5,
}
macro_rules! private_debug {
    ($($t:ty),*) => {$ (impl std::fmt::Debug for $t {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(concat!(stringify!($t), "([redacted])"))
        }
    })*};
}
private_debug!(User, DnsCredentials, EabCredentials, ProxyUpstream);
impl Proxy {
    fn validate(&self) -> Result<(), &'static str> {
        if !self.users.is_empty() {
            crate::auth::Credentials::new(
                &self
                    .users
                    .iter()
                    .map(|u| (u.username.as_str(), u.password.as_str()))
                    .collect::<Vec<_>>(),
            )?;
            if self
                .users
                .iter()
                .map(|u| &u.username)
                .collect::<std::collections::HashSet<_>>()
                .len()
                != self.users.len()
            {
                return Err("duplicate proxy usernames");
            }
        }
        if let Some(u) = &self.upstream {
            crate::policy::Authority::parse(&u.address)?;
            if u.username.is_some() != u.password.is_some()
                || u.username.as_ref().is_some_and(|s| {
                    s.is_empty()
                        || s.len() > 255
                        || s.contains(':')
                        || s.chars().any(char::is_control)
                })
                || u.password.as_ref().is_some_and(|s| {
                    s.is_empty() || s.len() > 255 || s.chars().any(char::is_control)
                })
                || (u.kind != ProxyKind::Https
                    && (u.tls_server_name.is_some() || u.ca_file.is_some()))
                || u.ca_file.as_ref().is_some_and(|p| {
                    !p.is_absolute() || p.components().any(|c| c == std::path::Component::ParentDir)
                })
                || u.tls_server_name
                    .as_ref()
                    .is_some_and(|s| !crate::policy::valid_dns_name(s))
            {
                return Err("invalid upstream proxy configuration");
            }
        }
        Ok(())
    }
}

// Shared startup resource policy for H2/H3, independent of authentication.
pub struct TransportProfile {
    idle_timeout_ms: u64,
    max_streams: u32,
    stream_window: u32,
    connection_window: u32,
    quic_congestion: QuicCongestion,
}

impl TransportProfile {
    pub fn from_config(config: &Config) -> Result<Self, &'static str> {
        config.validate()?;
        let limits = &config.limits;
        let idle_timeout_ms = limits
            .idle_timeout_secs
            .checked_mul(1000)
            .ok_or("idle timeout overflows milliseconds")?;
        let max_streams =
            u32::try_from(limits.max_streams).map_err(|_| "max_streams exceeds transport range")?;
        let stream_window = u32::try_from(limits.max_buffer_bytes_per_stream)
            .map_err(|_| "stream window exceeds transport range")?;
        // Keep connection-level flow control bounded even at high stream counts.
        // These are wire credits, not a substitute for application memory permits.
        // Reserve the entire non-revocable rolling credit for the connection's
        // lifetime, including after authenticated streams finish. Divide the
        // configured budget across connection slots instead of reserving 16 MiB
        // unconditionally. H2's initial connection credit cannot be reduced.
        let fair_share = (limits.max_total_receive_bytes / limits.max_connections)
            .clamp(65_535, 16 * 1024 * 1024);
        let connection_window = (u64::from(stream_window) * u64::from(max_streams))
            .clamp(65_535, fair_share as u64) as u32;
        Ok(Self {
            idle_timeout_ms,
            max_streams,
            stream_window,
            connection_window,
            quic_congestion: config.transport.quic_congestion,
        })
    }
    pub fn idle_timeout_ms(&self) -> u64 {
        self.idle_timeout_ms
    }
    pub fn max_streams(&self) -> u32 {
        self.max_streams
    }
    pub fn stream_window(&self) -> u32 {
        self.stream_window
    }
    /// Bound aggregate stalled request DATA so control/QPACK can still progress.
    /// These are transport credits; application authentication never owns them.
    pub fn h3_control_reserve(&self) -> u32 {
        (self.connection_window / 4).min(64 * 1024)
    }
    pub fn h3_stream_window(&self) -> u32 {
        self.stream_window
            .min((self.connection_window - self.h3_control_reserve()) / self.max_streams)
    }
    pub fn connection_window(&self) -> u32 {
        self.connection_window
    }
    pub fn quic_congestion(&self) -> QuicCongestion {
        self.quic_congestion
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    const SAMPLE: &str = include_str!("../../config.example.toml");
    #[test]
    fn shared_values_follow_config_and_connection_credit_is_capped() {
        let config = Config::parse(SAMPLE).unwrap();
        let profile = TransportProfile::from_config(&config).unwrap();
        assert_eq!(profile.idle_timeout_ms(), 600_000);
        assert_eq!(profile.max_streams(), 100);
        assert_eq!(profile.stream_window(), 262_144);
        assert_eq!(profile.connection_window(), 512 * 1024);
        assert!(
            profile.h3_stream_window() * profile.max_streams() + profile.h3_control_reserve()
                <= profile.connection_window()
        );
        let config = Config::parse(&format!("{SAMPLE}\n[limits]\nmax_streams=1\n")).unwrap();
        assert_eq!(
            TransportProfile::from_config(&config)
                .unwrap()
                .connection_window(),
            262_144
        );
    }
    #[test]
    fn minimum_credit_and_control_progress_are_budgeted() {
        let mut config = Config::parse(SAMPLE).unwrap();
        config.limits.max_streams = 1;
        config.limits.max_buffer_bytes_per_stream = 16 * 1024;
        config.limits.max_early_data_bytes = 16 * 1024;
        config.limits.max_total_receive_bytes = 65_535;
        let profile = TransportProfile::from_config(&config).unwrap();
        assert_eq!(profile.connection_window(), 65_535);
        assert!(profile.h3_stream_window() + profile.h3_control_reserve() <= 65_535);
        config.limits.max_pending_requests = 0;
        assert!(config.validate().is_err());
    }
    #[test]
    fn unsupported_transport_values_are_rejected() {
        let mut config = Config::parse(SAMPLE).unwrap();
        config.limits.idle_timeout_secs = u64::MAX;
        assert!(TransportProfile::from_config(&config).is_err());
        config.limits.idle_timeout_secs = 600;
        config.limits.max_streams = usize::MAX;
        assert!(TransportProfile::from_config(&config).is_err());
    }
}
