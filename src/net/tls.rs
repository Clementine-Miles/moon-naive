use super::{Config, Result, TransportProfile};
use crate::acme::store::DiskStore;
use boring::{
    pkey::PKey,
    ssl::{AlpnError, SslAcceptor, SslContextBuilder, SslMethod, SslVersion, select_next_proto},
    x509::X509,
};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::watch;

pub(super) struct Generation {
    pub id: String,
    ech_stamp: Option<[u8; 32]>,
    pub h2: SslAcceptor,
    pub h3: Mutex<quiche::Config>,
    pub not_after: u64,
}
#[derive(Clone)]
pub(super) struct Slot(Arc<RwLock<Arc<Generation>>>);
impl Slot {
    pub fn load(config: &Config) -> Result<Self> {
        Ok(Self(Arc::new(RwLock::new(Arc::new(load(config)?)))))
    }
    pub fn current(&self) -> Result<Arc<Generation>> {
        let generation = self
            .0
            .read()
            .map_err(|_| "TLS generation lock poisoned")?
            .clone();
        if crate::acme::now() >= generation.not_after {
            return Err("no unexpired TLS generation".into());
        }
        Ok(generation)
    }
    pub(super) fn refresh(&self, config: &Config) -> Result<bool> {
        let current = self
            .0
            .read()
            .map_err(|_| "TLS generation lock poisoned")?
            .clone();
        let id = DiskStore::open(&config.state_dir.join("certificates"))?.current_generation()?;
        if id.as_deref() == Some(current.id.as_str()) && ech_stamp(config)? == current.ech_stamp {
            return Ok(false);
        }
        self.replace(load(config)?)?;
        Ok(true)
    }
    fn replace(&self, generation: Generation) -> Result<()> {
        *self.0.write().map_err(|_| "TLS generation lock poisoned")? = Arc::new(generation);
        Ok(())
    }
}
fn load(config: &Config) -> Result<Generation> {
    let stamp = ech_stamp(config)?;
    let stored = DiskStore::open(&config.state_dir.join("certificates"))?
        .read_current()?
        .ok_or("valid CURRENT certificate required before binding listeners")?;
    let bundle = crate::acme::certificate::Validator::for_config(config)?
        .verify(stored.candidate, crate::acme::now())?;
    if bundle.lifetime() != stored.lifetime {
        return Err("certificate metadata mismatch".into());
    }
    let certs = X509::stack_from_pem(&bundle.material().chain_pem)?;
    let key = PKey::private_key_from_pem(&bundle.material().key_pem)?;
    // boring's legacy v4 helper explicitly disables TLS 1.3. The v5 policy
    // preserves TLS 1.2 compatibility while allowing modern H2 handshakes.
    let mut h2 = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    h2.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    h2.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    h2.set_certificate(&certs[0])?;
    h2.set_private_key(&key)?;
    for cert in &certs[1..] {
        if config.ech.is_none() {
            h2.add_extra_chain_cert(cert.clone())?;
        }
    }
    h2.check_private_key()?;
    let ech = EchMaterial::load(config)?;
    if let Some(ech) = &ech {
        ech.install(&mut h2, &certs, &key)?;
    }
    let h1_enabled = config.listener.h1;
    h2.set_alpn_select_callback(move |_, offered| {
        let protocols: &[u8] = if h1_enabled {
            b"\x02h2\x08http/1.1"
        } else {
            b"\x02h2"
        };
        select_next_proto(protocols, offered).ok_or(AlpnError::ALERT_FATAL)
    });

    let mut h3 = SslContextBuilder::new(SslMethod::tls())?;
    h3.set_certificate(&certs[0])?;
    h3.set_private_key(&key)?;
    for cert in &certs[1..] {
        if config.ech.is_none() {
            h3.add_extra_chain_cert(cert.clone())?;
        }
    }
    h3.check_private_key()?;
    if let Some(ech) = &ech {
        ech.install(&mut h3, &certs, &key)?;
    }
    let mut h3 = h3_settings(h3, &TransportProfile::from_config(config)?)?;
    let initial = config
        .limits
        .max_early_data_bytes
        .min(config.limits.max_buffer_bytes_per_stream) as u64;
    h3.set_initial_max_stream_data_bidi_local(initial);
    h3.set_initial_max_stream_data_bidi_remote(initial);
    h3.set_max_recv_udp_payload_size(1350);
    h3.set_max_send_udp_payload_size(1350);
    // One server CID: disable migration until additional CID routing is implemented.
    h3.set_disable_active_migration(true);
    if ech_stamp(config)? != stamp {
        return Err("ECH files changed during reload".into());
    }
    Ok(Generation {
        id: stored.generation,
        ech_stamp: stamp,
        h2: h2.build(),
        h3: Mutex::new(h3),
        not_after: bundle.lifetime().not_after,
    })
}
pub(super) async fn watch(config: Arc<Config>, slot: Slot, mut stop: watch::Receiver<bool>) {
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! {_=stop.changed()=>break,_=tokio::time::sleep(std::time::Duration::from_secs(5))=>{}}
        let local = config.clone();
        let slot = slot.clone();
        // Failed validation leaves the previous immutable generation installed.
        let _ = tokio::task::spawn_blocking(move || slot.refresh(&local)).await;
    }
}

// BoringSSL performs ECH decryption before certificate selection. The fallback
// certificate authenticates public_name when a client needs retry_configs.
struct EchMaterial {
    keys: boring::ssl::SslEchKeys,
    public_name: String,
    certificates: Vec<X509>,
    private_key: PKey<boring::pkey::Private>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EchKeyFile {
    keys: Vec<EchKeyEntry>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EchKeyEntry {
    config: String,
    private_key: String,
    retry: bool,
}
impl EchMaterial {
    fn load(config: &Config) -> Result<Option<Self>> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let Some(settings) = &config.ech else {
            return Ok(None);
        };
        let file: EchKeyFile = crate::acme::state::load_toml(&settings.keys_file, 65536)?;
        if file.keys.is_empty() || file.keys.len() > 8 || !file.keys.iter().any(|k| k.retry) {
            return Err("ECH requires 1..8 keys and at least one retry config".into());
        }
        let mut builder = boring::ssl::SslEchKeys::builder()?;
        let mut ids = std::collections::HashSet::new();
        for entry in file.keys {
            let encoded = STANDARD
                .decode(entry.config)
                .map_err(|_| "invalid ECH config base64")?;
            let key = STANDARD
                .decode(entry.private_key)
                .map_err(|_| "invalid ECH private key base64")?;
            let (id, name) = ech_config_name(&encoded)?;
            if name != settings.public_name.as_bytes() || !ids.insert(id) {
                return Err("ECH public name mismatch or duplicate config ID".into());
            }
            // Despite its historical Rust name, boring 5.2 implements X25519 here.
            builder.add_key(
                entry.retry,
                &encoded,
                boring::hpke::HpkeKey::dhkem_p256_sha256(&key)?,
            )?;
        }
        let certificates = X509::stack_from_pem(&std::fs::read(&settings.certificate_file)?)?;
        let leaf = certificates
            .first()
            .ok_or("empty ECH public certificate chain")?;
        if !leaf.subject_alt_names().is_some_and(|names| {
            names
                .iter()
                .any(|n| n.dnsname() == Some(settings.public_name.as_str()))
        }) {
            return Err("ECH public certificate requires an exact DNS SAN".into());
        }
        let now = boring::asn1::Asn1Time::days_from_now(0)?;
        if leaf.not_before() > now || leaf.not_after() <= now {
            return Err("ECH public certificate is not currently valid".into());
        }
        let private_key = PKey::private_key_from_pem(&crate::acme::state::read_private(
            &settings.private_key_file,
            65536,
        )?)?;
        if !leaf.public_key()?.public_eq(&private_key) {
            return Err("ECH public certificate key mismatch".into());
        }
        Ok(Some(Self {
            keys: builder.build(),
            public_name: settings.public_name.clone(),
            certificates,
            private_key,
        }))
    }
    fn install(
        &self,
        context: &mut SslContextBuilder,
        inner_chain: &[X509],
        inner_key: &PKey<boring::pkey::Private>,
    ) -> Result<()> {
        context.set_ech_keys(&self.keys)?;
        let name = self.public_name.clone();
        let certificates = self.certificates.clone();
        let key = self.private_key.clone();
        let inner_chain = inner_chain.to_vec();
        let inner_key = inner_key.clone();
        let installed = boring::ssl::Ssl::new_ex_index::<bool>()?;
        context.set_select_certificate_callback(move |mut hello| {
            if hello.ssl().ex_data(installed).copied().unwrap_or(false) {
                return Ok(());
            }
            let (certificates, key) =
                if hello.servername(boring::ssl::NameType::HOST_NAME) == Some(name.as_str()) {
                    (&certificates, &key)
                } else {
                    (&inner_chain, &inner_key)
                };
            {
                let ssl = hello.ssl_mut();
                ssl.set_certificate(&certificates[0])
                    .map_err(|_| boring::ssl::SelectCertError::ERROR)?;
                ssl.set_private_key(key)
                    .map_err(|_| boring::ssl::SelectCertError::ERROR)?;
                for cert in &certificates[1..] {
                    ssl.add_chain_cert(cert)
                        .map_err(|_| boring::ssl::SelectCertError::ERROR)?;
                }
            }
            hello.ssl_mut().set_ex_data(installed, true);
            Ok(())
        });
        Ok(())
    }
}
// Parse only the supported ECHConfig envelope to enforce the declared public
// name and unique IDs; BoringSSL validates all cryptographic fields/extensions.
fn ech_config_name(bytes: &[u8]) -> Result<(u8, &[u8])> {
    fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8]> {
        if input.len() < count {
            return Err("truncated ECHConfig".into());
        }
        let (head, tail) = input.split_at(count);
        *input = tail;
        Ok(head)
    }
    fn length(input: &mut &[u8]) -> Result<usize> {
        let b = take(input, 2)?;
        Ok(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }
    let mut input = bytes;
    if take(&mut input, 2)? != [0xfe, 0x0d] {
        return Err("unsupported ECH version".into());
    }
    let size = length(&mut input)?;
    if size != input.len() {
        return Err("invalid ECHConfig length".into());
    }
    let id = take(&mut input, 1)?[0];
    if take(&mut input, 2)? != [0, 0x20] {
        return Err("ECH requires X25519".into());
    }
    let size = length(&mut input)?;
    take(&mut input, size)?;
    let size = length(&mut input)?;
    take(&mut input, size)?;
    take(&mut input, 1)?;
    let size = usize::from(take(&mut input, 1)?[0]);
    let name = take(&mut input, size)?;
    let size = length(&mut input)?;
    take(&mut input, size)?;
    if !input.is_empty() {
        return Err("trailing ECHConfig data".into());
    }
    Ok((id, name))
}

pub(crate) fn ech_command(action: &str, config: &Config) -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let settings = config.ech.as_ref().ok_or("configure [ech] first")?;
    match action {
        "init" => {
            let key = PKey::generate(boring::pkey::Id::X25519)?;
            let mut public = [0; 32];
            let mut private = [0; 32];
            key.raw_public_key(&mut public)?;
            key.raw_private_key(&mut private)?;
            let mut id = [0];
            boring::rand::rand_bytes(&mut id)?;
            let name = settings.public_name.as_bytes();
            let mut body = vec![id[0], 0, 32, 0, 32];
            body.extend_from_slice(&public);
            body.extend_from_slice(&[0, 4, 0, 1, 0, 1, 255, u8::try_from(name.len())?]);
            body.extend_from_slice(name);
            body.extend_from_slice(&[0, 0]);
            let mut encoded = vec![0xfe, 0x0d];
            encoded.extend_from_slice(&u16::try_from(body.len())?.to_be_bytes());
            encoded.extend(body);
            // Validate the serialized public/private pair before persisting it.
            let mut keys = boring::ssl::SslEchKeys::builder()?;
            keys.add_key(
                true,
                &encoded,
                boring::hpke::HpkeKey::dhkem_p256_sha256(&private)?,
            )?;
            let text = format!(
                "[[keys]]\nconfig = '{}'\nprivate_key = '{}'\nretry = true\n",
                STANDARD.encode(encoded),
                STANDARD.encode(private)
            );
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&settings.keys_file)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            println!(
                "ECH key created; install public-name certificate, run ech check, restart, then publish DNS"
            );
        }
        "check" => {
            let material = EchMaterial::load(config)?.ok_or("ECH not configured")?;
            let context = SslContextBuilder::new(SslMethod::tls())?;
            context.set_ech_keys(&material.keys)?;
            println!(
                "ECH keys and public-name certificate valid; DNS and client support not checked"
            );
        }
        "dns" => {
            let _ = EchMaterial::load(config)?;
            let file: EchKeyFile = crate::acme::state::load_toml(&settings.keys_file, 65536)?;
            let mut configs = Vec::new();
            for key in file.keys.into_iter().filter(|key| key.retry) {
                configs.extend(
                    STANDARD
                        .decode(key.config)
                        .map_err(|_| "invalid ECH config base64")?,
                );
            }
            let mut list = u16::try_from(configs.len())?.to_be_bytes().to_vec();
            list.extend(configs);
            println!(
                "{} IN HTTPS 1 . alpn=\"h2,h3\" ech=\"{}\"",
                config.domain,
                STANDARD.encode(list)
            );
        }
        _ => return Err("ECH action must be init, check, or dns".into()),
    }
    Ok(())
}

// Content based, so atomic replacement and preserved timestamps are detected.
// This runs in the maintenance worker, never in the request hot path.
fn ech_stamp(config: &Config) -> Result<Option<[u8; 32]>> {
    use std::io::Read;
    let Some(ech) = &config.ech else {
        return Ok(None);
    };
    let mut digest = boring::sha::Sha256::new();
    for (path, private) in [
        (&ech.keys_file, true),
        (&ech.certificate_file, false),
        (&ech.private_key_file, true),
    ] {
        let bytes = if private {
            crate::acme::state::read_private(path, 65536)?
        } else {
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 1024 * 1024 {
                return Err("ECH certificate file too large".into());
            }
            bytes
        };
        digest.update(&(bytes.len() as u64).to_be_bytes());
        digest.update(&bytes);
    }
    Ok(Some(digest.finish()))
}

/// The argument and quiche constructor must agree on one boring major/version.
fn h3_settings(
    builder: boring::ssl::SslContextBuilder,
    profile: &TransportProfile,
) -> std::result::Result<quiche::Config, quiche::Error> {
    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)?;
    config.set_application_protos(&[b"h3"])?;
    config.set_cc_algorithm(match profile.quic_congestion() {
        moon_naive_core::config::QuicCongestion::Cubic => quiche::CongestionControlAlgorithm::CUBIC,
        moon_naive_core::config::QuicCongestion::Bbr2 => {
            quiche::CongestionControlAlgorithm::Bbr2Gcongestion
        }
    });
    config.enable_pacing(true);
    config.set_max_idle_timeout(profile.idle_timeout_ms());
    config.set_initial_max_data(u64::from(profile.connection_window()));
    config.set_initial_max_stream_data_bidi_local(u64::from(profile.stream_window()));
    config.set_initial_max_stream_data_bidi_remote(u64::from(profile.stream_window()));
    config.set_initial_max_stream_data_uni(64 * 1024);
    config.set_initial_max_streams_bidi(u64::from(profile.max_streams()));
    config.set_initial_max_streams_uni(16);
    config.set_max_connection_window(u64::from(profile.connection_window()));
    config.set_max_stream_window(u64::from(profile.stream_window()));
    // Control streams have a separate bounded reserve. No enable_early_data():
    // 0-RTT stays disabled. H2 applies the same profile in its driver.
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercise the actual boring/quiche ABI and link, not a dependency-tree
    /// assertion. This does not open a listener or test a QUIC handshake.
    #[test]
    fn shared_profile_constructs_a_real_quiche_config() {
        let config =
            moon_naive_core::config::Config::parse(include_str!("../../config.example.toml"))
                .unwrap();
        let profile = TransportProfile::from_config(&config).unwrap();
        let builder = boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).unwrap();
        let _config = h3_settings(builder, &profile).unwrap();
    }
}
