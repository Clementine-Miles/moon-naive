use super::{Config, Result, TransportProfile};
use crate::acme::persist::DiskStore;
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
    outer: Option<crate::acme::certificate::Lifetime>,
}
#[derive(Clone)]
pub(super) struct Slot(
    Arc<RwLock<Arc<Generation>>>,
    #[cfg(test)] Arc<Mutex<Option<RecordFault>>>,
    #[cfg(test)] Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)] Arc<std::sync::atomic::AtomicUsize>,
);
#[cfg(test)]
struct RecordFault {
    stage: &'static str,
    skip_records: usize,
}

impl Slot {
    pub fn load(config: &Config) -> Result<Self> {
        let slot = Self(
            Arc::new(RwLock::new(Arc::new(load(config)?))),
            #[cfg(test)]
            Arc::new(Mutex::new(None)),
            #[cfg(test)]
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        );
        slot.report(config);
        Ok(slot)
    }
    pub fn current(&self) -> Result<Arc<Generation>> {
        let generation = self
            .0
            .read()
            .map_err(|_| "TLS generation lock poisoned")?
            .clone();
        generation.valid_at(crate::acme::now())?;
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
            self.report(config);
            current.valid_at(crate::acme::now())?;
            return Ok(false);
        }
        self.replace(load(config)?)?;
        self.report(config);
        Ok(true)
    }
    fn report(&self, config: &Config) {
        if let Err(error) = self.record(config) {
            #[cfg(test)]
            self.3.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            eprintln!("event=tls_status_write_failed detail={error}");
        }
    }
    fn record(&self, config: &Config) -> Result<()> {
        let generation = self
            .0
            .read()
            .map_err(|_| "TLS generation lock poisoned")?
            .clone();
        #[cfg(test)]
        let fault = {
            let mut fault = self.1.lock().unwrap();
            if let Some(value) = fault.as_mut() {
                if value.skip_records > 0 {
                    value.skip_records -= 1;
                    None
                } else {
                    fault.take().map(|value| value.stage)
                }
            } else {
                None
            }
        };
        let path = config.state_dir.join("certificates/TLS-LOADED");
        let mut composite = boring::sha::Sha256::new();
        composite.update(generation.id.as_bytes());
        if let Some(stamp) = generation.ech_stamp {
            composite.update(&stamp);
        }
        let composite: String = composite
            .finish()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let text = format!(
            "process_id={}\nloaded_generation={}\nloaded_bundle_sha256={composite}\nnew_handshakes_allowed={}\ninner_not_after={}\nouter_not_after={:?}\nhandshake_probe=not_performed_by_status_writer\n",
            std::process::id(),
            generation.id,
            generation.valid_at(crate::acme::now()).is_ok(),
            generation.not_after,
            generation.outer.map(|life| life.not_after)
        );
        if crate::acme::persist::read_private(&path, 4096).is_ok_and(|old| old == text.as_bytes()) {
            return Ok(());
        }
        let mut nonce = [0; 8];
        boring::rand::rand_bytes(&mut nonce)?;
        let temp = path.with_file_name(format!("TLS-LOADED-{}.tmp", u64::from_be_bytes(nonce)));
        let result = (|| -> Result<()> {
            #[cfg(test)]
            record_fault(fault, "create", &self.2)?;
            crate::acme::persist::write_private_new(&temp, text.as_bytes())?;
            #[cfg(test)]
            record_fault(fault, "rename", &self.2)?;
            std::fs::rename(&temp, &path)?;
            #[cfg(test)]
            record_fault(fault, "fsync", &self.2)?;
            std::fs::File::open(path.parent().unwrap())?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }
    #[cfg(test)]
    pub(super) fn laboratory_report_failures(&self) -> usize {
        self.3.load(std::sync::atomic::Ordering::SeqCst)
    }
    #[cfg(test)]
    pub(super) fn laboratory_fault_hits(&self) -> usize {
        self.2.load(std::sync::atomic::Ordering::SeqCst)
    }
    #[cfg(test)]
    pub(super) fn laboratory_fail_record(&self, stage: &'static str, skip_records: usize) {
        *self.1.lock().unwrap() = Some(RecordFault {
            stage,
            skip_records,
        });
    }
    fn replace(&self, generation: Generation) -> Result<()> {
        *self.0.write().map_err(|_| "TLS generation lock poisoned")? = Arc::new(generation);
        Ok(())
    }
}
#[cfg(test)]
fn record_fault(
    fault: Option<&str>,
    stage: &str,
    hits: &std::sync::atomic::AtomicUsize,
) -> Result<()> {
    if fault == Some(stage) {
        hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        return Err(std::io::Error::other(format!("injected TLS-LOADED {stage} failure")).into());
    }
    Ok(())
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
    // Build the latest inner even when outer is expired. Admission below gates
    // all new handshakes until the complete configured ECH identity is valid.
    let ech = EchMaterial::read(config, false)?;
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
        .min(TransportProfile::from_config(config)?.h3_stream_window() as usize)
        as u64;
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
        outer: ech.as_ref().map(|ech| ech.lifetime),
    })
}
impl Generation {
    fn valid_at(&self, now: u64) -> Result<()> {
        if now >= self.not_after {
            return Err("inner TLS identity expired".into());
        }
        if self.outer.is_some_and(|life| !life.valid_at(now)) {
            return Err(
                "ECH outer identity invalid; new handshakes suspended (ECH remains configured)"
                    .into(),
            );
        }
        Ok(())
    }
}
pub(super) async fn watch(config: Arc<Config>, slot: Slot, mut stop: watch::Receiver<bool>) {
    let mut last_error: Option<std::time::Instant> = None;
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! {_=stop.changed()=>break,_=tokio::time::sleep(std::time::Duration::from_secs(5))=>{}}
        let local = config.clone();
        let slot = slot.clone();
        // Failed validation leaves the previous immutable generation installed.
        match tokio::task::spawn_blocking(move || slot.refresh(&local)).await {
            Ok(Ok(true)) => eprintln!("event=tls_generation_loaded"),
            Ok(Ok(false)) => {}
            result => {
                if last_error.is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(60)) {
                    eprintln!("event=tls_refresh_failed detail={result:?}");
                    last_error = Some(std::time::Instant::now());
                }
            }
        }
    }
}

// BoringSSL performs ECH decryption before certificate selection. The fallback
// certificate authenticates public_name when a client needs retry_configs.
struct EchMaterial {
    keys: boring::ssl::SslEchKeys,
    public_name: String,
    certificates: Vec<X509>,
    private_key: PKey<boring::pkey::Private>,
    lifetime: crate::acme::certificate::Lifetime,
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
        Self::read(config, true)
    }
    fn read(config: &Config, require_valid_time: bool) -> Result<Option<Self>> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let Some(settings) = &config.ech else {
            return Ok(None);
        };
        let file: EchKeyFile = crate::acme::persist::load_toml(&settings.keys_file, 65536)?;
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
        let chain_pem = std::fs::read(&settings.certificate_file)?;
        let certificates = X509::stack_from_pem(&chain_pem)?;
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
        let lifetime = crate::acme::certificate::lifetime(leaf)?;
        if require_valid_time && !lifetime.valid_at(crate::acme::now()) {
            return Err("ECH public certificate is not currently valid".into());
        }
        let private_key = PKey::private_key_from_pem(&crate::acme::persist::read_private(
            &settings.private_key_file,
            65536,
        )?)?;
        if !leaf.public_key()?.public_eq(&private_key) {
            return Err("ECH public certificate key mismatch".into());
        }
        let candidate = crate::acme::certificate::Candidate {
            chain_pem,
            key_pem: private_key.private_key_to_pem_pkcs8()?,
        };
        let checked_at = crate::acme::now()
            .min(lifetime.not_after.saturating_sub(1))
            .max(lifetime.not_before);
        crate::acme::certificate::Validator::new(
            &settings.public_name,
            config.acme.certificate_ca_file.as_deref(),
        )?
        .verify(candidate, checked_at)?;
        Ok(Some(Self {
            keys: builder.build(),
            public_name: settings.public_name.clone(),
            certificates,
            private_key,
            lifetime,
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
            let file: EchKeyFile = crate::acme::persist::load_toml(&settings.keys_file, 65536)?;
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
            crate::acme::persist::read_private(path, 65536)?
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
    config.set_initial_max_stream_data_bidi_local(u64::from(profile.h3_stream_window()));
    config.set_initial_max_stream_data_bidi_remote(u64::from(profile.h3_stream_window()));
    config.set_initial_max_stream_data_uni(64 * 1024);
    config.set_initial_max_streams_bidi(u64::from(profile.max_streams()));
    config.set_initial_max_streams_uni(16);
    config.set_max_connection_window(u64::from(profile.connection_window()));
    config.set_max_stream_window(u64::from(profile.h3_stream_window()));
    // Stalled bidi DATA cannot consume the control reserve. QPACK dynamic tables
    // remain disabled in the H3 driver. No enable_early_data():
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
