use super::{Result, crypto};
use boring::{
    asn1::{Asn1Time, Asn1TimeRef},
    hash::MessageDigest,
    stack::Stack,
    x509::{
        X509, X509NameBuilder, X509Req, X509StoreContext, extension::SubjectAlternativeName,
        store::X509StoreBuilder, verify::X509CheckFlags,
    },
};
use std::{
    path::Path,
    sync::{Arc, RwLock},
};

// No Debug: key material must not enter diagnostic logs.
#[derive(Clone)]
pub struct Candidate {
    pub chain_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}
#[derive(Clone)]
pub struct VerifiedBundle {
    material: Candidate,
    lifetime: Lifetime,
}
impl VerifiedBundle {
    /// Adapter trust boundary: caller MUST verify SAN, key match, chain and validity
    /// with a cryptographic library. This constructor only checks structural bounds.
    pub(super) fn from_validator(
        material: Candidate,
        lifetime: Lifetime,
    ) -> std::result::Result<Self, &'static str> {
        if material.chain_pem.is_empty()
            || material.key_pem.is_empty()
            || material.chain_pem.len() > 1024 * 1024
            || material.key_pem.len() > 64 * 1024
            || lifetime.not_after <= lifetime.not_before
        {
            return Err("invalid certificate material bounds");
        }
        Ok(Self { material, lifetime })
    }
    pub fn lifetime(&self) -> Lifetime {
        self.lifetime
    }
    /// Validated key material for TLS context construction; never log it.
    pub fn material(&self) -> &Candidate {
        &self.material
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetime {
    pub not_before: u64,
    pub not_after: u64,
}
impl Lifetime {
    pub fn valid_at(self, now: u64) -> bool {
        self.not_before <= now && now < self.not_after
    }
    pub fn renew_at(self, window: u64) -> u64 {
        self.not_after
            .saturating_sub(window.min(self.not_after.saturating_sub(self.not_before) / 3))
    }
}

#[derive(Clone, Default)]
pub struct CertificateSlot(Arc<RwLock<Option<Arc<VerifiedBundle>>>>);
impl CertificateSlot {
    /// Startup recovery only: caller must read the durable CURRENT generation
    /// and cryptographically validate it before publishing.
    pub fn restore(&self, bundle: VerifiedBundle) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(bundle));
    }
    pub fn current(&self, now: u64) -> Option<Arc<VerifiedBundle>> {
        let current = self
            .0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        current.filter(|bundle| bundle.lifetime().valid_at(now))
    }
}

pub struct Validator {
    domain: String,
    roots: Vec<X509>,
}
impl Validator {
    pub fn for_config(config: &moon_naive_core::config::Config) -> Result<Self> {
        let mut validator = Self::new(&config.domain, config.acme.certificate_ca_file.as_deref())?;
        if config.acme.directory_url.is_none()
            && config.acme.environment == moon_naive_core::config::Environment::Staging
        {
            let roots: &[u8] = match config.acme.issuer {
                moon_naive_core::config::Issuer::Letsencrypt => {
                    include_bytes!("../../assets/le-staging-roots.crt")
                }
                moon_naive_core::config::Issuer::Google => {
                    include_bytes!("../../assets/gts-test-roots.crt")
                }
            };
            validator.roots.extend(X509::stack_from_pem(roots)?);
        }
        Ok(validator)
    }
    pub fn new(domain: &str, roots: Option<&Path>) -> Result<Self> {
        Ok(Self {
            domain: domain.into(),
            roots: match roots {
                Some(path) => X509::stack_from_pem(&std::fs::read(path)?)?,
                None => Vec::new(),
            },
        })
    }
    pub fn verify(&self, candidate: Candidate, now: u64) -> Result<VerifiedBundle> {
        if candidate.chain_pem.len() > 1024 * 1024 || candidate.key_pem.len() > 64 * 1024 {
            return Err("certificate material exceeds limit".into());
        }
        let certs = X509::stack_from_pem(&candidate.chain_pem)?;
        if certs.is_empty() || certs.len() > 16 {
            return Err("invalid certificate chain length".into());
        }
        let leaf = &certs[0];
        let der = leaf.to_der()?;
        let (_, parsed) = x509_parser::parse_x509_certificate(&der)
            .map_err(|_| "invalid leaf certificate DER")?;
        if parsed
            .basic_constraints()
            .map_err(|_| "invalid basic constraints")?
            .is_some_and(|ext| ext.value.ca)
            || parsed
                .extended_key_usage()
                .map_err(|_| "invalid extended key usage")?
                .is_some_and(|ext| !ext.value.server_auth && !ext.value.any)
            || parsed
                .key_usage()
                .map_err(|_| "invalid key usage")?
                .is_some_and(|ext| !ext.value.digital_signature())
        {
            return Err("leaf certificate does not permit TLS server authentication".into());
        }
        let key = boring::pkey::PKey::private_key_from_pem(&candidate.key_pem)?;
        if !leaf.public_key()?.public_eq(&key) {
            return Err("certificate/private key mismatch".into());
        }
        // Require SAN, never fall back to a matching legacy CN.
        if !leaf
            .subject_alt_names()
            .is_some_and(|names| names.iter().any(|name| name.dnsname().is_some()))
        {
            return Err("certificate has no DNS SAN".into());
        }
        let mut roots = X509StoreBuilder::new()?;
        roots.set_default_paths()?;
        if let Some(file) = crate::trust::system_ca_file() {
            for root in X509::stack_from_pem(&std::fs::read(file)?)? {
                roots.add_cert(root)?;
            }
        }
        for root in &self.roots {
            roots.add_cert(root.clone())?;
        }
        let params = roots.verify_param_mut();
        params.set_hostflags(
            X509CheckFlags::NEVER_CHECK_SUBJECT | X509CheckFlags::NO_PARTIAL_WILDCARDS,
        );
        params.set_host(&self.domain)?;
        params.set_time(i64::try_from(now)?);
        let roots = roots.build();
        let mut chain = Stack::new()?;
        for cert in &certs[1..] {
            chain.push(cert.clone())?;
        }
        let mut ctx = X509StoreContext::new()?;
        if !ctx.init(&roots, leaf, &chain, |ctx| ctx.verify_cert())? {
            return Err("certificate chain, identity or validity verification failed".into());
        }
        let lifetime = lifetime(leaf)?;
        if !lifetime.valid_at(now) {
            return Err("certificate not currently valid".into());
        }
        VerifiedBundle::from_validator(candidate, lifetime).map_err(Into::into)
    }
}
fn timestamp(time: &Asn1TimeRef) -> Result<u64> {
    let difference = Asn1Time::from_unix(0)?.diff(time)?;
    Ok(u64::try_from(
        i64::from(difference.days) * 86400 + i64::from(difference.secs),
    )?)
}
pub fn lifetime(cert: &boring::x509::X509Ref) -> Result<Lifetime> {
    Ok(Lifetime {
        not_before: timestamp(cert.not_before())?,
        not_after: timestamp(cert.not_after())?,
    })
}
pub fn csr(domain: &str) -> Result<(String, Vec<u8>)> {
    let key = crypto::p256()?;
    let mut request = X509Req::builder()?;
    request.set_version(0)?;
    request.set_subject_name(&X509NameBuilder::new()?.build())?;
    request.set_pubkey(&key)?;
    let mut extensions = Stack::new()?;
    extensions.push(
        SubjectAlternativeName::new()
            .dns(domain)
            .build(&request.x509v3_context(None))?,
    )?;
    request.add_extensions(&extensions)?;
    request.sign(&key, MessageDigest::sha256())?;
    Ok((
        String::from_utf8(key.private_key_to_pem_pkcs8()?)?,
        request.build().to_der()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn issuer_test_roots_are_isolated_from_production_and_custom_ca() {
        use moon_naive_core::config::{Config, Environment, Issuer};
        let mut config = Config::parse(include_str!("../../config.example.toml")).unwrap();
        config.acme.environment = Environment::Staging;
        let google = Validator::for_config(&config).unwrap();
        assert_eq!(google.roots.len(), 2);
        assert!(google.roots.iter().all(|root| {
            root.subject_name()
                .entries_by_nid(boring::nid::Nid::COMMONNAME)
                .next()
                .unwrap()
                .data()
                .as_slice()
                .starts_with(b"Test GTS Root")
        }));
        config.acme.environment = Environment::Production;
        assert!(Validator::for_config(&config).unwrap().roots.is_empty());
        config.acme.environment = Environment::Staging;
        config.acme.directory_url = Some("https://custom.example.dev/directory".into());
        assert!(Validator::for_config(&config).unwrap().roots.is_empty());
        config.acme.directory_url = None;
        config.acme.issuer = Issuer::Letsencrypt;
        let le = Validator::for_config(&config).unwrap();
        assert_eq!(le.roots.len(), 2);
        assert!(le.roots.iter().all(|root| {
            root.subject_name()
                .entries_by_nid(boring::nid::Nid::COMMONNAME)
                .next()
                .unwrap()
                .data()
                .as_slice()
                .starts_with(b"(STAGING)")
        }));
    }
    use boring::{
        bn::BigNum,
        pkey::{PKey, Private},
        x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
    };

    fn leaf(ca: &X509, ca_key: &PKey<Private>, san: bool, server_auth: bool) -> Candidate {
        let key = crypto::p256().unwrap();
        let mut cert = X509::builder().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "example.test").unwrap();
        cert.set_version(2).unwrap();
        let serial = BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap();
        cert.set_serial_number(&serial).unwrap();
        cert.set_subject_name(&name.build()).unwrap();
        cert.set_issuer_name(ca.subject_name()).unwrap();
        cert.set_pubkey(&key).unwrap();
        let before = Asn1Time::from_unix(super::super::now() as i64 - 60).unwrap();
        let after = Asn1Time::days_from_now(1).unwrap();
        cert.set_not_before(&before).unwrap();
        cert.set_not_after(&after).unwrap();
        cert.append_extension(&BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        cert.append_extension(&KeyUsage::new().digital_signature().build().unwrap())
            .unwrap();
        let mut eku = ExtendedKeyUsage::new();
        if server_auth {
            eku.server_auth();
        } else {
            eku.client_auth();
        }
        cert.append_extension(&eku.build().unwrap()).unwrap();
        if san {
            let extension = SubjectAlternativeName::new()
                .dns("example.test")
                .build(&cert.x509v3_context(Some(ca), None))
                .unwrap();
            cert.append_extension(&extension).unwrap();
        }
        cert.sign(ca_key, MessageDigest::sha256()).unwrap();
        let mut chain = cert.build().to_pem().unwrap();
        chain.extend(ca.to_pem().unwrap());
        Candidate {
            chain_pem: chain,
            key_pem: key.private_key_to_pem_pkcs8().unwrap(),
        }
    }
    #[test]
    fn requires_dns_san_and_server_auth_even_with_a_valid_trusted_signature() {
        let key = crypto::p256().unwrap();
        let mut ca = X509::builder().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "test-only CA").unwrap();
        let name = name.build();
        ca.set_version(2).unwrap();
        let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
        ca.set_serial_number(&serial).unwrap();
        ca.set_subject_name(&name).unwrap();
        ca.set_issuer_name(&name).unwrap();
        ca.set_pubkey(&key).unwrap();
        let before = Asn1Time::from_unix(super::super::now() as i64 - 60).unwrap();
        let after = Asn1Time::days_from_now(2).unwrap();
        ca.set_not_before(&before).unwrap();
        ca.set_not_after(&after).unwrap();
        ca.append_extension(&BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        ca.append_extension(
            &KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
        ca.sign(&key, MessageDigest::sha256()).unwrap();
        let ca = ca.build();
        let roots = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(roots.path(), ca.to_pem().unwrap()).unwrap();
        let validator = Validator::new("example.test", Some(roots.path())).unwrap();
        assert!(
            validator
                .verify(leaf(&ca, &key, true, true), super::super::now())
                .is_ok()
        );
        assert!(
            validator
                .verify(leaf(&ca, &key, false, true), super::super::now())
                .is_err()
        );
        assert!(
            validator
                .verify(leaf(&ca, &key, true, false), super::super::now())
                .is_err()
        );
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    fn bundle(expiry: u64) -> VerifiedBundle {
        VerifiedBundle::from_validator(
            Candidate {
                chain_pem: vec![1],
                key_pem: vec![2],
            },
            Lifetime {
                not_before: 0,
                not_after: expiry,
            },
        )
        .unwrap()
    }
    #[test]
    fn swap_keeps_existing_snapshot_and_expires_current() {
        let slot = CertificateSlot::default();
        assert!(slot.current(0).is_none());
        slot.restore(bundle(90));
        let old = slot.current(0).unwrap();
        slot.restore(bundle(180));
        assert_eq!(old.lifetime().not_after, 90);
        assert_eq!(slot.current(0).unwrap().lifetime().not_after, 180);
        assert!(slot.current(180).is_none());
    }
    #[test]
    fn renewal_window_keeps_two_thirds_of_short_certificate_lifetime() {
        let short = Lifetime {
            not_before: 0,
            not_after: 90,
        };
        assert_eq!(short.renew_at(2_592_000), 60);
        assert!(short.valid_at(0));
        assert!(!short.valid_at(90));
        assert_eq!(
            Lifetime {
                not_before: 100,
                not_after: 400
            }
            .renew_at(30),
            370
        );
    }
}
