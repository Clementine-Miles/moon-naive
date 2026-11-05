//! EAB credential import and instant-acme account registration.
use super::{Result, crypto::CRYPTO, http::Http, state::read_private};
use rustls_pki_types::PrivatePkcs8KeyDer;
use serde::Deserialize;
use std::path::Path;

pub use moon_naive_core::config::EabCredentials as Credentials;

pub fn load_credentials(path: &Path) -> Result<Credentials> {
    let value: Credentials = crate::acme::state::load_toml(path, 32768)?;
    value.validate()?;
    Ok(value)
}

/// Import the JSON export produced by gcloud once. Runtime configuration only
/// reads TOML. A temporary private inode is linked into place without replacing
/// any existing output, so interrupted imports cannot publish a partial file.
pub fn import_gcloud(input: &Path, output: &Path) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Export {
        key_id: String,
        b64_mac_key: String,
    }
    let value: Export = serde_json::from_slice(&read_private(input, 32768)?)
        .map_err(|_| "invalid private gcloud EAB export")?;
    let value = Credentials {
        key_id: value.key_id,
        b64_mac_key: value.b64_mac_key,
    };
    value.validate()?;
    let text = toml::to_string(&value)?;
    super::state::write_private_new(output, text.as_bytes())
}
/// EAB registration uses instant-acme's protocol implementation while retaining
/// the key persisted before the first network request.
pub async fn register(
    http: &Http,
    directory: &str,
    key_der: &[u8],
    contact: &str,
    credentials: &Credentials,
) -> Result<(instant_acme::Account, instant_acme::AccountCredentials)> {
    credentials.validate()?;
    let der = PrivatePkcs8KeyDer::from(key_der.to_vec());
    let key = instant_acme::Key::from_pkcs8_der(der.clone_key(), &CRYPTO)?;
    let external = instant_acme::ExternalAccountKey::new(
        credentials.key_id.clone(),
        CRYPTO.hmac.load_key(&credentials.mac()?),
    );
    let contact = format!("mailto:{}", contact.trim_start_matches("mailto:"));
    let result = instant_acme::Account::builder(Box::new(http.clone()), &CRYPTO)?
        .create_with_key(
            &instant_acme::NewAccount {
                contact: &[&contact],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            (key, der),
            directory.to_owned(),
            Some(&external),
        )
        .await?;
    let uri: http::Uri = result.0.id().parse()?;
    if uri.scheme_str() != Some("https")
        || uri.host().is_none()
        || uri.authority().is_some_and(|a| a.as_str().contains('@'))
    {
        return Err("invalid ACME account Location".into());
    }
    Ok(result)
}
