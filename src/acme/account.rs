//! Account creation, restoration and EAB recovery through instant-acme.
use super::persist::read_private;
use super::{Result, crypto::CRYPTO, http::Http, persist::Journal};
use instant_acme::{Account, Key};
use moon_naive_core::config::Config;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub(super) struct AccountClient {
    http: Http,
    contact: String,
    eab_file: Option<PathBuf>,
    eab_inline: Option<moon_naive_core::config::EabCredentials>,
}
impl AccountClient {
    pub fn new(config: &Config, http: Http) -> Self {
        Self {
            http,
            contact: config.acme.contact.clone(),
            eab_file: config.acme.eab_credentials_file.clone(),
            eab_inline: config.acme.eab.clone(),
        }
    }
    pub async fn restore_or_create(
        &self,
        journal: &mut Journal,
        mut persist: impl FnMut(&Journal) -> Result<()>,
    ) -> Result<Account> {
        let builder = Account::builder(Box::new(self.http.clone()), &CRYPTO)?;
        let account = if let Some(credentials) = &journal.account {
            builder
                .from_credentials(serde_json::from_value(credentials.clone())?)
                .await?
        } else if let Some(id) = &journal.account_id {
            builder
                .from_parts(
                    id.clone(),
                    PrivatePkcs8KeyDer::from(journal.account_key.clone()),
                    journal.directory.clone(),
                )
                .await?
        } else {
            // Persist key before newAccount: retries reuse the same identity.
            if journal.account_key.is_empty() {
                let (_, key) = CRYPTO.key_provider.generate_key()?;
                journal.account_key = key.secret_pkcs8_der().to_vec();
                persist(journal)?;
            }
            let der = PrivatePkcs8KeyDer::from(journal.account_key.clone());
            let key = Key::from_pkcs8_der(der.clone_key(), &CRYPTO)?;
            if self.eab_file.is_some() || self.eab_inline.is_some() {
                // EAB credentials can be single-use. Always recover by the
                // durable account key before attempting a new registration.
                match builder
                    .from_key((key, PrivateKeyDer::Pkcs8(der)), journal.directory.clone())
                    .await
                {
                    Ok((account, credentials)) => {
                        journal.account = Some(serde_json::to_value(credentials)?);
                        persist(journal)?;
                        account
                    }
                    Err(instant_acme::Error::Api(problem))
                        if problem.r#type.as_deref()
                            == Some("urn:ietf:params:acme:error:accountDoesNotExist") =>
                    {
                        let credentials = if let Some(value) = &self.eab_inline {
                            value.clone()
                        } else {
                            load_credentials(self.eab_file.as_ref().unwrap())?
                        };
                        let (account, credentials) = register_eab(
                            &self.http,
                            &journal.directory,
                            &journal.account_key,
                            &self.contact,
                            &credentials,
                        )
                        .await?;
                        journal.account_id = Some(account.id().to_owned());
                        journal.account = Some(serde_json::to_value(credentials)?);
                        persist(journal)?;
                        account
                    }
                    Err(error) => return Err(error.into()),
                }
            } else {
                let (account, credentials) = builder
                    .create_from_key((key, PrivateKeyDer::Pkcs8(der)), journal.directory.clone())
                    .await?;
                journal.account = Some(serde_json::to_value(credentials)?);
                persist(journal)?;
                account
            }
        };
        let contact = format!("mailto:{}", self.contact.trim_start_matches("mailto:"));
        account.update_contacts(&[&contact]).await?;
        Ok(account)
    }
}

pub use moon_naive_core::config::EabCredentials as Credentials;

pub fn load_credentials(path: &Path) -> Result<Credentials> {
    let value: Credentials = crate::acme::persist::load_toml(path, 32768)?;
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
    super::persist::write_private_new(output, text.as_bytes())
}
/// EAB registration uses instant-acme's protocol implementation while retaining
/// the key persisted before the first network request.
pub async fn register_eab(
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
