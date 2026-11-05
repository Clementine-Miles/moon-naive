//! Account creation, restoration and EAB recovery through instant-acme.
use super::{Result, crypto::CRYPTO, http::Http, state::Journal};
use instant_acme::{Account, Key};
use moon_naive_core::config::Config;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::path::PathBuf;

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
                            super::eab::load_credentials(self.eab_file.as_ref().unwrap())?
                        };
                        let (account, credentials) = super::eab::register(
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn account_key_must_be_durable_before_any_registration_request() {
        let client = AccountClient {
            http: Http::new(None, Duration::from_millis(100)).unwrap(),
            contact: "operator@example.test".into(),
            eab_file: None,
            eab_inline: None,
        };
        let mut journal = Journal {
            directory: "https://invalid.invalid/directory".into(),
            ..Journal::default()
        };
        let mut persisted = false;
        let result = client
            .restore_or_create(&mut journal, |state| {
                assert!(!state.account_key.is_empty());
                assert!(state.account.is_none());
                persisted = true;
                Err("simulated disk failure".into())
            })
            .await;
        assert!(persisted);
        assert_eq!(result.err().unwrap().to_string(), "simulated disk failure");
    }
}
