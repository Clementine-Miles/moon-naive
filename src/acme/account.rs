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

#[cfg(test)]
mod eab_tests {
    use super::super::tests::http_server;
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use boring::{bn::BigNum, ecdsa::EcdsaSig, pkey::PKey};
    use bytes::Bytes;
    use http::Response;
    use http::header;
    use http_body_util::Full;
    use serde_json::{Value, json};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    #[test]
    fn private_gcloud_import_is_validated_atomic_and_never_overwrites() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("export.json");
        let output = root.path().join("eab.toml");
        std::fs::write(
            &input,
            serde_json::to_vec(&json!({
                "name":"projects/test/locations/global/externalAccountKeys/test",
                "keyId":"test-key-id", "b64MacKey":URL_SAFE_NO_PAD.encode([0x42;32])
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
        import_gcloud(&input, &output).unwrap();
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let value = load_credentials(&output).unwrap();
        assert_eq!(value.key_id, "test-key-id");
        assert_eq!(value.mac().unwrap(), [0x42; 32]);
        let before = std::fs::read(&output).unwrap();
        assert!(import_gcloud(&input, &output).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), before);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
        assert!(load_credentials(&input).is_err()); // JSON is import-only.
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(import_gcloud(&input, &root.path().join("other.toml")).is_err());
        assert!(!root.path().join("other.toml").exists());
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(
            &input,
            br#"{"keyId":"test-key-id","b64MacKey":"invalid-private-value!"}"#,
        )
        .unwrap();
        assert!(import_gcloud(&input, &root.path().join("other.toml")).is_err());
        assert!(!root.path().join("other.toml").exists());
    }
    #[tokio::test]
    async fn eab_is_bound_to_durable_account_key_and_retries_only_bad_nonce() {
        let (_, der) = CRYPTO.key_provider.generate_key().unwrap();
        let public = PKey::private_key_from_pkcs8(der.secret_pkcs8_der())
            .unwrap()
            .ec_key()
            .unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let server=http_server({
            let attempts=attempts.clone();
            move |request| {
                let attempts=attempts.clone();let public=public.clone();
                async move {
                    let origin=format!("http://{}",request.headers()["host"].to_str().unwrap());
                    if request.uri().path()=="/directory" {
                        return Response::new(Full::new(Bytes::from(serde_json::to_vec(&json!({"newAccount":format!("{origin}/account"),"newNonce":format!("{origin}/nonce"),"newOrder":format!("{origin}/order")})).unwrap())));
                    }
                    if request.uri().path()=="/nonce" {
                        assert_eq!(request.method(),"HEAD");
                        return Response::builder().header("Replay-Nonce","test-nonce").body(Full::new(Bytes::new())).unwrap();
                    }
                    assert_eq!(request.uri().path(),"/account");
                    assert_eq!(request.headers()[header::CONTENT_TYPE],"application/jose+json");
                    let jws:Value=serde_json::from_slice(request.body()).unwrap();
                    let decode=|s:&Value|URL_SAFE_NO_PAD.decode(s.as_str().unwrap()).unwrap();
                    let header:Value=serde_json::from_slice(&decode(&jws["protected"])).unwrap();
                    let payload:Value=serde_json::from_slice(&decode(&jws["payload"])).unwrap();
                    assert_eq!(header["nonce"],"test-nonce");assert_eq!(header["url"],format!("{origin}/account"));
                    let sig=decode(&jws["signature"]);
                    assert!(EcdsaSig::from_private_components(BigNum::from_slice(&sig[..32]).unwrap(),BigNum::from_slice(&sig[32..]).unwrap()).unwrap()
                        .verify(&boring::sha::sha256(format!("{}.{}",jws["protected"].as_str().unwrap(),jws["payload"].as_str().unwrap()).as_bytes()),&public).unwrap());
                    let binding=&payload["externalAccountBinding"];
                    let protected:Value=serde_json::from_slice(&decode(&binding["protected"])).unwrap();
                    assert_eq!(protected,json!({"alg":"HS256","kid":"test-kid","url":format!("{origin}/account")}));
                    assert_eq!(serde_json::from_slice::<Value>(&decode(&binding["payload"])).unwrap(),header["jwk"]);
                    let expected=boring::hash::hmac_sha256(&[0x42;32],format!("{}.{}",binding["protected"].as_str().unwrap(),binding["payload"].as_str().unwrap()).as_bytes()).unwrap();
                    assert_eq!(decode(&binding["signature"]),expected);
                    assert_eq!(payload["contact"],json!(["mailto:operator@example.dev"]));
                    if attempts.fetch_add(1,Ordering::Relaxed)==0 {
                        Response::builder().status(400).body(Full::new(Bytes::from_static(br#"{"type":"urn:ietf:params:acme:error:badNonce"}"#))).unwrap()
                    } else {
                        Response::builder().status(201).header(header::LOCATION,"https://acme.example.dev/account/1").body(Full::new(Bytes::from_static(br#"{"status":"valid"}"#))).unwrap()
                    }
                }
            }
        }).await;
        let credentials = Credentials {
            key_id: "test-kid".into(),
            b64_mac_key: URL_SAFE_NO_PAD.encode([0x42; 32]),
        };
        let http = Http::new(None, Duration::from_secs(2))
            .unwrap()
            .with_loopback_http();
        assert_eq!(
            register_eab(
                &http,
                &format!("{}/directory", server.url),
                der.secret_pkcs8_der(),
                "operator@example.dev",
                &credentials
            )
            .await
            .unwrap()
            .0
            .id(),
            "https://acme.example.dev/account/1"
        );
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }
    #[tokio::test]
    async fn eab_does_not_retry_rejected_credentials() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let server = http_server({
            let attempts = attempts.clone();
            move |request| {
                let attempts = attempts.clone();
                async move {
                    let origin = format!("http://{}", request.headers()["host"].to_str().unwrap());
                    match request.uri().path() {
                        "/directory" => Response::new(Full::new(Bytes::from(serde_json::to_vec(
                            &json!({"newAccount":format!("{origin}/account"),
                                "newNonce":format!("{origin}/nonce"),"newOrder":format!("{origin}/order")})
                        ).unwrap()))),
                        "/nonce" => Response::builder().header("Replay-Nonce", "nonce")
                            .body(Full::new(Bytes::new())).unwrap(),
                        _ => {
                            attempts.fetch_add(1, Ordering::Relaxed);
                            Response::builder().status(400).body(Full::new(Bytes::from_static(
                                br#"{"type":"urn:ietf:params:acme:error:unauthorized"}"#
                            ))).unwrap()
                        }
                    }
                }
            }
        }).await;
        let (_, der) = CRYPTO.key_provider.generate_key().unwrap();
        let http = Http::new(None, Duration::from_secs(2))
            .unwrap()
            .with_loopback_http();
        let result = register_eab(
            &http,
            &format!("{}/directory", server.url),
            der.secret_pkcs8_der(),
            "operator@example.test",
            &Credentials {
                key_id: "rejected".into(),
                b64_mac_key: URL_SAFE_NO_PAD.encode([0x42; 32]),
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }
}
