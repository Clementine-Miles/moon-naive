//! Locate the distribution's CA bundle without changing process environment.
use std::path::{Path, PathBuf};
use std::sync::Arc;

type Certificates = Arc<Box<[boring::x509::X509]>>;

/// One lazily parsed trust bundle per application/configuration generation.
/// Clones and different forward origins share it; new generations reload it.
#[derive(Clone)]
pub(crate) struct Roots(Arc<RootState>);
struct RootState {
    path: Option<PathBuf>,
    loaded: tokio::sync::OnceCell<Option<Certificates>>,
}
impl Roots {
    pub(crate) fn new(path: Option<PathBuf>) -> Self {
        Self(Arc::new(RootState {
            path,
            loaded: tokio::sync::OnceCell::new(),
        }))
    }
    pub(crate) async fn get(&self) -> crate::acme::Result<Option<Certificates>> {
        let roots = self
            .0
            .loaded
            .get_or_try_init(|| async {
                let Some(path) = self.0.path.clone() else {
                    return Ok(None);
                };
                // Both filesystem IO and X509 parsing stay off the data-plane workers.
                tokio::task::spawn_blocking(move || -> crate::acme::Result<_> {
                    let bytes = std::fs::read(path)?;
                    let certs = boring::x509::X509::stack_from_pem(&bytes)?;
                    if certs.is_empty() {
                        return Err("empty forward proxy CA bundle".into());
                    }
                    Ok(Some(Arc::new(certs.into_boxed_slice())))
                })
                .await?
            })
            .await?;
        Ok(roots.clone())
    }
}

pub(crate) fn system_ca_file() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("SSL_CERT_FILE") {
        return Some(path.into());
    }
    [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/cert.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
    ]
    .iter()
    .map(Path::new)
    .find(|path| path.is_file())
    .map(Path::to_owned)
}
