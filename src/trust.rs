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
    pub(crate) async fn get(&self) -> crate::Result<Option<Certificates>> {
        let roots = self
            .0
            .loaded
            .get_or_try_init(|| async {
                let Some(path) = self.0.path.clone() else {
                    return Ok(None);
                };
                // Both filesystem IO and X509 parsing stay off the data-plane workers.
                tokio::task::spawn_blocking(move || -> crate::Result<_> {
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

#[cfg(test)]
mod tests {
    use super::*;
    const CA: &[u8] = include_bytes!("../assets/le-staging-roots.crt");

    #[tokio::test]
    async fn roots_shared_across_clones_and_reloaded_for_new_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.crt");
        std::fs::write(&path, CA).unwrap();
        let roots = Roots::new(Some(path.clone()));
        let clone = roots.clone();
        let (a, b) = tokio::join!(roots.get(), clone.get());
        let a = a.unwrap().unwrap();
        assert!(Arc::ptr_eq(&a, &b.unwrap().unwrap()));
        std::fs::remove_file(&path).unwrap();
        assert!(Arc::ptr_eq(&a, &roots.get().await.unwrap().unwrap()));
        let next = Roots::new(Some(path.clone()));
        assert!(next.get().await.is_err());
        std::fs::write(&path, b"invalid or empty bundle").unwrap();
        assert!(next.get().await.is_err());
        std::fs::write(path, CA).unwrap();
        let b = next.get().await.unwrap().unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(a[0].to_der().unwrap(), b[0].to_der().unwrap());
    }

    #[tokio::test]
    async fn absent_bundle_leaves_tls_library_default_trust_enabled() {
        assert!(Roots::new(None).get().await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "release microbenchmark; run separately with --nocapture --test-threads=1"]
    async fn benchmark_forward_trust_bundle() {
        let path = system_ca_file().expect("benchmark requires system CA bundle");
        let roots = Roots::new(Some(path.clone()));
        let certs = roots.get().await.unwrap().unwrap();
        let mut old = Vec::new();
        let mut new = Vec::new();
        for _ in 0..101 {
            let start = std::time::Instant::now();
            let bytes = std::fs::read(&path).unwrap();
            let parsed = boring::x509::X509::stack_from_pem(&bytes).unwrap();
            assert_eq!(parsed.len(), certs.len());
            old.push(start.elapsed());
            let start = std::time::Instant::now();
            std::hint::black_box(roots.get().await.unwrap());
            new.push(start.elapsed());
        }
        old.sort();
        new.sort();
        eprintln!(
            "forward CA: old_read_parse={:?}/request new_cached={:?}/request (median, roots={}, samples=101)",
            old[50],
            new[50],
            certs.len()
        );
    }
}
