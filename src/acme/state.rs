//! Durable write-ahead journal. A kernel file lock releases on process death.
use super::Result;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub version: u32,
    pub domain: String,
    pub directory: String,
    pub dns_identity: String,
    pub account_key: Vec<u8>,
    pub account: Option<serde_json::Value>,
    #[serde(default)]
    pub account_id: Option<String>,
    pub order: Option<Order>,
    #[serde(default)]
    pub retired_order: Option<RetiredOrder>,
    pub leases: Vec<Lease>,
    pub next_attempt: u64,
    pub failures: u32,
    pub renew_at: u64,
    pub ari_check_at: u64,
    pub ari_window: Option<(u64, u64)>,
    pub ari_selected: Option<u64>,
    #[serde(default)]
    pub last_failure_phase: Option<String>,
}
/// One bounded diagnostic record; obsolete certificate private keys are discarded.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredOrder {
    pub url_sha256: String,
    pub retired_at: u64,
    pub not_after: u64,
    pub reason: String,
}
impl Journal {
    pub fn retire_completed(&mut self, now: u64, not_after: u64, retry_at: u64) -> Result<()> {
        let order = self.order.take().ok_or("no completed order to retire")?;
        self.retired_order = Some(RetiredOrder {
            url_sha256: boring::sha::sha256(order.url.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            retired_at: now,
            not_after,
            reason: "completed-certificate-obsolete".into(),
        });
        self.next_attempt = retry_at.max(now.saturating_add(3600));
        self.last_failure_phase = Some("completed-certificate-obsolete".into());
        // Account identity and DNS leases must survive this transition.
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Order {
    pub url: String,
    pub key_pem: String,
    pub csr: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub name: String,
    pub value: String,
    pub marker: String,
    pub record_id: Option<String>,
    pub borrowed: bool,
}
pub struct State {
    root: PathBuf,
    name: String,
    _lock: File,
}
/// Validate the descriptor actually read. Parent directories must remain trusted;
/// NOFOLLOW protects the final component, NONBLOCK prevents FIFO open stalls.
pub(super) fn open_private(path: &Path, limit: usize) -> std::io::Result<File> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let file = File::from(fd);
    validate_private(&file, limit)?;
    Ok(file)
}
pub(super) fn validate_private(file: &File, limit: usize) -> std::io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > limit as u64
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected bounded private regular file",
        ));
    }
    Ok(())
}
pub fn read_private(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    open_private(path, limit)?
        .take(limit as u64 + 1)
        .read_to_end(&mut data)?;
    if data.is_empty() || data.len() > limit {
        return Err("invalid state/secret length".into());
    }
    Ok(data)
}
impl State {
    pub fn open(root: &Path, namespace: &str) -> Result<Self> {
        if namespace.len() != 64 || !namespace.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid journal namespace".into());
        }
        if !root.is_absolute() {
            return Err("absolute ACME state directory required".into());
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)?;
        let meta = fs::symlink_metadata(root)?;
        if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
            return Err("ACME state directory must be a real private directory (0700)".into());
        }
        let lock_path = root.join("manager.lock");
        if let Ok(metadata) = fs::symlink_metadata(&lock_path)
            && (!metadata.is_file() || metadata.permissions().mode() & 0o077 != 0)
        {
            return Err("invalid manager lock".into());
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&lock_path)?;
        validate_private(&lock, 1024)?;
        lock.try_lock()
            .map_err(|_| "another ACME manager owns this state")?;
        Ok(Self {
            root: root.into(),
            name: format!("journal-{namespace}.json"),
            _lock: lock,
        })
    }
    pub fn load(&self) -> Result<Option<Journal>> {
        match read_private(&self.root.join(&self.name), 2 * 1024 * 1024) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
    /// Switching issuer must not silently abandon a pending TXT cleanup.
    pub fn check_other_journals(&self) -> Result<()> {
        for (index, entry) in fs::read_dir(&self.root)?.enumerate() {
            if index >= 128 {
                return Err("too many ACME state files; explicit inspection required".into());
            }
            let path = entry?.path();
            if path.file_name().is_some_and(|n| n == self.name.as_str())
                || path.extension().is_none_or(|n| n != "json")
            {
                continue;
            }
            let journal: Journal = serde_json::from_slice(&read_private(&path, 2 * 1024 * 1024)?)?;
            if !journal.leases.is_empty() {
                return Err("another issuer has pending DNS cleanup; run cleanup with its original configuration first".into());
            }
        }
        Ok(())
    }
    pub fn save(&self, journal: &Journal) -> Result<()> {
        let data = serde_json::to_vec(journal)?;
        if data.len() > 2 * 1024 * 1024 {
            return Err("ACME journal exceeds limit".into());
        }
        let mut random = [0; 16];
        boring::rand::rand_bytes(&mut random)?;
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let temp = self.root.join(format!("journal-{name}.tmp"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&data)?;
        file.sync_all()?;
        fs::rename(&temp, self.root.join(&self.name))?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

// Private TOML parsing shares the bounded private-file reader above.
// Never expose source lines containing credentials in parser errors.
pub(crate) fn parse_toml<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let text = std::str::from_utf8(bytes).map_err(|_| "private TOML must be UTF-8")?;
    toml::from_str(text).map_err(|_| "invalid private TOML configuration".into())
}

pub(crate) fn load_toml<T: serde::de::DeserializeOwned>(path: &Path, limit: usize) -> Result<T> {
    parse_toml(&read_private(path, limit)?)
}

/// Publish a complete private file without replacing any existing destination.
/// Used by config init/migrate and EAB import; the parent must be trusted.
pub fn write_private_new(destination: &Path, bytes: &[u8]) -> Result<()> {
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut random = [0; 16];
    boring::rand::rand_bytes(&mut random)?;
    let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let temporary = parent.join(format!(".moon-naive-private-{suffix}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::hard_link(&temporary, destination)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    fs::remove_file(&temporary)?;
    result
}

#[cfg(test)]
mod private_toml_tests {
    use super::*;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Token {
        api_token: String,
    }
    #[test]
    fn strict_toml_and_errors_never_include_secret_source() {
        assert_eq!(
            parse_toml::<Token>(b"api_token = 'private-value'")
                .unwrap()
                .api_token,
            "private-value"
        );
        for input in [
            b"{\"api_token\":\"private-value\"}".as_slice(),
            b"api_token = 'private-value'\nextra = true",
            b"api_token = 'private-value'\napi_token = 'duplicate-secret'",
            b"api_token = 'private-value",
            b"api_token = '\xff'",
        ] {
            let error = parse_toml::<Token>(input).err().unwrap().to_string();
            assert!(!error.contains("private-value"));
            assert!(!error.contains("duplicate-secret"));
        }
    }
}
