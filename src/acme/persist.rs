//! Durable write-ahead journal. A kernel file lock releases on process death.
use super::certificate::{Candidate, Lifetime, VerifiedBundle};
use crate::Result;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
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
    #[serde(default)]
    pub blocked_certificate: Option<BlockedCertificate>,
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
/// Public certificate evidence only; the original order retains its private key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedCertificate {
    pub sha256: String,
    pub category: String,
    #[serde(default)]
    pub original_bytes: usize,
    /// Legacy name: bounded diagnostic prefix, not a complete-chain contract.
    pub chain_pem: Vec<u8>,
    pub retry_at: Option<u64>,
}
impl BlockedCertificate {
    /// Public diagnostic prefix, bounded before copying/JSON expansion.
    pub const EVIDENCE_BYTES: usize = 16 * 1024;
    pub fn evidence(body: &[u8]) -> Self {
        Self {
            sha256: boring::sha::sha256(body)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            original_bytes: body.len(),
            chain_pem: body[..body.len().min(Self::EVIDENCE_BYTES)].to_vec(),
            category: String::new(),
            retry_at: None,
        }
    }
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
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeasePhase {
    // Legacy journals default conservatively: an absent ID never proves no POST.
    #[default]
    CreateUncertain,
    /// Read-only preparation: no mutation has been submitted.
    Preparing,
    Created,
    /// Persisted before ACK: cancellation cannot prove validation has finished.
    Validating,
    DeleteUncertain,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    #[serde(default)]
    pub phase: LeasePhase,
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
        match read_private(&self.root.join(&self.name), 8 * 1024 * 1024) {
            Ok(bytes) => {
                let mut journal: Journal = serde_json::from_slice(&bytes)?;
                if let Some(evidence) = journal.blocked_certificate.as_mut() {
                    if evidence.original_bytes == 0 {
                        evidence.original_bytes = evidence.chain_pem.len();
                    }
                    evidence
                        .chain_pem
                        .truncate(BlockedCertificate::EVIDENCE_BYTES);
                }
                Ok(Some(journal))
            }
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
            let journal: Journal = serde_json::from_slice(&read_private(&path, 8 * 1024 * 1024)?)?;
            if !journal.leases.is_empty() {
                return Err("another issuer has pending DNS cleanup; run cleanup with its original configuration first".into());
            }
        }
        Ok(())
    }
    pub fn save(&self, journal: &Journal) -> Result<()> {
        let data = serde_json::to_vec(journal)?;
        if data.len() > 8 * 1024 * 1024 {
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

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
fn unique_id() -> String {
    format!(
        "{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn private_dir(path: &Path, recursive: bool) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(path)
}
fn write_new(path: &Path, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Err(invalid("empty write refused"));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.sync_all()
}
fn read_bounded(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    super::persist::open_private(path, max)?
        .take(max as u64 + 1)
        .read_to_end(&mut out)?;
    if out.is_empty() || out.len() > max {
        return Err(invalid("invalid state file length"));
    }
    Ok(out)
}
struct WriterLock {
    _file: File,
}
impl WriterLock {
    fn acquire(root: &Path) -> io::Result<Self> {
        let path = root.join("writer.lock");
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if !meta.is_file() {
                return Err(invalid(
                    "legacy directory or symlink writer lock requires explicit recovery",
                ));
            }
            #[cfg(unix)]
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(invalid("writer lock must be private"));
            }
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        options.mode(0o600);
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
        let file = options.open(path)?;
        super::persist::validate_private(&file, 1024)?;
        file.try_lock().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "certificate writer already active",
            )
        })?;
        Ok(Self { _file: file })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFailure {
    Uncommitted,
    CommitUncertain,
}

pub struct DiskStore {
    root: PathBuf,
}
pub struct StoredCertificate {
    pub generation: String,
    pub candidate: Candidate,
    pub lifetime: Lifetime,
}
impl DiskStore {
    pub fn open(root: &Path) -> io::Result<Self> {
        if !root.is_absolute() {
            return Err(invalid("absolute state directory required"));
        }
        private_dir(root, true)?;
        let meta = fs::symlink_metadata(root)?;
        if !meta.is_dir() {
            return Err(invalid("state root must be a real directory"));
        }
        #[cfg(unix)]
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(invalid("state directory must be private (0700)"));
        }
        Ok(Self { root: root.into() })
    }
    fn install_transaction(
        &mut self,
        bundle: &VerifiedBundle,
        committed: &mut bool,
    ) -> io::Result<()> {
        let _lock = WriterLock::acquire(&self.root)?;
        let id = unique_id();
        let generation = format!("generation-{id}");
        let dir = self.root.join(&generation);
        private_dir(&dir, false)?;
        write_new(&dir.join("chain.pem"), &bundle.material().chain_pem)?;
        write_new(&dir.join("key.pem"), &bundle.material().key_pem)?;
        let meta = format!(
            "{} {}\n",
            bundle.lifetime().not_before,
            bundle.lifetime().not_after
        );
        write_new(&dir.join("lifetime"), meta.as_bytes())?;
        File::open(&dir)?.sync_all()?;
        File::open(&self.root)?.sync_all()?;
        let temp = self.root.join(format!("CURRENT-{id}.tmp"));
        write_new(&temp, generation.as_bytes())?;
        fs::rename(&temp, self.root.join("CURRENT"))?;
        *committed = true;
        // After rename, any failure is an uncertain durability result. Never roll
        // back or remove the generation here; startup must reconcile CURRENT.
        File::open(&self.root)?.sync_all()
    }
    /// Validated bounded pointer read; does not read certificate/key material.
    /// An unchanged immutable generation needs no repeated TLS construction.
    pub fn current_generation(&self) -> io::Result<Option<String>> {
        let raw = match read_bounded(&self.root.join("CURRENT"), 128) {
            Ok(raw) => raw,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let generation =
            String::from_utf8(raw).map_err(|_| invalid("invalid generation pointer"))?;
        let suffix = generation
            .strip_prefix("generation-")
            .ok_or_else(|| invalid("invalid generation pointer"))?;
        if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
            return Err(invalid("unsafe generation pointer"));
        }
        Ok(Some(generation))
    }
    pub fn read_current(&self) -> io::Result<Option<StoredCertificate>> {
        let Some(generation) = self.current_generation()? else {
            return Ok(None);
        };
        let dir = self.root.join(&generation);
        if !fs::symlink_metadata(&dir)?.is_dir() {
            return Err(invalid("generation must be a real directory"));
        }
        let candidate = Candidate {
            chain_pem: read_bounded(&dir.join("chain.pem"), 1024 * 1024)?,
            key_pem: read_bounded(&dir.join("key.pem"), 64 * 1024)?,
        };
        let meta = read_bounded(&dir.join("lifetime"), 64)?;
        let text = std::str::from_utf8(&meta).map_err(|_| invalid("invalid lifetime"))?;
        let nums: Vec<_> = text.split_whitespace().collect();
        if nums.len() != 2 {
            return Err(invalid("invalid lifetime"));
        }
        let lifetime = Lifetime {
            not_before: nums[0].parse().map_err(|_| invalid("invalid lifetime"))?,
            not_after: nums[1].parse().map_err(|_| invalid("invalid lifetime"))?,
        };
        if lifetime.not_after <= lifetime.not_before {
            return Err(invalid("invalid lifetime"));
        }
        Ok(Some(StoredCertificate {
            generation,
            candidate,
            lifetime,
        }))
    }
    pub fn install(&mut self, bundle: &VerifiedBundle) -> Result<(), StoreFailure> {
        let mut committed = false;
        self.install_transaction(bundle, &mut committed)
            .map_err(|_| {
                if committed {
                    StoreFailure::CommitUncertain
                } else {
                    StoreFailure::Uncommitted
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("naive-store-test-{}", unique_id())))
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn bundle(tag: u8) -> VerifiedBundle {
        VerifiedBundle::from_validator(
            Candidate {
                chain_pem: vec![tag; 32],
                key_pem: vec![tag; 16],
            },
            Lifetime {
                not_before: 0,
                not_after: 90,
            },
        )
        .unwrap()
    }
    #[test]
    fn atomic_pair_and_old_generation_are_preserved() {
        let scratch = Scratch::new();
        let mut s = DiskStore::open(&scratch.0).unwrap();
        assert!(s.read_current().unwrap().is_none());
        s.install(&bundle(1)).unwrap();
        let old = s.read_current().unwrap().unwrap();
        s.install(&bundle(2)).unwrap();
        let new = s.read_current().unwrap().unwrap();
        assert_ne!(old.generation, new.generation);
        assert_eq!(new.candidate.chain_pem, vec![2; 32]);
        assert_eq!(new.candidate.key_pem, vec![2; 16]);
        assert_eq!(
            read_bounded(&scratch.0.join(old.generation).join("key.pem"), 64).unwrap(),
            vec![1; 16]
        );
    }
    #[test]
    fn lock_contention_cannot_replace_current() {
        let scratch = Scratch::new();
        let mut s = DiskStore::open(&scratch.0).unwrap();
        s.install(&bundle(1)).unwrap();
        let old = fs::read(scratch.0.join("CURRENT")).unwrap();
        let lock = WriterLock::acquire(&scratch.0).unwrap();
        assert!(s.install(&bundle(2)).is_err());
        assert_eq!(fs::read(scratch.0.join("CURRENT")).unwrap(), old);
        drop(lock);
        s.install(&bundle(2)).unwrap();
    }
    #[test]
    fn uncommitted_generation_is_not_visible() {
        let scratch = Scratch::new();
        let mut s = DiskStore::open(&scratch.0).unwrap();
        s.install(&bundle(1)).unwrap();
        let partial = scratch.0.join("generation-999");
        private_dir(&partial, false).unwrap();
        write_new(&partial.join("chain.pem"), b"incomplete new generation").unwrap();
        assert_eq!(
            s.read_current().unwrap().unwrap().candidate.chain_pem,
            vec![1; 32]
        );
    }
    #[test]
    fn empty_material_and_pointer_traversal_are_rejected() {
        assert!(
            VerifiedBundle::from_validator(
                Candidate {
                    chain_pem: vec![],
                    key_pem: vec![1]
                },
                Lifetime {
                    not_before: 0,
                    not_after: 10
                }
            )
            .is_err()
        );
        let scratch = Scratch::new();
        let s = DiskStore::open(&scratch.0).unwrap();
        write_new(&scratch.0.join("CURRENT"), b"generation-../../other").unwrap();
        assert!(s.read_current().is_err());
    }
    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_state_directories() {
        use std::os::unix::fs::symlink;
        let scratch = Scratch::new();
        private_dir(&scratch.0, true).unwrap();
        let target = scratch.0.join("target");
        private_dir(&target, false).unwrap();
        let link = scratch.0.join("link");
        symlink(&target, &link).unwrap();
        assert!(DiskStore::open(&link).is_err());
    }
}
