//! Unix local single-writer store. CURRENT is the only commit point.
//! Cryptographic validation is completed by certificate::Validator before install.
use super::certificate::{Candidate, Lifetime, VerifiedBundle};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

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
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > max as u64 {
        return Err(invalid("invalid state file"));
    }
    #[cfg(unix)]
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(invalid("state file is not private"));
    }
    let mut out = Vec::new();
    File::open(path)?
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
        let file = options.open(path)?;
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
