//! Private, process-bound renewal heartbeat; never a public readiness endpoint.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Observation {
    pid: u32,
    start: String,
    boot: String,
    heartbeat: u64,
    running: bool,
    pub next_attempt: u64,
    pub last_success: u64,
    pub phase: String,
    pub reconciliation_required: bool,
}
fn start(pid: u32) -> Result<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(stat
        .rsplit_once(") ")
        .ok_or("invalid process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or("missing process start")?
        .into())
}
fn boot() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .into())
}
fn uptime() -> Result<u64> {
    Ok(fs::read_to_string("/proc/uptime")?
        .split('.')
        .next()
        .ok_or("invalid uptime")?
        .parse()?)
}
/// Rewrite an unchanged heartbeat at most this often; `report` treats a
/// heartbeat older than 15 seconds as stale.
const PULSE_INTERVAL_SECS: u64 = 5;
pub(crate) struct Worker {
    path: PathBuf,
    pub observation: Observation,
    /// Uptime and content (without the heartbeat) of the last write.
    last: Option<(u64, Vec<u8>)>,
}
impl Worker {
    pub fn new(path: PathBuf) -> Result<Self> {
        let pid = std::process::id();
        let mut worker = Self {
            path,
            observation: Observation {
                pid,
                start: start(pid)?,
                boot: boot()?,
                heartbeat: 0,
                running: true,
                next_attempt: 0,
                last_success: 0,
                phase: "starting".into(),
                reconciliation_required: false,
            },
            last: None,
        };
        worker.pulse()?;
        Ok(worker)
    }
    pub fn pulse(&mut self) -> Result<()> {
        let now = uptime()?;
        self.observation.heartbeat = 0;
        let content = serde_json::to_vec(&self.observation)?;
        self.observation.heartbeat = now;
        if let Some((written, previous)) = &self.last
            && *previous == content
            && now.saturating_sub(*written) < PULSE_INTERVAL_SECS
        {
            return Ok(());
        }
        let parent = self.path.parent().ok_or("health parent")?;
        // Parent is the validated private ACME state directory. Replacement
        // never follows the destination; a preexisting symlink is rejected.
        if fs::symlink_metadata(&self.path).is_ok() {
            super::persist::read_private(&self.path, 4096)?;
        }
        let temporary = parent.join(format!(
            ".worker-{}-{}.tmp",
            self.observation.pid,
            super::random_below(u64::MAX)?
        ));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        // Atomic replacement keeps readers from seeing a torn file, but the
        // heartbeat is deliberately not fsynced: it is rewritten every few
        // seconds, is reconstructed on restart, and `report` validates it
        // against the live process and boot ID. Durable recovery state lives in
        // the ACME journal, which keeps its own fsync discipline.
        let result = (|| -> Result<()> {
            file.write_all(&serde_json::to_vec(&self.observation)?)?;
            fs::rename(&temporary, &self.path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        } else {
            self.last = Some((now, content));
        }
        result
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.observation.running = false;
        self.observation.reconciliation_required |= std::thread::panicking();
        let _ = self.pulse();
    }
}
pub(crate) fn report(path: &Path) -> Result<String> {
    if !path.exists() {
        return Ok("renewal_worker=unknown\n".into());
    }
    let o: Observation = serde_json::from_slice(&super::persist::read_private(path, 4096)?)?;
    let age = uptime()?.checked_sub(o.heartbeat);
    let live = o.running
        && start(o.pid).is_ok_and(|s| s == o.start)
        && boot()? == o.boot
        && age.is_some_and(|a| a <= 15);
    Ok(format!(
        "renewal_worker={}\nrenewal_process_id={}\nrenewal_heartbeat_age_secs={:?}\nrenewal_last_success={}\nrenewal_next_attempt={}\nrenewal_failure_phase={}\nrenewal_reconciliation_required={}\n",
        if live { "running" } else { "stopped_or_stale" },
        o.pid,
        age,
        o.last_success,
        o.next_attempt,
        o.phase,
        o.reconciliation_required
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stopped_reused_pid_and_stale_heartbeat_never_report_running() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("WORKER");
        let mut w = Worker::new(path.clone()).unwrap();
        assert!(report(&path).unwrap().contains("renewal_worker=running"));
        w.observation.start = "different".into();
        w.pulse().unwrap();
        assert!(report(&path).unwrap().contains("stopped_or_stale"));
        // Unchanged observations within the pulse interval are not rewritten,
        // but any state change is written immediately.
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        w.pulse().unwrap();
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
        w.observation.start = String::new();
        w.pulse().unwrap();
        assert!(report(&path).unwrap().contains("stopped_or_stale"));
        drop(w);
        assert!(report(&path).unwrap().contains("stopped_or_stale"));
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(report(&link).is_err());
    }
}
