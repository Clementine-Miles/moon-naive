//! Evidence helpers shared by unit and integration tests; not a production module.
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
#[derive(Clone)]
pub struct Case(Arc<Inner>);
struct Inner {
    root: PathBuf,
    start: Instant,
    events: Mutex<File>,
}
impl Case {
    pub fn new(name: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::var_os("ACME_LAB_ARTIFACTS")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("moon-acme-lab"));
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = base.join(format!("{name}-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let events = File::create(root.join("events.jsonl")).unwrap();
        let case = Self(Arc::new(Inner {
            root,
            start: Instant::now(),
            events: Mutex::new(events),
        }));
        case.write("manifest.json",&json!({"case":name,"test_name":std::thread::current().name(),"pid":std::process::id(),"utc_epoch_ns":stamp.to_string(),"argv":std::env::args().collect::<Vec<_>>(),"evidence":"pending","artifacts_retained":true,"moon_version":env!("CARGO_PKG_VERSION"),"baseline":base.join("baseline.json")}));
        eprintln!("ACME_LAB_ARTIFACTS={}", case.path().display());
        case
    }
    pub fn path(&self) -> &Path {
        &self.0.root
    }
    pub fn event(&self, kind: &str, value: Value) {
        let entry = json!({"kind":kind,"elapsed_us":self.0.start.elapsed().as_micros(),"utc_epoch_us":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros(),"data":value});
        let mut file = self.0.events.lock().unwrap();
        writeln!(file, "{entry}").unwrap();
        file.flush().unwrap();
    }
    pub fn write(&self, name: &str, value: &Value) {
        fs::write(
            self.path().join(name),
            serde_json::to_vec_pretty(value).unwrap(),
        )
        .unwrap();
    }
    pub fn journal(&self, root: &Path, label: &str) -> Value {
        let state = fs::read_dir(root.join("acme"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|v| v == "json"))
            .unwrap();
        let bytes = fs::read(state).unwrap();
        fs::write(self.path().join(format!("journal-{label}.json")), &bytes).unwrap();
        self.event("journal", json!({"label":label,"bytes":bytes.len()}));
        serde_json::from_slice(&bytes).unwrap()
    }
    pub fn capture(&self, ports: &[u16]) -> Option<Capture> {
        let mode = std::env::var("ACME_LAB_CAPTURE").unwrap_or_default();
        let required = mode == "required";
        if !required && mode != "optional" {
            return None;
        }
        self.write("ports.json", &json!({"ports":ports}));
        let filter = ports
            .iter()
            .map(|p| format!("port {p}"))
            .collect::<Vec<_>>()
            .join(" or ");
        let exe = std::env::var_os("ACME_LAB_TCPDUMP").unwrap_or_else(|| "tcpdump".into());
        let log = File::create(self.path().join("tcpdump.log")).unwrap();
        let spawn = Command::new(exe)
            .args([
                "--immediate-mode",
                "-i",
                "lo",
                "-U",
                "-n",
                "-s",
                "0",
                "-Z",
                "root",
                "-w",
            ])
            .arg(self.path().join("wire.pcap"))
            .arg(&filter)
            .stdout(Stdio::null())
            .stderr(log)
            .spawn();
        match spawn {
            Ok(mut child) => {
                std::thread::sleep(std::time::Duration::from_millis(80));
                if let Ok(Some(status)) = child.try_wait() {
                    self.event(
                        "pcap_unavailable",
                        json!({"exit":status.code(),"filter":filter}),
                    );
                    assert!(
                        !required,
                        "required capture exited before the case: {status}"
                    );
                    None
                } else {
                    self.event("capture_started", json!({"pid":child.id(),"filter":filter}));
                    Some(Capture {
                        child,
                        case: self.clone(),
                    })
                }
            }
            Err(error) => {
                self.event(
                    "pcap_unavailable",
                    json!({"error":error.to_string(),"filter":filter}),
                );
                assert!(!required, "required capture could not start: {error}");
                None
            }
        }
    }
    #[allow(dead_code)] // The integration fixture uses the CA-side keylog instead.
    pub fn keylog(&self) -> Arc<Mutex<File>> {
        use std::os::unix::fs::OpenOptionsExt;
        Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(self.path().join("tls.keys"))
                .unwrap(),
        ))
    }
}
pub struct Capture {
    child: Child,
    case: Case,
}
impl Drop for Capture {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status();
        let status = self.child.wait();
        self.case
            .event("capture_stopped", json!({"exit_code":status.as_ref().ok().and_then(|s|s.code()),"status":format!("{status:?}")}));
    }
}
