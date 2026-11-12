//! Laboratory orchestration. Python is limited to independent packet/crypto analysis.
use super::{Result, check, root};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::os::unix::{
    fs::{OpenOptionsExt, PermissionsExt},
    process::CommandExt,
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const ACME: &[&str] = &[
    "ari_remote_retry_after_is_not_clipped_by_local_recheck_policy",
    "ari_rate_limit_wait_is_not_capped_by_local_recheck_policy",
    "nonce_endpoint_404_preserves_existing_order",
    "order_endpoint_404_is_attributed_to_order",
    "finalize_processing_honors_initial_retry_after_120",
    "retry_after_maximum_does_not_panic",
    "outer_retry_after_overflow_does_not_persist_saturated_date",
    "deferred_order_wait_survives_restart",
    "recovered_processing_preserves_first_retry_after",
    "cancellation_during_order_wait_preserves_restart_deadline",
    "retry_after_beyond_operation_deadline_defers_without_early_poll",
    "completed_future_not_before_recovers_same_order",
    "external_cancellation_closes_socket_and_owned_driver",
    "cloudflare_discovery_failure_recovers",
    "cloudflare_list_failure_recovers",
    "cloudflare_confirmed_create_rejection_recovers",
    "cloudflare_intent_cancel_before_post_recovers",
    "cloudflare_durable_send_gap_retains_uncertainty",
    "cloudflare_late_create_empty_cleanup_and_restart",
    "porkbun_discovery_failure_recovers",
    "porkbun_list_failure_recovers",
    "porkbun_confirmed_create_rejection_recovers",
    "porkbun_intent_cancel_before_post_recovers",
    "porkbun_durable_send_gap_retains_uncertainty",
    "porkbun_late_create_empty_cleanup_and_restart",
    "certificate_invalid_1m",
    "certificate_invalid_1m_plus_one",
    "certificate_invalid_2m",
    "certificate_invalid_3m",
    "certificate_invalid_4m",
    "certificate_invalid_4m_plus_one",
    "certificate_pem_1m",
    "certificate_pem_1m_plus_one",
    "certificate_pem_2m",
    "certificate_pem_3m",
    "certificate_pem_4m",
    "certificate_pem_4m_plus_one",
];
const LIVE: &[&str] = &[
    "acme_invalid_renewal_material_keeps_valid_network",
    "acme_live_two_renewals_h2_h3_and_old_connections",
    "acme_live_outer_expiry_then_inner_renewal_and_recovery",
    "acme_control_panic_degrades_renewal_and_keeps_valid_network",
    "acme_tls_loaded_diagnostic_failure_does_not_block_activation",
];
const LOCAL_CASES: &[&str] = &[
    "coalesced_output_wake_keeps_bounded_website_drain_running",
    "acme_tls_status_create_failure_before_load",
    "acme_tls_status_rename_failure_before_load",
    "acme_tls_status_fsync_failure_before_load",
    "acme_tls_status_failures_after_load_observe_partial_activation",
];
const PEBBLE: &[&str] = &[
    "issue_restart_renew_and_keep_certificate_during_dns_outage",
    "eab_issue_restart_renew_and_recover_account_without_eab_file",
    "challenge_timeout_before_ca_dns_preserves_validation",
    "challenge_sigterm_before_ca_dns_preserves_validation",
    "challenge_crash_restart_before_ca_dns_preserves_validation",
    "continuous_nonce_rejection_fails_boundedly",
    "authorization_reuse_does_not_require_second_dns_create",
];
const DEFAULT: &[&str] = &["oracles", "workspace", "pebble", "vendor", "resolver"];
const EXTRA: &[&str] = &[
    "mixed_h1_h2_h3_websocket_admission_holds_through_half_close",
    "website_pingora_streaming_proxy_reuses_pool_across_h2_h3_and_sanitizes_headers",
    "negotiated_windows_share_h2_h3_connections_without_content_changes",
];

fn suite(name: &str) -> Result<(Vec<String>, Vec<&'static str>, bool)> {
    let base = ["cargo", "test", "--locked", "-p", "moon-naive", "--lib"];
    let (args, expected, capture): (Vec<&str>, Vec<&str>, bool) = match name {
        "ari" => (
            base.into_iter().chain(["ari_"]).collect(),
            ACME[..2].to_vec(),
            true,
        ),
        "workspace" => (
            vec!["cargo", "test", "--locked", "--workspace"],
            [ACME, LIVE, LOCAL_CASES, EXTRA].concat(),
            true,
        ),
        "acme" => (
            base.into_iter().chain(["acme::"]).collect(),
            ACME.to_vec(),
            true,
        ),
        "network" => (
            base.into_iter().chain(["net::"]).collect(),
            [LIVE, LOCAL_CASES, EXTRA].concat(),
            true,
        ),
        "pebble" => (
            base.into_iter()
                .chain([
                    "acme::pebble::",
                    "--",
                    "--ignored",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .collect(),
            PEBBLE.to_vec(),
            true,
        ),
        "resolver" => (
            vec![],
            vec!["actual_system_dns_cancellation_keeps_running_job_until_reply"],
            true,
        ),
        "vendor" => (
            vec![
                "cargo",
                "test",
                "--manifest-path",
                "vendor/instant-acme/Cargo.toml",
                "--locked",
                "--no-default-features",
                "--features",
                "time,x509-parser",
                "--lib",
            ],
            vec![
                "retry_wait_checks_deadline_before_sleep",
                "retry_wait_does_not_discard_last_permitted_attempt",
            ],
            false,
        ),
        "oracles" => (
            vec![
                "cargo",
                "test",
                "--locked",
                "-p",
                "xtask",
                "lab::tests::",
                "--",
                "--nocapture",
            ],
            vec![
                "decoder_oracles",
                "evidence_requires_crypto_and_named_cases",
                "command_failure_and_zero_tests_stay_failed",
            ],
            false,
        ),
        _ => return Err(format!("unknown laboratory suite: {name}").into()),
    };
    Ok((
        args.into_iter().map(str::to_owned).collect(),
        expected,
        capture,
    ))
}
fn matches(name: &str, suffix: &str) -> bool {
    name == suffix || name.strip_suffix(suffix).is_some_and(|p| p.ends_with("::"))
}
fn jose(name: &str) -> bool {
    ACME.iter().chain(PEBBLE).any(|t| matches(name, t))
        && ![
            "external_cancellation_closes_socket_and_owned_driver",
            "cloudflare_durable_send_gap_retains_uncertainty",
            "porkbun_durable_send_gap_retains_uncertainty",
        ]
        .iter()
        .any(|t| matches(name, t))
}
fn files(path: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for item in fs::read_dir(path)? {
        let item = item?;
        if item.file_type()?.is_dir() {
            out.extend(files(&item.path())?);
        } else if item.file_type()?.is_file() {
            out.push(item.path());
        }
    }
    out.sort();
    Ok(out)
}
fn evidence<F>(dir: &Path, records: &[Value], mut decode: F) -> Result<(Vec<Value>, Vec<String>)>
where
    F: FnMut(&Path) -> Result<Value>,
{
    let mut cases = Vec::new();
    for p in files(dir)?
        .into_iter()
        .filter(|p| p.file_name().is_some_and(|n| n == "manifest.json"))
    {
        cases.push((
            p.parent().ok_or("manifest parent")?.to_owned(),
            serde_json::from_slice::<Value>(&fs::read(p)?)?,
        ));
    }
    let mut errors = Vec::new();
    let mut summaries = Vec::new();
    let mut required = false;
    for record in records {
        let (_, expected, capture) = suite(record["name"].as_str().ok_or("missing suite name")?)?;
        required |= capture;
        for test in expected {
            if !record["tests"].as_array().is_some_and(|ts| {
                ts.iter()
                    .any(|n| n.as_str().is_some_and(|n| matches(n, test)))
            }) {
                errors.push(format!("expected test did not run: {test}"));
            }
            if !capture {
                continue;
            }
            let found: Vec<_> = cases
                .iter()
                .filter(|(_, m)| m["test_name"].as_str().is_some_and(|n| matches(n, test)))
                .collect();
            if found.is_empty() {
                errors.push(format!("expected case manifest missing: {test}"));
            }
            for (case, _) in found {
                if !LOCAL_CASES.contains(&test) && !case.join("wire.pcap").is_file() {
                    errors.push(format!("expected capture missing: {}", case.display()));
                }
            }
        }
    }
    for (case, manifest) in cases {
        if !case.join("wire.pcap").exists() {
            continue;
        }
        let summary = match decode(&case) {
            Ok(value) => value,
            Err(error) => {
                errors.push(format!("{}: analysis failed: {error}", case.display()));
                continue;
            }
        };
        // A decoder response must contain its verification fields; missing data is not success.
        if let Some(es) = summary["errors"].as_array() {
            for e in es {
                errors.push(format!("{}: {e}", case.display()));
            }
        } else {
            errors.push(format!("{}: decoder errors field missing", case.display()));
        }
        let name = manifest["test_name"].as_str().unwrap_or("");
        if jose(name) && summary["valid_jose"].as_u64().unwrap_or(0) == 0 {
            errors.push(format!("JOSE not observed: {}", case.display()));
        }
        if name.contains("eab_issue_") && summary["eab_valid"].as_u64().unwrap_or(0) == 0 {
            errors.push(format!("EAB not verified: {}", case.display()));
        }
        let events: Vec<Value> = fs::read_to_string(case.join("events.jsonl"))?
            .lines()
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?;
        if events
            .iter()
            .any(|e| e["data"]["outage_was_not_exercised"] == true)
        {
            errors.push(format!("target outage was skipped: {}", case.display()));
        }
        if case
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("live-renew"))
        {
            let probes: Vec<_> = events
                .iter()
                .filter(|e| e["kind"] == "active_generation")
                .collect();
            if probes.len() < 3
                || probes.iter().any(|p| {
                    p["data"]["h2_sha256"].as_str().is_none()
                        || p["data"]["h2_sha256"] != p["data"]["h3_sha256"]
                })
            {
                errors.push(format!(
                    "missing or inconsistent activation probes: {}",
                    case.display()
                ));
            }
        }
        summaries.push(summary);
    }
    if required && summaries.is_empty() {
        errors.push("zero relevant captures analyzed".into());
    }
    Ok((summaries, errors))
}
fn successful(records: &[Value], errors: &[String], selected: &[String]) -> bool {
    !selected.is_empty()
        && errors.is_empty()
        && records
            .iter()
            .all(|r| r["exit_code"] == 0 && r["errors"].as_array().is_some_and(Vec::is_empty))
        && selected
            .iter()
            .all(|n| records.iter().any(|r| r["name"] == *n))
}
fn parsed_record(name: &str, args: &[String], code: i32, elapsed: f64, output: &str) -> Value {
    let mut names = Vec::new();
    let mut executed = 0usize;
    for line in output.lines() {
        if let Some(line) = line.strip_prefix("test ")
            && let Some((test, result)) = line.split_once(" ... ")
            && !result.starts_with("ignored")
        {
            names.push(test);
        }
        if let Some(line) = line.strip_prefix("test result: ") {
            for pair in line.split_whitespace().collect::<Vec<_>>().windows(2) {
                if matches!(pair[1], "passed;" | "failed;") {
                    executed += pair[0].parse::<usize>().unwrap_or(0);
                }
            }
        }
    }
    let errors = if executed == 0 {
        vec!["zero relevant Rust tests"]
    } else {
        vec![]
    };
    json!({"name":name,"command":args,"exit_code":code,"elapsed_seconds":elapsed,"tests":names,"errors":errors})
}
fn command(
    dir: &Path,
    name: &str,
    args: &[String],
    env: &BTreeMap<String, String>,
    namespace: bool,
    deadline: Duration,
) -> Result<Value> {
    let mut actual: Vec<String> = if namespace {
        [
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
            "--",
            "sh",
            "-c",
            "ip link set lo up; exec \"$@\"",
            "lab",
        ]
        .map(str::to_owned)
        .to_vec()
    } else {
        vec![]
    };
    actual.extend_from_slice(args);
    let start = Instant::now();
    let mut child = Command::new(&actual[0])
        .args(&actual[1..])
        .current_dir(root())
        .envs(env)
        .stdin(Stdio::null())
        .stdout(fs::File::create(dir.join(format!("{name}.stdout.log")))?)
        .stderr(fs::File::create(dir.join(format!("{name}.stderr.log")))?)
        .process_group(0)
        .spawn()?;
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status.code().unwrap_or(128)),
            Ok(None) if start.elapsed() < deadline => thread::sleep(Duration::from_millis(25)),
            result => {
                // Own the whole process group, including namespace children and fixtures.
                if let Ok(pid) = i32::try_from(child.id()) {
                    let _ = nix::sys::signal::killpg(
                        nix::unistd::Pid::from_raw(pid),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
                let _ = child.wait();
                break match result {
                    Err(e) => Err(e),
                    _ => Ok(124),
                };
            }
        }
    };
    let record = parsed_record(
        name,
        &actual,
        outcome?,
        start.elapsed().as_secs_f64(),
        &fs::read_to_string(dir.join(format!("{name}.stdout.log")))?,
    );
    println!("{name} {}", record["exit_code"]);
    Ok(record)
}
fn probe(args: &[&str], env: &BTreeMap<String, String>) -> Result<Value> {
    let out = Command::new(args[0])
        .args(&args[1..])
        .current_dir(root())
        .envs(env)
        .output()?;
    Ok(
        json!({"exit_code":out.status.code(),"stdout":String::from_utf8_lossy(&out.stdout),"stderr":String::from_utf8_lossy(&out.stderr)}),
    )
}
fn baseline(dir: &Path, env: &BTreeMap<String, String>) -> Result<()> {
    let mut value = json!({});
    for (name, args) in [
        ("HEAD", vec!["git", "rev-parse", "HEAD"]),
        ("worktree", vec!["git", "status", "--porcelain=v1"]),
        ("rustc", vec!["rustc", "-Vv"]),
        ("cargo", vec!["cargo", "-V"]),
        ("kernel", vec!["uname", "-a"]),
        ("cpu", vec!["lscpu"]),
        (
            "production_features",
            vec![
                "cargo",
                "tree",
                "--locked",
                "-p",
                "moon-naive",
                "-e",
                "features,no-dev",
            ],
        ),
    ] {
        value[name] = probe(&args, env)?;
    }
    for name in ["Cargo.lock", "vendor/instant-acme/Cargo.lock"] {
        value["lockfiles_sha256"][name] = json!(format!(
            "{:x}",
            Sha256::digest(fs::read(root().join(name))?)
        ));
    }
    for folder in ["src", "core", "tools/xtask/src"] {
        for p in files(&root().join(folder))?
            .into_iter()
            .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        {
            value["source_sha256"][p.strip_prefix(root())?.to_string_lossy().as_ref()] =
                json!(format!("{:x}", Sha256::digest(fs::read(&p)?)));
        }
    }
    value["source_sha256"]["tools/analyze.py"] = json!(format!(
        "{:x}",
        Sha256::digest(fs::read(root().join("tools/analyze.py"))?)
    ));
    for name in [
        "PEBBLE_BIN",
        "CHALLTESTSRV_BIN",
        "ACME_LAB_TCPDUMP",
        "ACME_LAB_TSHARK",
    ] {
        if let Some(path) = env.get(name).filter(|p| Path::new(p).is_file()) {
            value["tools"][name] =
                json!({"path":path,"sha256":format!("{:x}",Sha256::digest(fs::read(path)?))});
            let args = if name.contains("TCPDUMP") {
                vec![path.as_str(), "--version"]
            } else if name.contains("TSHARK") {
                vec![path.as_str(), "-v"]
            } else {
                vec!["go", "version", "-m", path]
            };
            value["tools"][name]["version"] =
                probe(&args, env).unwrap_or_else(|_| json!({"unavailable":true}));
        }
    }
    fs::write(
        dir.join("baseline.json"),
        serde_json::to_vec_pretty(&value)?,
    )?;
    for name in ["HEAD", "worktree", "rustc", "cargo", "production_features"] {
        check(
            value[name]["exit_code"] == 0,
            &format!("required baseline command failed: {name}"),
        )?;
    }
    Ok(())
}
fn locate(name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(name);
    if path.is_file() {
        return Some(path);
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

pub fn run(args: &[String]) -> Result<()> {
    let mut options = BTreeMap::new();
    for pair in args.chunks(2) {
        check(
            pair.len() == 2
                && [
                    "--only",
                    "--run",
                    "--home",
                    "--pebble",
                    "--challtestsrv",
                    "--pebble-source",
                    "--tcpdump",
                    "--tshark",
                    "--python",
                ]
                .contains(&pair[0].as_str()),
            "lab options require a known flag and value",
        )?;
        check(
            options.insert(pair[0].clone(), pair[1].clone()).is_none(),
            "duplicate lab option",
        )?;
    }
    let selected: Vec<String> = options
        .get("--only")
        .map(|n| vec![n.clone()])
        .unwrap_or_else(|| DEFAULT.iter().map(|s| (*s).into()).collect());
    for name in &selected {
        suite(name)?;
    }
    let home = PathBuf::from(
        options
            .get("--home")
            .cloned()
            .or_else(|| std::env::var("ACME_LAB_HOME").ok())
            .unwrap_or("/workspace/.moon-naive-acme-lab".into()),
    );
    let dir = PathBuf::from(options.get("--run").cloned().unwrap_or(format!(
        "/workspace/acme-lab-artifacts/{}-{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        std::process::id()
    )));
    let absolute = if dir.is_absolute() {
        dir
    } else {
        std::env::current_dir()?.join(dir)
    };
    fs::create_dir_all(absolute.parent().ok_or("artifact parent")?)?;
    let dir = absolute
        .parent()
        .ok_or("artifact parent")?
        .canonicalize()?
        .join(absolute.file_name().ok_or("artifact name")?);
    check(
        !dir.starts_with(root().canonicalize()?),
        "artifacts must be outside the source checkout",
    )?;
    fs::create_dir(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let python = options.get("--python").cloned().unwrap_or("python3".into());
    let mut env = BTreeMap::from([
        ("ACME_LAB_HOME".into(), home.to_string_lossy().into()),
        ("ACME_LAB_ARTIFACTS".into(), dir.to_string_lossy().into()),
        ("ACME_LAB_CAPTURE".into(), "required".into()),
        ("RUST_TEST_THREADS".into(), "1".into()),
        ("RUST_BACKTRACE".into(), "1".into()),
        ("MONA_LAB_PYTHON".into(), python.clone()),
    ]);
    for (var, flag, path) in [
        ("PEBBLE_SOURCE", "--pebble-source", "tools/pebble-src"),
        ("PEBBLE_BIN", "--pebble", "tools/bin/pebble"),
        (
            "CHALLTESTSRV_BIN",
            "--challtestsrv",
            "tools/bin/pebble-challtestsrv",
        ),
        (
            "ACME_LAB_TCPDUMP",
            "--tcpdump",
            "apt/prefix/usr/bin/tcpdump",
        ),
        ("ACME_LAB_TSHARK", "--tshark", "apt/prefix/usr/bin/tshark"),
    ] {
        env.insert(
            var.into(),
            options
                .get(flag)
                .cloned()
                .or_else(|| std::env::var(var).ok())
                .unwrap_or_else(|| home.join(path).to_string_lossy().into()),
        );
    }
    for key in [
        "ACME_LAB_TCPDUMP",
        "ACME_LAB_TSHARK",
        "PEBBLE_BIN",
        "CHALLTESTSRV_BIN",
    ] {
        if let Some(path) = locate(&env[key]) {
            env.insert(key.into(), path.to_string_lossy().into());
        }
    }
    env.insert(
        "LD_LIBRARY_PATH".into(),
        format!(
            "{}:{}",
            home.join("apt/prefix/usr/lib/x86_64-linux-gnu").display(),
            std::env::var("LD_LIBRARY_PATH").unwrap_or_default()
        ),
    );
    env.insert(
        "WIRESHARK_DATA_DIR".into(),
        std::env::var("WIRESHARK_DATA_DIR").unwrap_or_else(|_| {
            home.join("apt/prefix/usr/share/wireshark")
                .to_string_lossy()
                .into()
        }),
    );
    let bundle = format!("{}.tar.gz", dir.display());
    let mut result = json!({"schema":1,"success":false,"selected":selected,"commands":[],"evidence":[],"errors":[],"bundle":bundle});
    let work = (|| -> Result<()> {
        if selected.iter().any(|n| suite(n).is_ok_and(|s| s.2)) {
            let version = probe(
                &[
                    &python,
                    "-c",
                    "import cryptography; print(cryptography.__version__)",
                ],
                &env,
            )?;
            check(
                version["exit_code"] == 0,
                "required Python cryptography verifier unavailable",
            )?;
            result["crypto_verifier"] = json!({"python":python,"version":version["stdout"]});
        }
        baseline(&dir, &env)?;
        let mut records = Vec::new();
        for name in &selected {
            let (mut argv, _, capture) = suite(name)?;
            let mut local = env.clone();
            if capture {
                for key in ["ACME_LAB_TCPDUMP", "ACME_LAB_TSHARK"] {
                    check(
                        Path::new(&local[key]).is_file(),
                        &format!("required tool unavailable: {key}"),
                    )?;
                }
            }
            if name == "pebble" {
                for key in ["PEBBLE_SOURCE", "PEBBLE_BIN", "CHALLTESTSRV_BIN"] {
                    check(
                        Path::new(&local[key]).exists(),
                        &format!("required Pebble prerequisite missing: {key}"),
                    )?;
                }
                local.insert("ACME_LAB_FORCE_DNS_TCP".into(), "1".into());
            }
            if name == "vendor" {
                local.insert(
                    "CARGO_TARGET_DIR".into(),
                    home.join("vendor-target").to_string_lossy().into(),
                );
            }
            if name == "resolver" {
                let config = fs::read_to_string("/etc/resolv.conf")?;
                let address = config
                    .lines()
                    .find_map(|l| l.strip_prefix("nameserver "))
                    .ok_or("no system nameserver")?
                    .trim()
                    .parse::<std::net::Ipv4Addr>()?;
                local.insert("RES_OPTIONS".into(), "timeout:4 attempts:1".into());
                local.insert("ACME_LAB_DNS_LISTEN".into(), format!("{address}:53"));
                argv = [
                    "sh",
                    "-c",
                    "ip addr add \"$1/32\" dev lo; shift; exec \"$@\"",
                    "resolver",
                    &address.to_string(),
                    "cargo",
                    "test",
                    "--locked",
                    "-p",
                    "moon-naive",
                    "--lib",
                    "actual_system_dns_cancellation",
                    "--",
                    "--ignored",
                    "--nocapture",
                ]
                .map(str::to_owned)
                .to_vec();
            }
            records.push(command(
                &dir,
                name,
                &argv,
                &local,
                capture,
                Duration::from_secs(600),
            )?);
            result["commands"] = json!(records); // Preserve original outcomes even if indexing later fails.
        }
        let (summaries, errors) = evidence(&dir, &records, |case| {
            let output = Command::new(&python)
                .arg(root().join("tools/analyze.py"))
                .arg("--case")
                .arg(case)
                .arg("--tshark")
                .arg(&env["ACME_LAB_TSHARK"])
                .envs(&env)
                .output()?;
            check(output.status.success(), "packet decoder execution failed")?;
            Ok(serde_json::from_slice(&output.stdout)?)
        })?;
        result["evidence"] = json!(summaries);
        result["errors"] = json!(errors);
        Ok(())
    })();
    if let Err(error) = work {
        result["errors"]
            .as_array_mut()
            .ok_or("result errors")?
            .push(json!(error.to_string()));
    }
    let records: Vec<Value> = serde_json::from_value(result["commands"].clone())?;
    let errors: Vec<String> = serde_json::from_value(result["errors"].clone())?;
    let success = successful(&records, &errors, &selected);
    result["success"] = json!(success);
    fs::write(dir.join("result.json"), serde_json::to_vec_pretty(&result)?)?;
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(bundle)?;
    let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
        file,
        flate2::Compression::default(),
    ));
    archive.append_dir_all(dir.file_name().ok_or("run name")?, &dir)?;
    archive.into_inner()?.finish()?;
    println!("RESULT={}", dir.join("result.json").display());
    check(success, "laboratory failed; inspect its result.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_failure_and_zero_tests_stay_failed() {
        let selected = vec!["test".into()];
        let failed = parsed_record(
            "test",
            &[],
            101,
            0.,
            "test case ... ok\ntest result: ok. 1 passed; 0 failed;",
        );
        assert!(!successful(&[failed], &[], &selected));
        let empty = parsed_record(
            "test",
            &[],
            0,
            0.,
            "test case ... ignored\ntest result: ok. 0 passed; 0 failed;",
        );
        assert!(empty["tests"].as_array().unwrap().is_empty());
        assert!(!successful(&[empty], &[], &selected));
        assert!(!successful(&[], &[], &[]));
        let dir = tempfile::tempdir().unwrap();
        let failure = command(
            dir.path(),
            "test",
            &[
                "sh".into(),
                "-c".into(),
                "printf 'test example ... ok\ntest result: ok. 1 passed; 0 failed;\n'; exit 101"
                    .into(),
            ],
            &BTreeMap::new(),
            false,
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(failure["exit_code"], 101);
        assert!(failure["errors"].as_array().unwrap().is_empty());
        assert!(!successful(&[failure], &[], &selected));
        let timeout = command(
            dir.path(),
            "deadline",
            &["sh".into(), "-c".into(), "sleep 30 & echo $!; wait".into()],
            &BTreeMap::new(),
            false,
            Duration::from_millis(500),
        )
        .unwrap();
        assert_eq!(timeout["exit_code"], 124);
        let child = fs::read_to_string(dir.path().join("deadline.stdout.log")).unwrap();
        let pid = child.trim().parse::<u32>().unwrap();
        if let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) {
            let state = stat
                .rsplit_once(") ")
                .unwrap()
                .1
                .split_whitespace()
                .next()
                .unwrap();
            assert!(
                matches!(state, "Z" | "X"),
                "timed-out child still running: {state}"
            );
        }
    }
    #[test]
    fn evidence_requires_crypto_and_named_cases() {
        let dir = tempfile::tempdir().unwrap();
        let records = vec![json!({"name":"pebble","tests":PEBBLE})];
        let (_, errors) = evidence(dir.path(), &records, |_| panic!("no capture")).unwrap();
        assert!(!errors.is_empty());
        for name in PEBBLE {
            let case = dir.path().join(name);
            fs::create_dir(&case).unwrap();
            fs::write(
                case.join("manifest.json"),
                serde_json::to_vec(&json!({"test_name":format!("acme::pebble::{name}")})).unwrap(),
            )
            .unwrap();
            fs::write(case.join("wire.pcap"), "fixture").unwrap();
            fs::write(case.join("events.jsonl"), "").unwrap();
        }
        let (summaries, errors) = evidence(dir.path(), &records, |_| {
            Ok(json!({"errors":[],"valid_jose":0}))
        })
        .unwrap();
        assert_eq!(summaries.len(), 7);
        assert_eq!(
            errors
                .iter()
                .filter(|s| s.starts_with("JOSE not observed:"))
                .count(),
            7
        );
        let (_, errors) = evidence(dir.path(), &records, |_| {
            Ok(json!({"errors":[],"valid_jose":1,"eab_valid":1}))
        })
        .unwrap();
        assert!(errors.is_empty(), "{errors:?}");
        let (_, errors) = evidence(dir.path(), &records, |_| Err("decoder failed".into())).unwrap();
        assert!(errors.iter().any(|e| e.contains("zero relevant captures")));
        let missing = vec![json!({"name":"pebble","tests":[]})];
        let (_, errors) = evidence(dir.path(), &missing, |_| {
            Ok(json!({"errors":[],"valid_jose":1,"eab_valid":1}))
        })
        .unwrap();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("expected test did not run"))
        );
    }
    #[test]
    fn decoder_oracles() {
        let python = std::env::var("MONA_LAB_PYTHON").unwrap_or("python3".into());
        let output = Command::new(python)
            .arg(root().join("tools/analyze.py"))
            .arg("--self-test")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("Ran 4 tests"));
    }
}
