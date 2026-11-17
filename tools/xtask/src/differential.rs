//! A bounded optional cross-stack experiment; never an indistinguishability claim.
use super::{Result, check, hex, root};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
pub const VERSION: &str = "v2.10.2";
struct Group(std::process::Child);
impl Drop for Group {
    fn drop(&mut self) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(self.0.id() as i32),
            nix::sys::signal::Signal::SIGKILL,
        );
        let _ = self.0.wait();
    }
}
const ARCHIVE_SHA512: &str = "747df7ee74de188485157a383633a1a963fd9233b71fbb4a69ddcbcc589ce4e2cc82dacf5dbbe136cb51d17e14c59daeb5d9bc92487610b0f3b93680b2646546";
const BINARY_SHA256: &str = "4ef1f68c70219536b2711fd16547a79841a2dec2d6b4e56b1e3e5e9da76028e6";
pub fn fetch(directory: &Path) -> Result<()> {
    check(
        std::env::consts::OS == "linux" && std::env::consts::ARCH == "x86_64",
        "pinned reference artifact supports Linux x86_64",
    )?;
    fs::create_dir_all(directory)?;
    let archive = directory.join("caddy.tar.gz");
    check(
        !archive.exists() && !directory.join("caddy").exists(),
        "reference destination already contains an artifact",
    )?;
    let status = Command::new("curl").args(["--fail", "--location", "--show-error", "--proto", "=https", "https://github.com/caddyserver/caddy/releases/download/v2.10.2/caddy_2.10.2_linux_amd64.tar.gz", "--output"]).arg(&archive).status()?;
    check(status.success(), "reference download failed")?;
    check(
        hex(Sha512::digest(fs::read(&archive)?)) == ARCHIVE_SHA512,
        "reference archive SHA-512 mismatch",
    )?;
    let decoder = flate2::read::GzDecoder::new(fs::File::open(&archive)?);
    let mut found = false;
    for entry in tar::Archive::new(decoder).entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() == Path::new("caddy") {
            check(
                entry.header().entry_type().is_file() && !found && entry.size() < 128 * 1024 * 1024,
                "invalid reference executable entry",
            )?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join("caddy"))?;
            std::io::copy(&mut entry, &mut file)?;
            file.flush()?;
            fs::set_permissions(directory.join("caddy"), fs::Permissions::from_mode(0o700))?;
            found = true;
        }
    }
    check(found, "reference archive has no executable")?;
    validate_binary(&directory.join("caddy"))?;
    println!("reference={}", directory.join("caddy").display());
    Ok(())
}
fn validate_binary(path: &Path) -> Result<String> {
    check(
        hex(Sha256::digest(fs::read(path)?)) == BINARY_SHA256,
        "reference binary differs from pinned official Linux x86_64 artifact",
    )?;
    let output = Command::new(path).arg("version").output()?;
    let version = String::from_utf8(output.stdout)?;
    check(
        output.status.success() && version.split_whitespace().next() == Some(VERSION),
        "reference version mismatch",
    )?;
    Ok(version.trim().into())
}
fn differences(records: &[Value]) -> Vec<Value> {
    let mut result = Vec::new();
    for moon in records.iter().filter(|r| r["server"] == "moon") {
        let Some(reference) = records.iter().find(|r| {
            r["server"] == "reference"
                && r["protocol"] == moon["protocol"]
                && r["case"] == moon["case"]
                && r["repetition"] == moon["repetition"]
        }) else {
            continue;
        };
        let fields = moon
            .as_object()
            .unwrap()
            .keys()
            .chain(reference.as_object().unwrap().keys())
            .map(String::as_str)
            .filter(|key| {
                !["server", "protocol", "case", "repetition", "elapsed_micros"].contains(key)
            })
            .collect::<std::collections::BTreeSet<_>>();
        for field in fields {
            if moon.get(field) != reference.get(field) {
                let case = moon["case"].as_str().unwrap_or("");
                let expected = case == "valid_connect"
                    || field == "transport"
                    || (field == "tls"
                        && ["version", "alpn", "certificate_sha256"]
                            .into_iter()
                            .all(|key| moon[field][key] == reference[field][key]));
                let occurrences = records
                    .iter()
                    .filter(|r| {
                        r["server"] == "moon"
                            && r["protocol"] == moon["protocol"]
                            && r["case"] == moon["case"]
                            && r.get(field) == moon.get(field)
                    })
                    .count();
                result.push(json!({"protocol":moon["protocol"],"case":moon["case"],"category":field,"classification":if expected {"expected_implementation_or_configuration_difference"} else {"review_required"},"severity":if case == "valid_connect" {"informational"} else {"observable"},"reproducibility":{"same_moon_observation_count":occurrences,"total_repetitions":3,"timing":"descriptive only; no deterministic timing assertion"},"repetition":moon["repetition"],"moon":moon.get(field),"reference":reference.get(field)}));
            }
        }
    }
    result
}
pub fn run(args: &[String]) -> Result<()> {
    check(
        args.len() >= 4 && args.len().is_multiple_of(2),
        "usage: cargo xtask differential --caddy PATH --run NEW_DIR [--tcpdump PATH] [--tshark PATH]",
    )?;
    let mut options = std::collections::BTreeMap::new();
    for pair in args.as_chunks::<2>().0 {
        check(
            ["--caddy", "--run", "--tcpdump", "--tshark"].contains(&pair[0].as_str())
                && options.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
            "unknown or duplicate differential option",
        )?;
    }
    let caddy = Path::new(*options.get("--caddy").ok_or("--caddy required")?).canonicalize()?;
    let version = validate_binary(&caddy)?;
    let dir = Path::new(*options.get("--run").ok_or("--run required")?);
    check(
        dir.is_absolute() && !dir.starts_with(root()),
        "absolute new report directory outside source checkout required",
    )?;
    fs::create_dir_all(dir.parent().ok_or("report parent required")?)?;
    let parent = dir.parent().unwrap().canonicalize()?;
    check(
        !parent.starts_with(root().canonicalize()?),
        "report directory must not resolve into source checkout",
    )?;
    fs::create_dir(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let dir = dir.canonicalize()?;
    let mut command = Command::new("cargo");
    command
        .current_dir(root())
        .args([
            "test",
            "--locked",
            "-p",
            "moon-naive",
            "--lib",
            "net::tests::differential::independent_reference_matrix",
            "--",
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env("MOON_DIFF_CADDY", &caddy)
        .env("MOON_DIFF_RUN", &dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdin(Stdio::null());
    if let Some(path) = options.get("--tcpdump") {
        command.env("MOON_DIFF_TCPDUMP", path);
    }
    if let Some(path) = options.get("--tshark") {
        command.env("MOON_DIFF_TSHARK", path);
    }
    command.process_group(0);
    let mut child = Group(command.spawn()?);
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(600) {
            child.0.kill()?;
            child.0.wait()?;
            return Err("differential test exceeded 600s".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    check(
        status.success(),
        "differential test failed; no passing report is claimed",
    )?;
    let mut report: Value = serde_json::from_slice(&fs::read(dir.join("observations.json"))?)?;
    check(
        report["success"] == true && report["executed_test"] == "independent_reference_matrix",
        "missing successful current-run observations",
    )?;
    let records = report["records"].as_array().ok_or("records required")?;
    check(
        ["h1", "h2", "h3"].into_iter().all(|p| {
            records
                .iter()
                .any(|r| r["protocol"] == p && r["server"] == "reference")
        }),
        "all reference protocols must execute",
    )?;
    let observed_differences = differences(records);
    report["reference"] = json!({"name":"Caddy","version":version,"binary_sha256":BINARY_SHA256,"archive_sha512":ARCHIVE_SHA512,"source":"https://github.com/caddyserver/caddy/releases/tag/v2.10.2","tls":"same ephemeral certificate/key and CA as Moon; h1/h2/h3; TLS 1.2/1.3; no public CA"});
    report["differences"] = json!(observed_differences);
    let records = report["records"].as_array().unwrap();
    let counts = ["h1", "h2", "h3", "tls"]
        .into_iter()
        .map(|protocol| {
            (
                protocol,
                records
                    .iter()
                    .filter(|r| r["protocol"] == protocol)
                    .map(|r| r["case"].as_str().unwrap())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    report["distinct_case_counts"] = json!(counts);
    report["warning"] = json!(
        "Observed differences are measurements, not an undetectability guarantee. Expected stack differences remain fingerprintable. Unmeasured scenarios are not passing tests."
    );
    let mut markdown = format!(
        "# HTTPS differential observations\n\nReference: Caddy {VERSION}; official artifact hashes and configuration identity are in result.json.\n\n{}\n\n| Protocol | Case | Category | Classification |\n|---|---|---|---|\n",
        report["warning"].as_str().unwrap()
    );
    for diff in report["differences"].as_array().unwrap() {
        markdown.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            diff["protocol"].as_str().unwrap(),
            diff["case"].as_str().unwrap(),
            diff["category"].as_str().unwrap(),
            diff["classification"].as_str().unwrap()
        ));
    }
    markdown.push_str("\n## Unmeasured experiments\n\n");
    for case in report["unmeasured"]
        .as_array()
        .ok_or("coverage inventory required")?
    {
        markdown.push_str(&format!("- {}\n", case.as_str().unwrap()));
    }
    fs::write(dir.join("result.json"), serde_json::to_vec_pretty(&report)?)?;
    fs::write(dir.join("summary.md"), markdown)?;
    println!("RESULT={}", dir.join("result.json").display());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn equal_status_does_not_hide_wire_differences() {
        let records = vec![
            json!({"server":"moon","protocol":"h2","case":"normal","status":200,"frames":[[4,0,0]],"headers":[["x","a"]]}),
            json!({"server":"reference","protocol":"h2","case":"normal","status":200,"frames":[[4,0,6]],"headers":[["x","b"]]}),
        ];
        let d = differences(&records);
        assert_eq!(d.len(), 2);
        assert!(d.iter().any(|d| d["category"] == "frames"));
    }
    #[test]
    fn mismatching_reference_hash_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake");
        fs::write(&path, b"not caddy").unwrap();
        assert!(validate_binary(&path).is_err());
    }
}
