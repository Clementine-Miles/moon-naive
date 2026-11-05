mod audit;
mod release;
use std::{
    collections::BTreeSet,
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .into()
}
fn check(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn capture(dir: &Path, executable: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(executable)
        .args(args)
        .current_dir(dir)
        .output()?;
    check(
        out.status.success(),
        &format!(
            "{executable} {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;
    Ok(String::from_utf8(out.stdout)?)
}
fn run(dir: &Path, executable: &str, args: &[&str]) -> Result<()> {
    println!("RUN {executable} {}", args.join(" "));
    let started = Instant::now();
    let mut child = Command::new(executable)
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .spawn()?;
    loop {
        if let Some(status) = child.try_wait()? {
            return check(
                status.success(),
                &format!("{executable} {args:?}: {status}"),
            );
        }
        if started.elapsed() > Duration::from_secs(480) {
            child.kill()?;
            child.wait()?;
            return Err("command exceeded 480-second limit".into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}
fn save_report(name: &str, text: &str) -> Result<()> {
    check(!text.is_empty(), "empty report refused")?;
    let dir = root().join("reports");
    fs::create_dir_all(&dir)?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = dir.join(format!("{name}-{stamp}-{}.txt", std::process::id()));
    let temp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    fs::rename(&temp, &path)?;
    println!("report={}", path.display());
    Ok(())
}
fn audit_native() -> Result<()> {
    audit::sources()?;
    let args = vec![
        "tree",
        "--package",
        "moon-naive",
        "--locked",
        "--edges",
        "normal",
        "--prefix",
        "none",
        "--format",
        "{p}",
    ];
    let tree = capture(&root(), "cargo", &args)?;
    let mut boring = BTreeSet::new();
    let mut sys = BTreeSet::new();
    for line in tree.lines() {
        let mut fields = line.split_whitespace();
        let name = fields.next().unwrap_or("");
        let version = fields.next().unwrap_or("");
        check(
            ![
                "rustls",
                "tokio-rustls",
                "ring",
                "quinn",
                "quinn-proto",
                "hyper-rustls",
                "openssl",
                "openssl-sys",
                "aws-lc-rs",
                "aws-lc-sys",
                "libz-ng-sys",
                "libz-sys",
                "zstd-sys",
                "brotli",
                "caddy",
                "xcaddy",
                "certmagic",
                "quic-go",
            ]
            .contains(&name),
            &format!("unexpected native TLS/compression dependency: {name}"),
        )?;
        if name == "boring" {
            boring.insert(version.to_owned());
        }
        if name == "boring-sys" {
            sys.insert(version.to_owned());
        }
    }
    let expected = BTreeSet::from(["v5.2.0".to_owned()]);
    check(
        boring == expected && sys == expected,
        "native backends do not share boring/boring-sys 5.2.0",
    )?;
    save_report(
        "native-graph",
        &format!("dependency graph audit=passed\nnative compilation=not performed\n{tree}"),
    )
}
fn verify(target: Option<&str>) -> Result<()> {
    let root = root();
    audit::sources()?;
    for mut args in [
        vec![
            "fmt",
            "-p",
            "moon-naive",
            "-p",
            "moon-naive-core",
            "-p",
            "xtask",
            "--",
            "--check",
        ],
        vec![
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        vec!["build", "--package", "moon-naive", "--release", "--locked"],
    ] {
        if args[0] != "fmt"
            && let Some(target) = target
        {
            let at = args
                .iter()
                .position(|arg| *arg == "--")
                .unwrap_or(args.len());
            args.splice(at..at, ["--target", target]);
        }
        run(&root, "cargo", &args)?;
    }
    let mut output_dir = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    if !output_dir.is_absolute() {
        output_dir = root.join(output_dir);
    }
    if let Some(target) = target {
        output_dir.push(target);
    }
    let cli = output_dir.join("release/moon-naive");
    let example = private_example(&cli)?;
    let output = Command::new(&cli)
        .arg("check-config")
        .arg(&example.0)
        .current_dir(&root)
        .output()?;
    check(
        output.status.success() && output.stderr.is_empty(),
        "config check failed",
    )?;
    check(
        String::from_utf8_lossy(&output.stdout).contains("protocols=h1-website,h2,h3")
            && String::from_utf8_lossy(&output.stdout)
                .contains("acme_directory=https://dv.acme-v02.api.pki.goog/directory")
            && String::from_utf8_lossy(&output.stdout).contains("terms_accepted=false"),
        "CLI must describe the unified example without opening listeners",
    )?;
    // Exercise the actual executable on an invalid config, not just Config::parse.
    let dir = root.join("reports");
    fs::create_dir_all(&dir)?;
    let invalid = dir.join(format!(
        "invalid-config-{}-{}.toml",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    let original = fs::read_to_string(root.join("config.example.toml"))?;
    let text = format!("{original}\n[listener]\nfast_open=true\n");
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&invalid)?;
    file.write_all(text.as_bytes())?;
    drop(file);
    let denied = Command::new(&cli)
        .arg("check-config")
        .arg(&invalid)
        .output()?;
    check(
        !denied.status.success()
            && String::from_utf8_lossy(&denied.stderr).contains("unknown field"),
        "CLI must reject the retired fast_open field",
    )?;
    fs::remove_file(invalid)?;
    let missing = root
        .join("reports")
        .join(format!("missing-users-{}.toml", std::process::id()));
    check(!missing.exists(), "test missing-users path already exists")?;
    let mut config: toml::Value = toml::from_str(&original)?;
    config["proxy"].as_table_mut().unwrap().remove("users");
    config.as_table_mut().unwrap().insert(
        "credentials_file".into(),
        toml::Value::String(missing.to_string_lossy().into_owned()),
    );
    let setup = root
        .join("reports")
        .join(format!("incomplete-setup-{}.toml", std::process::id()));
    fs::write(&setup, toml::to_string(&config)?)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&setup, fs::Permissions::from_mode(0o600))?;
    let failed = Command::new(&cli).arg("serve").arg(&setup).output()?;
    fs::remove_file(setup)?;
    check(
        !failed.status.success()
            && !String::from_utf8_lossy(&failed.stderr).contains("event=server_ready"),
        "serve must reject incomplete setup before accepting traffic",
    )?;
    save_report(
        "verification",
        "native Git revision pins=passed\nworkspace fmt=passed\nclippy -D warnings=passed\nrelease server build=passed\nCLI generated private example=passed\nCLI Fast Open rejection=passed\nserve incomplete-setup rejection=passed\n24h network soak=not performed\n",
    )
}
// Test the installed CLI's embedded example without making the distributed
// template secret or changing checkout permissions. Always remove the copy.
struct PrivateExample(PathBuf);
impl Drop for PrivateExample {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn private_example(cli: &Path) -> Result<PrivateExample> {
    let dir = root().join("reports");
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!(
        "example-{}-{}.toml",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    let result = Command::new(cli)
        .args(["config", "init"])
        .arg(&path)
        .output()?;
    check(
        result.status.success(),
        "could not generate private example",
    )?;
    Ok(PrivateExample(path))
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args().skip(1).collect();
    let result = match args.as_slice() {
        [cmd] if cmd == "verify" => verify(None),
        [cmd,target] if cmd=="verify"=>verify(Some(target)),
        [cmd] if cmd == "audit-native" => audit_native(),
        [cmd, binary] if cmd == "check-elf" => release::check_elf(Path::new(binary)),
        [cmd,binary,output] if cmd=="dist"=>release::dist(Path::new(binary),Path::new(output)),
        [cmd,output] if cmd=="source"=>release::source(Path::new(output)),
        [cmd,binary] if cmd=="platform-smoke"=>release::platform_smoke(Path::new(binary),None),
        [cmd,binary,ca] if cmd=="platform-smoke"=>release::platform_smoke(Path::new(binary),Some(Path::new(ca))),
        _ => Err("usage: cargo xtask verify [target] | audit-native | check-elf <binary> | dist <binary> <output-dir> | source <output-dir> | platform-smoke <binary> [ca-bundle]".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("verification failed: {e}");
            ExitCode::FAILURE
        }
    }
}
