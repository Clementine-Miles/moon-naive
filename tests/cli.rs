use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
const BINARY: &str = env!("CARGO_BIN_EXE_moon-naive");
fn command(args: &[&str]) -> std::process::Output {
    Command::new(BINARY).args(args).output().unwrap()
}

#[test]
fn release_cli_checks_real_arguments_and_never_echoes_config_secrets() {
    for argument in ["--help", "--version", "status"] {
        assert!(command(&[argument]).status.success());
    }
    let version = command(&["--version"]);
    assert!(
        String::from_utf8_lossy(&version.stdout).starts_with(concat!(
            "moon-naive ",
            env!("CARGO_PKG_VERSION"),
            " "
        ))
    );
    let status = command(&["status"]);
    let status = String::from_utf8(status.stdout).unwrap();
    assert!(status.contains("cpu_dispatch=runtime\n"));
    assert!(status.contains("header_scan=memchr-runtime\n"));
    #[cfg(target_arch = "x86_64")]
    assert!(status.contains(&format!(
        "cpu_avx2={}\n",
        std::arch::is_x86_feature_detected!("avx2")
    )));
    let temporary = tempfile::tempdir().unwrap();
    let config = temporary.path().join("config.toml");
    assert!(
        command(&["config", "init", config.to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let original = fs::read(&config).unwrap();
    assert_eq!(original, include_bytes!("../config.example.toml"));
    assert!(
        !command(&["config", "init", config.to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(fs::read(&config).unwrap(), original);
    let link = temporary.path().join("link.toml");
    std::os::unix::fs::symlink(&config, &link).unwrap();
    assert!(
        !command(&["config", "init", link.to_str().unwrap()])
            .status
            .success()
    );
    let result = command(&["check-config", config.to_str().unwrap()]);
    assert!(result.status.success());
    assert_eq!(
        String::from_utf8(result.stdout).unwrap(),
        "configuration valid (structure/policy only)\nprotocols=h1-website,h2,h3\nacme_directory=https://dv.acme-v02.api.pki.goog/directory\nterms_accepted=false\nexternal_secret_files=not read\nlisteners=not opened\n"
    );
    // The production example is parseable, but cannot start ACME without consent.
    let denied = command(&["acme", "once", config.to_str().unwrap()]);
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("accept_terms"));
    fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        !command(&["check-config", config.to_str().unwrap()])
            .status
            .success()
    );
    let path = temporary.path().join("bad.toml");
    fs::write(&path, "password = 'do-not-echo-this-secret'\n").unwrap();
    let result = command(&["check-config", path.to_str().unwrap()]);
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("do-not-echo-this-secret"));
}

#[test]
fn serve_sigterm_during_first_issuance_exits_cleanly_without_opening_listeners() {
    let temporary = tempfile::tempdir().unwrap();
    let ca = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    ca.set_nonblocking(true).unwrap();
    let address = ca.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_address = tcp.local_addr().unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_address = udp.local_addr().unwrap();
    drop((tcp, udp));
    let mut doc: toml::Value = toml::from_str(include_str!("../config.example.toml")).unwrap();
    doc.as_table_mut().unwrap().insert(
        "state_dir".into(),
        temporary.path().join("state").to_str().unwrap().into(),
    );
    doc.as_table_mut()
        .unwrap()
        .insert("listener".into(), toml::Value::Table(Default::default()));
    doc["listener"]
        .as_table_mut()
        .unwrap()
        .insert("tcp".into(), tcp_address.to_string().into());
    doc["listener"]
        .as_table_mut()
        .unwrap()
        .insert("udp".into(), udp_address.to_string().into());
    doc["acme"]["accept_terms"] = true.into();
    doc["acme"].as_table_mut().unwrap().insert(
        "directory_url".into(),
        format!("https://{address}/dir").into(),
    );
    let path = temporary.path().join("config.toml");
    fs::write(&path, toml::to_string(&doc).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut child = Command::new(BINARY)
        .arg("serve")
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let held = loop {
        if let Ok((socket, _)) = ca.accept() {
            break socket;
        }
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            panic!(
                "serve stopped before local CA connect: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("server did not reach the loopback CA");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // The TLS endpoint deliberately stalls. No public service may start yet.
    drop(std::net::TcpListener::bind(tcp_address).unwrap());
    drop(std::net::UdpSocket::bind(udp_address).unwrap());
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("SIGTERM cleanup deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    drop(held);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("event=certificate_wait"));
    assert!(stderr.contains("event=server_stopped clean=true"));
    assert!(!stderr.contains("event=server_ready"));
    assert!(!stderr.contains("local-test-token"));
}
