//! Real ACME/JWS/HTTPS/CSR/certificate issuance and authoritative DNS-01.
//! Test-only provider controls pebble-challtestsrv on loopback. No public DNS writes.
use super::lab_support;
use crate::Result;
use crate::acme::{
    self,
    certificate::Validator,
    dns::{DnsProvider, authoritative_txt},
    http::Http,
    manager::{Manager, Tick},
    persist::Lease,
};
use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

struct Process(Child);
struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[derive(Clone)]
struct TestDns {
    http: Http,
    control: String,
    dns: std::net::SocketAddr,
    fail: Arc<AtomicBool>,
    creates: Arc<AtomicUsize>,
    preparation_failures: Arc<AtomicUsize>,
    cleanups: Arc<AtomicUsize>,
    gate: Arc<tokio::sync::Semaphore>,
    started: Arc<tokio::sync::Notify>,
}
#[async_trait]
impl DnsProvider for TestDns {
    fn identity(&self) -> String {
        "pebble-loopback-test".into()
    }
    async fn prepare(&mut self, _: &mut Lease) -> Result<()> {
        if self.fail.load(Ordering::Relaxed) {
            self.preparation_failures.fetch_add(1, Ordering::Relaxed);
            return Err("injected read-only DNS preparation outage".into());
        }
        Ok(())
    }
    async fn recover(&mut self, lease: &mut Lease) -> Result<()> {
        if lease.phase == acme::persist::LeasePhase::CreateUncertain {
            // This fixture has an isolated challtestsrv and no foreign writers.
            if !authoritative_txt(self.dns, &lease.name, &lease.value).await? {
                return Err("synthetic DNS creation remains uncertain".into());
            }
            lease.phase = acme::persist::LeasePhase::Created;
        }
        Ok(())
    }
    async fn present(&mut self, lease: &mut Lease) -> Result<()> {
        self.started.notify_one();
        self.gate.acquire().await?.forget();
        self.http
            .json(
                "POST",
                &format!("{}/set-txt", self.control),
                None,
                Some(json!({"host":format!("{}.",lease.name),"value":lease.value})),
            )
            .await?;
        self.creates.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn propagated(&mut self, lease: &Lease) -> Result<bool> {
        authoritative_txt(self.dns, &lease.name, &lease.value).await
    }
    async fn cleanup(&mut self, lease: &Lease) -> Result<()> {
        self.http
            .json(
                "POST",
                &format!("{}/clear-txt", self.control),
                None,
                Some(json!({"host":format!("{}.",lease.name)})),
            )
            .await?;
        self.cleanups.fetch_add(1, Ordering::Relaxed);
        if let Some(manifest) = std::env::var_os("ACME_LAB_WORKER") {
            std::fs::write(
                PathBuf::from(manifest).with_extension("cleanup"),
                acme::now().to_string(),
            )
            .unwrap();
        }
        Ok(())
    }
}
fn patch_journal(root: &Path, edit: impl FnOnce(&mut Value)) {
    let path = std::fs::read_dir(root.join("acme"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|p| p.extension().is_some_and(|v| v == "json"))
        .unwrap();
    let mut state: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    edit(&mut state);
    std::fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
}
fn journal(root: &Path) -> Value {
    let path = std::fs::read_dir(root.join("acme"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|p| p.extension().is_some_and(|v| v == "json"))
        .unwrap();
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires PEBBLE_BIN, CHALLTESTSRV_BIN and PEBBLE_SOURCE; starts loopback-only test services"]
async fn issue_restart_renew_and_keep_certificate_during_dns_outage() {
    exercise(false, "normal").await;
}

#[tokio::test]
#[ignore = "requires PEBBLE_BIN, CHALLTESTSRV_BIN and PEBBLE_SOURCE; starts loopback-only test services"]
async fn eab_issue_restart_renew_and_recover_account_without_eab_file() {
    exercise(true, "normal").await;
}

#[tokio::test]
#[ignore = "requires the isolated Pebble laboratory"]
async fn challenge_timeout_before_ca_dns_preserves_validation() {
    exercise(false, "timeout").await;
}
#[tokio::test]
#[ignore = "requires the isolated Pebble laboratory"]
async fn challenge_sigterm_before_ca_dns_preserves_validation() {
    exercise(false, "sigterm").await;
}
#[tokio::test]
#[ignore = "requires the isolated Pebble laboratory"]
async fn challenge_crash_restart_before_ca_dns_preserves_validation() {
    exercise(false, "crash").await;
}
#[tokio::test]
#[ignore = "requires the isolated Pebble laboratory"]
async fn continuous_nonce_rejection_fails_boundedly() {
    exercise(false, "nonce100").await;
}
#[tokio::test]
#[ignore = "requires the isolated Pebble laboratory"]
async fn authorization_reuse_does_not_require_second_dns_create() {
    exercise(false, "reuse").await;
}

async fn exercise(eab: bool, scenario: &str) {
    if let Some(manifest) = std::env::var_os("ACME_LAB_WORKER") {
        worker(Path::new(&manifest)).await;
        return;
    }

    let source = PathBuf::from(std::env::var_os("PEBBLE_SOURCE").expect("PEBBLE_SOURCE"));
    let evidence = lab_support::Case::new(&format!(
        "pebble-{}-{scenario}",
        if eab { "eab" } else { "plain" }
    ));
    let barrier = evidence.path().join("barrier");
    std::fs::create_dir(&barrier).unwrap();
    let scratch = Retained(evidence.path().to_owned());
    // Hold all reservations until the processes are about to bind them.
    let reservations: Vec<_> = (0..4)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let ports: Vec<_> = reservations
        .iter()
        .map(|r| r.local_addr().unwrap().port())
        .collect();
    let (ca_port, management_port, dns_port, control_port) =
        (ports[0], ports[1], ports[2], ports[3]);
    let logs = scratch.path().join("pebble.log");
    let config = json!({"pebble":{
        "listenAddress":format!("127.0.0.1:{ca_port}"),"managementListenAddress":format!("127.0.0.1:{management_port}"),
        "certificate":source.join("test/certs/localhost/cert.pem"),"privateKey":source.join("test/certs/localhost/key.pem"),
        "httpPort":5002,"tlsPort":5001,"externalAccountBindingRequired":eab,
        "externalAccountMACKeys":{"test-kid":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"},
        "retryAfter":{"authz":1,"order":1},"profiles":{"default":{"description":"local test","validityPeriod":7776000}}
    }});
    let config_path = scratch.path().join("pebble.json");
    std::fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    drop(reservations);
    let _chall = Process(
        Command::new(std::env::var_os("CHALLTESTSRV_BIN").expect("CHALLTESTSRV_BIN"))
            .args([
                "-dns01",
                &format!("127.0.0.1:{dns_port}"),
                "-management",
                &format!("127.0.0.1:{control_port}"),
                "-http01",
                "",
                "-https01",
                "",
                "-tlsalpn01",
                "",
                "-doh",
                "",
            ])
            .stdout(std::fs::File::create(scratch.path().join("challtestsrv.stdout.log")).unwrap())
            .stderr(std::fs::File::create(scratch.path().join("challtestsrv.stderr.log")).unwrap())
            .spawn()
            .unwrap(),
    );
    // challtestsrv models recursive DNS and omits AA. Expose it through a
    // loopback authoritative test facade; production must keep requiring AA.
    let authoritative = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let authoritative_address = authoritative.local_addr().unwrap();
    let _authoritative = Task(tokio::spawn(async move {
        let backend = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        backend.connect(("127.0.0.1", dns_port)).await.unwrap();
        let mut buffer = vec![0; 65535];
        loop {
            let (n, peer) = authoritative.recv_from(&mut buffer).await.unwrap();
            backend.send(&buffer[..n]).await.unwrap();
            let n = backend.recv(&mut buffer).await.unwrap();
            let mut answer = hickory_proto::op::Message::from_vec(&buffer[..n]).unwrap();
            answer.metadata.authoritative = true;
            answer.metadata.truncation =
                std::env::var("ACME_LAB_FORCE_DNS_TCP").is_ok_and(|v| v == "1");
            authoritative
                .send_to(&answer.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    }));
    let authority_tcp = tokio::net::TcpListener::bind(authoritative_address)
        .await
        .unwrap();
    let trace = evidence.clone();
    let _authority_tcp = Task(tokio::spawn(async move {
        loop {
            let (mut client, _) = authority_tcp.accept().await.unwrap();
            let trace = trace.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut backend = tokio::net::TcpStream::connect(("127.0.0.1", dns_port))
                    .await
                    .unwrap();
                let n = client.read_u16().await.unwrap();
                let mut query = vec![0; n as usize];
                client.read_exact(&mut query).await.unwrap();
                backend.write_u16(n).await.unwrap();
                backend.write_all(&query).await.unwrap();
                let n = backend.read_u16().await.unwrap();
                let mut answer = vec![0; n as usize];
                backend.read_exact(&mut answer).await.unwrap();
                let mut answer = hickory_proto::op::Message::from_vec(&answer).unwrap();
                answer.metadata.authoritative = true;
                answer.metadata.truncation = false;
                let answer = answer.to_vec().unwrap();
                client.write_u16(answer.len() as u16).await.unwrap();
                client.write_all(&answer).await.unwrap();
                trace.event("authority_tcp", json!({"bytes":answer.len()}));
            });
        }
    }));
    let mut capture_ports = ports.clone();
    capture_ports.push(authoritative_address.port());
    let _capture = evidence.capture(&capture_ports);
    let _pebble = Process(
        Command::new(std::env::var_os("PEBBLE_BIN").expect("PEBBLE_BIN"))
            .arg("-config")
            .arg(config_path)
            .args(["-dnsserver", &authoritative_address.to_string()])
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env(
                "PEBBLE_WFE_NONCEREJECT",
                if scenario == "nonce100" {
                    "100".into()
                } else {
                    std::env::var("ACME_LAB_NONCE_REJECT").unwrap_or("0".into())
                },
            )
            .env(
                "PEBBLE_AUTHZREUSE",
                if scenario == "reuse" {
                    "100".into()
                } else {
                    std::env::var("ACME_LAB_AUTHZ_REUSE").unwrap_or("0".into())
                },
            )
            .env("PEBBLE_LAB_KEYLOGFILE", scratch.path().join("tls.keys"))
            .env(
                "PEBBLE_LAB_STALL_ORDER",
                if scenario == "timeout" { "1" } else { "0" },
            )
            .env(
                "PEBBLE_LAB_BARRIER_DIR",
                if matches!(scenario, "timeout" | "sigterm" | "crash") {
                    barrier.clone()
                } else {
                    PathBuf::from("/nonexistent-acme-lab-barrier")
                },
            )
            .current_dir(&source)
            .stdout(std::fs::File::create(&logs).unwrap())
            .stderr(std::fs::File::create(scratch.path().join("pebble.stderr.log")).unwrap())
            .spawn()
            .unwrap(),
    );
    evidence.event("processes",json!({"pebble_pid":_pebble.0.id(),"challtestsrv_pid":_chall.0.id(),"authority":authoritative_address.to_string(),"ports":ports}));
    let http = Http::new(
        Some(&source.join("test/certs/pebble.minica.pem")),
        Duration::from_secs(10),
    )
    .unwrap()
    .with_loopback_http();
    let root_uri = format!("https://localhost:{management_port}/roots/0");
    let roots = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let request = http::Request::builder()
                .uri(&root_uri)
                .body(Full::new(Bytes::new()))
                .unwrap();
            if let Ok(response) = http.request(request).await {
                break response.into_body().collect().await.unwrap().to_bytes();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("Pebble readiness");
    let root_path = scratch.path().join("issued-root.pem");
    std::fs::write(&root_path, &roots).unwrap();
    let mut config =
        moon_naive_core::config::Config::parse(include_str!("../../config.example.toml")).unwrap();
    config.domain = "acme.example.test".into();
    config.proxy.users.clear();
    config.acme.dns_zone = Some("example.test".into());
    config.acme.eab = None;
    config.acme.issuer = moon_naive_core::config::Issuer::Letsencrypt;
    config.state_dir = scratch.path().join("state");
    config.acme.accept_terms = true;
    config.acme.directory_url = Some(format!("https://localhost:{ca_port}/dir"));
    config.acme.certificate_ca_file = Some(root_path.clone());
    config.acme.operation_timeout_secs = 60;
    config.acme.retry_initial_secs = 2;
    config.acme.poll_interval_secs = 1;
    if eab {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let path = scratch.path().join("eab.toml");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(
            b"key_id = 'test-kid'\nb64_mac_key = 'QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI'\n",
        )
        .unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        config.acme.issuer = moon_naive_core::config::Issuer::Google;
        config.acme.eab_credentials_file = Some(path);
    }
    let provider = TestDns {
        http: http.clone(),
        control: format!("http://127.0.0.1:{control_port}"),
        dns: authoritative_address,
        fail: Arc::new(AtomicBool::new(false)),
        creates: Arc::new(AtomicUsize::new(0)),
        preparation_failures: Arc::new(AtomicUsize::new(0)),
        cleanups: Arc::new(AtomicUsize::new(0)),
        gate: Arc::new(tokio::sync::Semaphore::new(0)),
        started: Arc::new(tokio::sync::Notify::new()),
    };
    // The release lifecycle must bootstrap before it binds, not require a
    // separate ACME process or a preinstalled CURRENT.
    use std::os::unix::fs::PermissionsExt;
    config.credentials_file = scratch.path().join("users.toml");
    std::fs::write(
        &config.credentials_file,
        b"[[users]]\nusername='alice'\npassword='a-long-lifecycle-test-password'\n",
    )
    .unwrap();
    std::fs::set_permissions(
        &config.credentials_file,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    config.website.upstreams.clear();
    config.website.routes.clear();
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        loop {
            let (socket, _) = origin.accept().await.unwrap();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(|_| async {
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                        Bytes::from_static(b"automatic lifecycle"),
                    )))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    config
        .website
        .upstreams
        .push(moon_naive_core::website::Upstream {
            name: "fixture".into(),
            origins: vec![format!("http://{origin_address}")],
            tls_server_name: None,
            host_header: None,
            ca_file: None,
            http2: false,
        });
    config.website.routes.push(moon_naive_core::website::Route {
        path_prefix: "/".into(),
        upstream: "fixture".into(),
        strip_prefix: false,
    });
    let _origin_task = origin_task;
    config.limits.graceful_timeout_secs = 1;
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    config.listener.tcp = tcp.local_addr().unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    config.listener.udp = udp.local_addr().unwrap();
    drop((tcp, udp));
    config.acme.directory_ca_file = Some(source.join("test/certs/pebble.minica.pem"));
    if scenario == "nonce100" {
        let start = std::time::Instant::now();
        provider.gate.add_permits(100);
        let mut manager = Manager::open(&config, provider, http.clone()).unwrap();
        let result = manager.tick().await;
        evidence.event(
            "continuous_nonce_result",
            json!({"elapsed_ms":start.elapsed().as_millis(),"result":format!("{result:?}")}),
        );
        evidence.journal(&config.state_dir, "after-bounded-rejection");
        assert_eq!(result.unwrap(), Tick::RetryScheduled);
        assert!(start.elapsed() < Duration::from_secs(10));
        return;
    }
    if matches!(scenario, "timeout" | "sigterm" | "crash") {
        barrier_experiment(
            &config,
            &provider,
            &http,
            &evidence,
            &barrier,
            scenario,
            origin_address,
        )
        .await;
        return;
    }
    let config = Arc::new(config);
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let service = tokio::spawn(crate::runtime::serve_with_provider(
        config.clone(),
        provider.clone(),
        http.clone(),
        shutdown,
    ));
    tokio::time::timeout(Duration::from_secs(10), provider.started.notified())
        .await
        .unwrap();
    assert!(
        tokio::net::TcpStream::connect(config.listener.tcp)
            .await
            .is_err()
    );
    drop(std::net::UdpSocket::bind(config.listener.udp).unwrap());
    provider.gate.add_permits(100);
    let socket = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(socket) = tokio::net::TcpStream::connect(config.listener.tcp).await {
                break socket;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let mut connector = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls()).unwrap();
    connector.set_ca_file(&root_path).unwrap();
    connector.set_alpn_protos(b"\x02h2").unwrap();
    let tls = tokio_boring::connect(
        connector.build().configure().unwrap(),
        &config.domain,
        socket,
    )
    .await
    .unwrap();
    let (mut client, connection) = h2::client::handshake(tls).await.unwrap();
    let connection = Task(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let (response, _) = client
        .send_request(
            http::Request::builder()
                .uri(format!("https://{}/", config.domain))
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let mut payload = Vec::new();
    while let Some(bytes) = body.data().await {
        let bytes = bytes.unwrap();
        body.flow_control().release_capacity(bytes.len()).unwrap();
        payload.extend(bytes);
    }
    assert_eq!(payload, b"automatic lifecycle");
    drop((client, connection));
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), service)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut manager = Manager::open(&config, provider.clone(), http.clone()).unwrap();
    let first = manager.tick().await.unwrap();
    assert_eq!(
        first,
        Tick::Idle,
        "Pebble log: {}",
        std::fs::read_to_string(&logs).unwrap()
    );
    assert!(manager.ready());
    assert_eq!(provider.creates.load(Ordering::Relaxed), 1);
    let old = manager.current(acme::now()).unwrap().clone();
    let pointer = config.state_dir.join("certificates/CURRENT");
    let generation = std::fs::read(&pointer).unwrap();
    let first_state = evidence.journal(&config.state_dir, "initial-issued");
    assert!(first_state["leases"].as_array().unwrap().is_empty());
    assert!(first_state["ari_check_at"].as_u64().unwrap() > 0);
    assert!(
        first_state["ari_window"].is_array(),
        "Pebble ARI window must be consumed"
    );
    let account = first_state["account"].clone();
    let account_id = first_state["account_id"].clone();
    if eab {
        assert_eq!(account["id"], account_id);
        assert!(
            account_id
                .as_str()
                .unwrap()
                .starts_with("https://localhost:")
        );
        // Successful registration consumes EAB. Restarts and renewals must use
        // the saved account even if the bootstrap secret is no longer present.
        std::fs::remove_file(config.acme.eab_credentials_file.as_ref().unwrap()).unwrap();
    }
    let original_key = old.material().key_pem.clone();
    // SAN, key, chain and validity failures must not reach the disk store.
    let wrong_domain = Validator::new("other.example.test", Some(&root_path)).unwrap();
    assert!(
        wrong_domain
            .verify(old.material().clone(), acme::now())
            .is_err()
    );
    let mut wrong_key = old.material().clone();
    wrong_key.key_pem = acme::certificate::csr(&config.domain)
        .unwrap()
        .0
        .into_bytes();
    let validator = Validator::new(&config.domain, Some(&root_path)).unwrap();
    assert!(validator.verify(wrong_key, acme::now()).is_err());
    assert!(
        validator
            .verify(old.material().clone(), old.lifetime().not_after)
            .is_err()
    );
    assert!(
        Validator::new(&config.domain, None)
            .unwrap()
            .verify(old.material().clone(), acme::now())
            .is_err()
    );
    drop(manager);
    let mut manager = Manager::open(&config, provider.clone(), http.clone()).unwrap();
    assert!(manager.ready());
    assert_eq!(manager.tick().await.unwrap(), Tick::Idle);
    assert_eq!(
        journal(&config.state_dir)["ari_selected"],
        first_state["ari_selected"]
    );
    assert_eq!(provider.creates.load(Ordering::Relaxed), 1);
    drop(manager);
    patch_journal(&config.state_dir, |state| {
        state["renew_at"] = json!(acme::now() - 1);
        state["next_attempt"] = json!(0);
    });
    provider.fail.store(true, Ordering::Relaxed);
    if scenario == "reuse" {
        let mut manager = Manager::open(&config, provider.clone(), http.clone()).unwrap();
        assert_eq!(
            manager.tick().await.unwrap(),
            Tick::Installed,
            "valid reused authorization needs no fresh DNS write, even during a provider outage"
        );
        assert_eq!(provider.creates.load(Ordering::Relaxed), 1);
        assert_ne!(std::fs::read(&pointer).unwrap(), generation);
        evidence.journal(&config.state_dir, "renewed-with-reused-authorization");
        return;
    }
    let mut manager = Manager::open(&config, provider.clone(), http.clone()).unwrap();
    let renewal = manager.tick().await.unwrap();
    if renewal == Tick::Installed {
        // An explicitly supplied, unpatched Pebble can reuse at 0% (upstream
        // off-by-one). The pinned lab patch removes that nondeterminism; required
        // verification still fails if this target outage was skipped.
        assert!(manager.ready());
        assert_eq!(provider.creates.load(Ordering::Relaxed), 1);
        assert_ne!(std::fs::read(&pointer).unwrap(), generation);
        evidence.event("renewal_reused_authorization",json!({"configured_reuse":std::env::var("ACME_LAB_AUTHZ_REUSE").unwrap_or("0".into()),"outage_was_not_exercised":true}));
        evidence.journal(&config.state_dir, "renewed-reused-authorization");
        drop(manager);
        if eab {
            eab_recovery(&config, &provider, http, &account_id, &evidence).await;
        }
        return;
    }
    assert_eq!(renewal, Tick::RetryScheduled);
    assert_eq!(
        provider.preparation_failures.load(Ordering::Relaxed),
        1,
        "outage must reach the intended read-only phase"
    );
    assert_eq!(
        journal(&config.state_dir)["leases"][0]["phase"],
        "Preparing"
    );
    assert!(manager.ready());
    assert_eq!(std::fs::read(&pointer).unwrap(), generation);
    let retry = manager.next_attempt();
    assert!(retry > acme::now());
    let pending = journal(&config.state_dir)["order"].clone();
    assert!(!pending.is_null());
    drop(manager);
    let mut manager = Manager::open(&config, provider.clone(), http.clone()).unwrap();
    assert_eq!(manager.next_attempt(), retry);
    assert_eq!(manager.tick().await.unwrap(), Tick::Idle);
    drop(manager);
    patch_journal(&config.state_dir, |state| state["next_attempt"] = json!(0));
    provider.fail.store(false, Ordering::Relaxed);
    let mut manager = Manager::open(&config, provider.clone(), http.clone()).unwrap();
    let prior = manager.current(acme::now()).unwrap().clone();
    assert_eq!(
        manager.tick().await.unwrap(),
        Tick::Installed,
        "Pebble log: {}",
        std::fs::read_to_string(&logs).unwrap()
    );
    assert_ne!(std::fs::read(&pointer).unwrap(), generation);
    assert!(manager.ready());
    assert_ne!(
        prior.material().key_pem,
        manager.current(acme::now()).unwrap().material().key_pem
    );
    assert_eq!(prior.material().key_pem, original_key);
    assert_eq!(journal(&config.state_dir)["account"], account);
    assert_eq!(journal(&config.state_dir)["account_id"], account_id);
    assert_eq!(old.material().key_pem, original_key); // A copied verified bundle remains valid.
    assert!(
        journal(&config.state_dir)["leases"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!((1..=2).contains(&provider.creates.load(Ordering::Relaxed)));
    assert!(provider.cleanups.load(Ordering::Relaxed) >= 1);
    evidence.journal(&config.state_dir, "renewed");
    drop(manager);
    // Simulate a crash after durable CURRENT installation but before clearing
    // the old order journal. Recovery identifies the matching private key.
    patch_journal(&config.state_dir, |state| {
        state["order"] = pending;
        state["next_attempt"] = json!(u64::MAX);
    });
    let mut recovered = Manager::open(&config, provider.clone(), http.clone()).unwrap();
    assert!(journal(&config.state_dir)["order"].is_null());
    assert_eq!(recovered.next_attempt(), 0);
    assert_eq!(recovered.tick().await.unwrap(), Tick::Idle);
    assert!((1..=2).contains(&provider.creates.load(Ordering::Relaxed)));
    if eab {
        drop(recovered);
        eab_recovery(&config, &provider, http, &account_id, &evidence).await;
    }
    let status_config = scratch.path().join("status.toml");
    let mut doc: toml::Value = toml::from_str(include_str!("../../config.example.toml")).unwrap();
    doc["domain"] = config.domain.clone().into();
    doc.as_table_mut().unwrap().insert(
        "state_dir".into(),
        config.state_dir.to_str().unwrap().into(),
    );
    doc["acme"]["dns_zone"] = "example.test".into();
    doc["acme"].as_table_mut().unwrap().insert(
        "certificate_ca_file".into(),
        root_path.to_str().unwrap().into(),
    );
    std::fs::write(&status_config, toml::to_string(&doc).unwrap()).unwrap();
    std::fs::set_permissions(&status_config, std::fs::Permissions::from_mode(0o600)).unwrap();
    crate::cli::run(&[
        "acme".into(),
        "status".into(),
        status_config.to_str().unwrap().into(),
    ])
    .await
    .unwrap();
    let blocked = crate::cli::run(&[
        "acme".into(),
        "once".into(),
        status_config.to_str().unwrap().into(),
    ])
    .await;
    assert!(blocked.unwrap_err().to_string().contains("accept_terms"));
    println!(
        "real Pebble DNS-01 issue/restart/renew=passed; EAB={eab}; SAN/key/expiry/trust rejection=passed; DNS outage preserves CURRENT=passed; persistent backoff/account/order recovery=passed"
    );
}

struct Retained(PathBuf);
impl Retained {
    fn path(&self) -> &Path {
        &self.0
    }
}

// A separate test process runs the real control thread and OS SIGTERM path.
// This constructor has no production configuration or provider-endpoint switch.
async fn worker(path: &Path) {
    let options: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut config =
        moon_naive_core::config::Config::parse(include_str!("../../config.example.toml")).unwrap();
    config.domain = "acme.example.test".into();
    config.proxy.users.clear();
    config.state_dir = options["state"].as_str().unwrap().into();
    config.credentials_file = options["credentials"].as_str().unwrap().into();
    config.acme.accept_terms = true;
    config.acme.eab = None;
    config.acme.issuer = moon_naive_core::config::Issuer::Letsencrypt;
    config.acme.dns_zone = Some("example.test".into());
    config.acme.directory_url = Some(options["directory"].as_str().unwrap().into());
    config.acme.directory_ca_file = Some(options["directory_ca"].as_str().unwrap().into());
    config.acme.certificate_ca_file = Some(options["certificate_ca"].as_str().unwrap().into());
    config.acme.operation_timeout_secs = 30;
    config.acme.poll_interval_secs = 1;
    config.acme.retry_initial_secs = 2;
    config.acme.retry_max_secs = 4;
    config.limits.graceful_timeout_secs = 1;
    config.listener.tcp = options["tcp"].as_str().unwrap().parse().unwrap();
    config.listener.udp = options["udp"].as_str().unwrap().parse().unwrap();
    config.website.upstreams = vec![moon_naive_core::website::Upstream {
        name: "fixture".into(),
        origins: vec![format!("http://{}", options["origin"].as_str().unwrap())],
        tls_server_name: None,
        host_header: None,
        ca_file: None,
        http2: false,
    }];
    config.website.routes = vec![moon_naive_core::website::Route {
        path_prefix: "/".into(),
        upstream: "fixture".into(),
        strip_prefix: false,
    }];
    let http = Http::new(
        config.acme.directory_ca_file.as_deref(),
        Duration::from_secs(if options["scenario"] == "timeout" {
            45
        } else {
            10
        }),
    )
    .unwrap()
    .with_loopback_http();
    let provider = TestDns {
        http: http.clone(),
        control: options["control"].as_str().unwrap().into(),
        dns: options["dns"].as_str().unwrap().parse().unwrap(),
        fail: Arc::new(AtomicBool::new(false)),
        creates: Arc::new(AtomicUsize::new(0)),
        preparation_failures: Arc::new(AtomicUsize::new(0)),
        cleanups: Arc::new(AtomicUsize::new(0)),
        gate: Arc::new(tokio::sync::Semaphore::new(100)),
        started: Arc::new(tokio::sync::Notify::new()),
    };
    let (stop, rx) = tokio::sync::watch::channel(false);
    let signal = tokio::spawn(async move {
        let mut signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        signal.recv().await;
        stop.send(true).unwrap();
    });
    let result = crate::runtime::serve_with_provider(Arc::new(config), provider, http, rx).await;
    eprintln!("LAB_WORKER_RESULT={result:?}");
    signal.abort();
    result.unwrap();
}
async fn barrier_experiment(
    config: &moon_naive_core::config::Config,
    provider: &TestDns,
    http: &Http,
    case: &lab_support::Case,
    barrier: &Path,
    scenario: &str,
    origin: std::net::SocketAddr,
) {
    let manifest = case.path().join("worker.json");
    case.write("worker.json",&json!({"scenario":scenario,"state":config.state_dir,"credentials":config.credentials_file,"directory":config.acme.directory_url,"directory_ca":config.acme.directory_ca_file,"certificate_ca":config.acme.certificate_ca_file,"tcp":config.listener.tcp.to_string(),"udp":config.listener.udp.to_string(),"origin":origin.to_string(),"control":provider.control,"dns":provider.dns.to_string()}));
    let name = match scenario {
        "timeout" => "challenge_timeout_before_ca_dns_preserves_validation",
        "sigterm" => "challenge_sigterm_before_ca_dns_preserves_validation",
        _ => "challenge_crash_restart_before_ca_dns_preserves_validation",
    };
    let spawn = |suffix: &str| {
        Process(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!("acme::pebble::{name}"),
                    "--ignored",
                    "--nocapture",
                ])
                .env("ACME_LAB_WORKER", &manifest)
                .stdout(
                    std::fs::File::create(case.path().join(format!("worker-{suffix}.stdout.log")))
                        .unwrap(),
                )
                .stderr(
                    std::fs::File::create(case.path().join(format!("worker-{suffix}.stderr.log")))
                        .unwrap(),
                )
                .spawn()
                .unwrap(),
        )
    };
    let mut process = spawn("initial");
    case.event(
        "worker_started",
        json!({"pid":process.0.id(),"scenario":scenario}),
    );
    tokio::time::timeout(Duration::from_secs(15), async {
        while !barrier.join("entered").exists() {
            assert!(process.0.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let before = case.journal(&config.state_dir, "challenge-acked-before-authority");
    assert_eq!(before["leases"].as_array().unwrap().len(), 1);
    case.event(
        "validation_barrier_entered",
        json!({"time":std::fs::read_to_string(barrier.join("entered")).unwrap()}),
    );
    let order_url = before["order"]["url"].as_str().unwrap().to_owned();
    if scenario == "timeout" {
        tokio::time::timeout(Duration::from_secs(38), async {
            loop {
                let j = journal(&config.state_dir);
                if j["failures"].as_u64().unwrap() > 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
    } else {
        let signal = if scenario == "crash" {
            "-KILL"
        } else {
            "-TERM"
        };
        assert!(
            Command::new("kill")
                .args([signal, &process.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        tokio::time::timeout(Duration::from_secs(10), async {
            while process.0.try_wait().unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        case.event(
            "worker_exited",
            json!({"signal":signal,"status":format!("{:?}",process.0.try_wait().unwrap())}),
        );
        if scenario == "crash" {
            case.journal(&config.state_dir, "after-crash-before-restart");
            process = spawn("restart");
            case.event("worker_restarted", json!({"pid":process.0.id()}));
            // Observe restored durable state, not a cleanup that must not happen.
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    assert!(process.0.try_wait().unwrap().is_none());
                    let j = journal(&config.state_dir);
                    if j["account_key"] == before["account_key"]
                        && j["order"]["url"] == before["order"]["url"]
                        && std::fs::read_to_string(case.path().join("worker-restart.stderr.log"))
                            .unwrap()
                            .contains("control_restored")
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
        }
    }
    let canceled = case.journal(&config.state_dir, "after-cancel-before-dns");
    // Query the original order with its durable account key; no new order is created by the observer.
    let account =
        instant_acme::Account::builder(Box::new(http.clone()), &crate::acme::crypto::CRYPTO)
            .unwrap()
            .from_parts(
                before["account_id"]
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| before["account"]["id"].as_str().map(str::to_owned))
                    .unwrap(),
                rustls_pki_types::PrivatePkcs8KeyDer::from(
                    serde_json::from_value::<Vec<u8>>(before["account_key"].clone()).unwrap(),
                ),
                config.acme.directory().to_owned(),
            )
            .await
            .unwrap();
    let deleted_before_validation = manifest.with_extension("cleanup").exists();
    assert!(
        !deleted_before_validation,
        "no cleanup while CA validation is blocked"
    );
    assert_eq!(canceled["leases"].as_array().unwrap().len(), 1);
    assert_eq!(canceled["order"]["url"], before["order"]["url"]);
    case.event(
        "validation_retained_before_release",
        json!({"lease_phase":canceled["leases"][0]["phase"]}),
    );
    std::fs::write(barrier.join("release"), b"release").unwrap();
    case.event(
        "validation_barrier_released",
        json!({"leases_remaining":canceled["leases"].as_array().unwrap().len(),"dns_deleted_before_ca_query":deleted_before_validation}),
    );
    let mut order = account.order(order_url.clone()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let status = order.refresh().await.unwrap().status;
            if status != instant_acme::OrderStatus::Pending {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let status = order.state().status;
    assert!(matches!(
        status,
        instant_acme::OrderStatus::Ready
            | instant_acme::OrderStatus::Processing
            | instant_acme::OrderStatus::Valid
    ));
    if process.0.try_wait().unwrap().is_some() {
        let mut manager = Manager::open(config, provider.clone(), http.clone()).unwrap();
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                manager.cleanup().await.unwrap();
                if journal(&config.state_dir)["leases"]
                    .as_array()
                    .unwrap()
                    .is_empty()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    } else {
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                // Provider completion precedes the Manager's durable journal rewrite.
                if manifest.with_extension("cleanup").exists()
                    && journal(&config.state_dir)["leases"]
                        .as_array()
                        .unwrap()
                        .is_empty()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }
    assert!(
        journal(&config.state_dir)["leases"]
            .as_array()
            .unwrap()
            .is_empty(),
        "finished validation must eventually release DNS ownership"
    );
    case.event("original_order_after_authority",json!({"url":order_url,"status":format!("{status:?}"),"state":format!("{:?}",order.state())}));
    if process.0.try_wait().unwrap().is_none() {
        let _ = Command::new("kill")
            .args(["-TERM", &process.0.id().to_string()])
            .status();
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        !deleted_before_validation,
        "DNS cleanup preceded the acknowledged CA validation; order={status:?}"
    );
    assert_ne!(
        status,
        instant_acme::OrderStatus::Invalid,
        "cleanup removed DNS before the CA performed its acknowledged validation"
    );
}

async fn eab_recovery(
    config: &moon_naive_core::config::Config,
    provider: &TestDns,
    http: Http,
    account_id: &Value,
    evidence: &lab_support::Case,
) {
    // Restore the old EAB journal format (ID + key, no serialized credentials)
    // after the one-time EAB credential file has been removed.
    patch_journal(&config.state_dir, |state| {
        state["account"] = Value::Null;
        state["ari_check_at"] = json!(0);
        state["next_attempt"] = json!(0);
    });
    let mut recovered = Manager::open(config, provider.clone(), http.clone()).unwrap();
    assert_eq!(recovered.tick().await.unwrap(), Tick::Idle);
    assert_eq!(&journal(&config.state_dir)["account_id"], account_id);
    assert!((1..=2).contains(&provider.creates.load(Ordering::Relaxed)));
    drop(recovered);
    // Model registration's response/persistence gap: the CA knows the key,
    // but the local journal has not saved its account URL. No EAB remains.
    patch_journal(&config.state_dir, |state| {
        state["account"] = Value::Null;
        state["account_id"] = Value::Null;
        state["ari_check_at"] = json!(0);
        state["next_attempt"] = json!(0);
    });
    let mut recovered = Manager::open(config, provider.clone(), http).unwrap();
    assert_eq!(recovered.tick().await.unwrap(), Tick::Idle);
    assert_eq!(&journal(&config.state_dir)["account"]["id"], account_id);
    assert!((1..=2).contains(&provider.creates.load(Ordering::Relaxed)));
    evidence.journal(&config.state_dir, "eab-account-recovery");
}
