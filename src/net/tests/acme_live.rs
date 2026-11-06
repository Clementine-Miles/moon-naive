//! Actual serve/control-thread/Manager renewal; observation is test-only.
use super::*;
use crate::acme::{
    lab::{Environment, Mode},
    lab_support::Case,
};
use serde_json::json;

async fn observed_h2(address: std::net::SocketAddr, ca: &std::path::Path, case: &Case) -> X509 {
    use std::io::Write;
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(ca).unwrap();
    connector.set_alpn_protos(b"\x02h2").unwrap();
    let keys = case.keylog();
    connector.set_keylog_callback(move |_, line| {
        let mut file = keys.lock().unwrap();
        writeln!(file, "{line}").unwrap();
        file.flush().unwrap();
    });
    let stream = tokio_boring::connect(
        connector.build().configure().unwrap(),
        "proxy.example.test",
        TcpStream::connect(address).await.unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        stream.ssl().selected_alpn_protocol(),
        Some(b"h2".as_slice())
    );
    stream.ssl().peer_certificate().unwrap()
}
fn fingerprint(cert: &X509) -> String {
    cert.digest(MessageDigest::sha256())
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn pointers(config: &Config) -> (String, String) {
    let root = config.state_dir.join("certificates");
    (
        std::fs::read_to_string(root.join("CURRENT")).unwrap(),
        std::fs::read_to_string(root.join("TLS-LOADED")).unwrap(),
    )
}
async fn record_handshakes(config: &Config, ca: &std::path::Path, case: &Case) -> Vec<u8> {
    let h2 = observed_h2(config.listener.tcp, ca, case).await;
    let mut h3 =
        QClient::initial_with_keylog(config.listener.udp, ca, Some(&case.path().join("h3.keys")))
            .await;
    tokio::time::timeout(Duration::from_secs(4), async {
        while h3.h3.is_none() {
            h3.step().await;
        }
    })
    .await
    .unwrap();
    let leaf = X509::from_der(h3.conn.peer_cert().unwrap()).unwrap();
    let (current, loaded) = pointers(config);
    case.event("active_generation", json!({"CURRENT":current,"TLS_LOADED":loaded,"h2_serial":serial(&h2),"h3_serial":serial(&leaf),"h2_sha256":fingerprint(&h2),"h3_sha256":fingerprint(&leaf)}));
    assert_eq!(fingerprint(&h2), fingerprint(&leaf));
    assert!(loaded.contains(&format!("loaded_generation={}", current.trim())));
    let result = serial(&h2);
    let _ = h3.conn.close(true, 0x100, b"");
    h3.step().await;
    result
}
async fn live(outer: bool) {
    let env = Environment::start(
        if outer {
            "live-renew-outer"
        } else {
            "live-renew"
        },
        Mode::Normal,
    )
    .await;
    env.state.lock().unwrap().domain = "proxy.example.test".into();
    let mut fixture = fixture();
    let config = Arc::get_mut(&mut fixture.config).unwrap();
    let acme = env.config();
    config.acme = acme.acme;
    config.state_dir = env.case.path().join("live-state");
    config.limits.idle_timeout_secs = 60;
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    config.listener.tcp = tcp.local_addr().unwrap();
    config.listener.udp = udp.local_addr().unwrap();
    drop((tcp, udp));
    if outer {
        let (cert, key) = env.outer(5);
        config.ech = Some(moon_naive_core::config::Ech {
            public_name: "public.example.test".into(),
            certificate_file: cert,
            private_key_file: key,
            keys_file: env.case.path().join("ech.toml"),
        });
        tls::ech_command("init", config).unwrap();
    }
    let _capture = env.case.capture(&[
        env.port,
        config.listener.tcp.port(),
        config.listener.udp.port(),
    ]);
    let config = fixture.config.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(crate::runtime::serve_with_provider(
        config.clone(),
        env.provider("none"),
        env.http(),
        rx,
    ));
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            if TcpStream::connect(config.listener.tcp).await.is_ok() {
                break;
            }
            assert!(!task.is_finished(), "serve exited before binding");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let first = record_handshakes(&config, &env.ca_file, &env.case).await;
    let initial = pointers(&config).0;
    let (mut existing, driver) = h2_client(config.listener.tcp, &env.ca_file).await;
    let mut old_h3 = QClient::new(config.listener.udp, &env.ca_file).await;
    let end = std::time::Instant::now() + Duration::from_secs(35);
    let mut seen = vec![initial];
    let mut serials = vec![first];
    let mut repaired = !outer;
    while seen.len() < 3 {
        assert!(
            std::time::Instant::now() < end,
            "live renewal deadline; generations={seen:?}"
        );
        assert!(!task.is_finished(), "control stopped serving");
        // Keep both old transports making real website requests throughout renewal.
        let (response, _) = existing
            .send_request(
                http::Request::builder()
                    .uri("https://proxy.example.test/")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        assert_eq!(response.await.unwrap().status(), 200);
        let id = old_h3.request("GET", "proxy.example.test", Some("/"), None, false, true);
        assert_eq!(old_h3.response(id).await.status, 200);
        let (current, loaded) = pointers(&config);
        if outer
            && !repaired
            && current != seen[0]
            && loaded.contains(&format!("loaded_generation={}", current.trim()))
        {
            env.case.event(
                "outer_expired_inner_loaded",
                json!({"CURRENT":current,"TLS_LOADED":loaded}),
            );
            assert!(loaded.contains("new_handshakes_allowed=false"));
            let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
            connector.set_ca_file(&env.ca_file).unwrap();
            let socket = TcpStream::connect(config.listener.tcp).await.unwrap();
            assert!(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    tokio_boring::connect(
                        connector.build().configure().unwrap(),
                        "proxy.example.test",
                        socket
                    )
                )
                .await
                .unwrap()
                .is_err()
            );
            env.outer(120);
            repaired = true;
        }
        if current != *seen.last().unwrap()
            && loaded.contains(&format!("loaded_generation={}", current.trim()))
            && loaded.contains("new_handshakes_allowed=true")
        {
            let serial = record_handshakes(&config, &env.ca_file, &env.case).await;
            assert!(!serials.contains(&serial));
            serials.push(serial);
            seen.push(current);
            env.case
                .journal(&config.state_dir, &format!("generation-{}", seen.len()));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    env.case.event(
        "old_connections_survived",
        json!({"rotations":seen.len()-1,"serials":serials}),
    );
    drop(existing);
    driver.abort();
    let _ = old_h3.conn.close(true, 0x100, b"");
    old_h3.step().await;
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(6), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
#[tokio::test]
async fn acme_live_two_renewals_h2_h3_and_old_connections() {
    live(false).await;
}
#[tokio::test]
async fn acme_live_outer_expiry_then_inner_renewal_and_recovery() {
    live(true).await;
}

#[tokio::test]
async fn acme_tls_loaded_diagnostic_failure_does_not_block_activation() {
    let fixture = fixture();
    let case = Case::new("tls-loaded-failure");
    let server = network(&fixture, None).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let slot = server.tls.clone();
    let before = slot.current().unwrap().id.clone();
    let _capture = case.capture(&[tcp.port(), udp.port()]);
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    rotate(&fixture);
    let status = fixture.config.state_dir.join("certificates/TLS-LOADED");
    std::fs::remove_file(&status).unwrap();
    std::fs::create_dir(&status).unwrap();
    let result = slot.refresh(&fixture.config);
    assert_eq!(
        slot.laboratory_report_failures(),
        1,
        "the real TLS-LOADED rename failure must be observed"
    );
    assert!(
        std::fs::read_dir(fixture.config.state_dir.join("certificates"))
            .unwrap()
            .filter_map(Result::ok)
            .all(|e| !e.file_name().to_string_lossy().ends_with(".tmp")),
        "failed status publication must remove temporary files"
    );
    let after = slot.current().unwrap().id.clone();
    let h2 = observed_h2(tcp, &fixture.ca, &case).await;
    let mut h3 = QClient::new(udp, &fixture.ca).await;
    let leaf = X509::from_der(h3.conn.peer_cert().unwrap()).unwrap();
    case.event("diagnostic_failure",json!({"before":before,"after":after,"CURRENT":pointers_current(&fixture.config),"error":result.err().map(|e|e.to_string()),"injection":"TLS-LOADED directory: actual rename fails before load","h2_serial":serial(&h2),"h3_serial":serial(&leaf),"h2_sha256":fingerprint(&h2),"h3_sha256":fingerprint(&leaf)}));
    let _ = h3.conn.close(true, 0x100, b"");
    h3.step().await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert_ne!(
        before, after,
        "a diagnostic rename failure should not prevent valid CURRENT activation"
    );
}

fn pointers_current(config: &Config) -> String {
    std::fs::read_to_string(config.state_dir.join("certificates/CURRENT")).unwrap()
}

async fn status_fault(stage: &'static str, after_load: bool) {
    let fixture = fixture();
    let case = Case::new(&format!("tls-loaded-{stage}-{after_load}"));
    let slot = tls::Slot::load(&fixture.config).unwrap();
    let before = slot.current().unwrap().id.clone();
    rotate(&fixture);
    if !after_load {
        std::fs::write(
            fixture.config.state_dir.join("certificates/TLS-LOADED"),
            b"force status rewrite",
        )
        .unwrap();
    }
    slot.laboratory_fail_record(stage, 0);
    let result = slot.refresh(&fixture.config);
    assert_eq!(
        slot.laboratory_fault_hits(),
        1,
        "intended diagnostic IO fault must be reached"
    );
    assert_eq!(slot.laboratory_report_failures(), 1);
    assert!(
        *result.as_ref().unwrap(),
        "activation succeeds independently of reporting"
    );
    let after = slot.current().unwrap().id.clone();
    case.event("status_fault",json!({"stage":stage,"after_load":after_load,"error":result.err().map(|e|e.to_string()),"before":before,"after":after,"CURRENT":pointers_current(&fixture.config),"TLS_LOADED":std::fs::read_to_string(fixture.config.state_dir.join("certificates/TLS-LOADED")).unwrap(),"evidence":"test-only injected io::Error at named syscall boundary"}));
    assert_ne!(
        before, after,
        "diagnostic failure should not prevent CURRENT activation; post-load failures already leave the generation changed"
    );
}
#[tokio::test]
async fn acme_tls_status_create_failure_before_load() {
    status_fault("create", false).await;
}
#[tokio::test]
async fn acme_tls_status_rename_failure_before_load() {
    status_fault("rename", false).await;
}
#[tokio::test]
async fn acme_tls_status_fsync_failure_before_load() {
    status_fault("fsync", false).await;
}
#[tokio::test]
async fn acme_tls_status_failures_after_load_observe_partial_activation() {
    for stage in ["create", "rename", "fsync"] {
        status_fault(stage, true).await;
    }
}

#[tokio::test]
async fn acme_control_panic_degrades_renewal_and_keeps_valid_network() {
    renewal_degradation(true).await;
}
#[tokio::test]
async fn acme_invalid_renewal_material_keeps_valid_network() {
    renewal_degradation(false).await;
}
async fn renewal_degradation(panic: bool) {
    let env = Environment::start(
        if panic {
            "control-panic"
        } else {
            "renewal-invalid"
        },
        Mode::Normal,
    )
    .await;
    env.state.lock().unwrap().domain = "proxy.example.test".into();
    let mut fixture = fixture();
    let config = Arc::get_mut(&mut fixture.config).unwrap();
    config.acme = env.config().acme;
    config.state_dir = env.case.path().join("live-state");
    config.limits.idle_timeout_secs = 30;
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    config.listener.tcp = tcp.local_addr().unwrap();
    config.listener.udp = udp.local_addr().unwrap();
    drop((tcp, udp));
    let config = fixture.config.clone();
    let _capture = env.case.capture(&[
        env.port,
        config.listener.tcp.port(),
        config.listener.udp.port(),
    ]);
    let (stop, rx) = watch::channel(false);
    let http = env.http();
    let (release_exit, exit) = std::sync::mpsc::channel();
    let provider = if panic {
        env.panic_provider(exit)
    } else {
        env.provider("none")
    };
    let task = tokio::spawn(crate::runtime::serve_with_provider(
        config.clone(),
        provider,
        http.clone(),
        rx,
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if TcpStream::connect(config.listener.tcp).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let cert = observed_h2(config.listener.tcp, &env.ca_file, &env.case).await;
    env.state.lock().unwrap().mode = if panic {
        Mode::Dns("normal")
    } else {
        Mode::Certificate(3 * 1024 * 1024)
    };
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let events = std::fs::read_to_string(env.case.path().join("events.jsonl")).unwrap();
            if panic && events.contains("control_fault") && events.contains("control_exit_blocked")
            {
                break;
            }
            if !panic {
                let state = std::fs::read_dir(config.state_dir.join("acme"))
                    .unwrap()
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .find(|p| p.extension().is_some_and(|s| s == "json"))
                    .unwrap();
                let journal: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(state).unwrap()).unwrap();
                if journal["blocked_certificate"].is_object() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        !task.is_finished(),
        "valid network must outlive failed renewal control"
    );
    assert_eq!(
        record_handshakes(&config, &env.ca_file, &env.case).await,
        serial(&cert)
    );
    let stored = DiskStore::open(&config.state_dir.join("certificates"))
        .unwrap()
        .read_current()
        .unwrap()
        .unwrap();
    env.case.event("renewal_degradation_outcome",json!({"renewal":if panic {"stopped; no automatic Manager restart"} else {"blocked on bounded certificate evidence; controller remains healthy"},"certificate_sha256":fingerprint(&cert),"not_after":stored.lifetime.not_after,"now":crate::acme::now(),"active_hyper_drivers":http.laboratory_active_drivers()}));
    assert!(stored.lifetime.not_after > crate::acme::now());
    assert!(TcpStream::connect(config.listener.tcp).await.is_ok());
    assert_eq!(http.laboratory_active_drivers(), 0);
    env.case.journal(&config.state_dir, "after-control-panic");
    stop.send(true).unwrap();
    if panic {
        env.case.event(
            "shutdown_before_control_exit",
            json!({"fault_reached":true}),
        );
        release_exit.send(()).unwrap();
    }
    tokio::time::timeout(Duration::from_secs(6), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
