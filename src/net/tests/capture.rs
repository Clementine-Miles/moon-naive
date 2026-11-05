//! Opt-in, loopback-only packet capture workload. This is a deterministic lab
//! client, not a Chromium fingerprint or a model of real browsing statistics.
use super::*;
use moon_naive_core::{
    auth::{Binding, Context},
    codec::{Decoder, Encoder, Mode, Offer},
};
use serde_json::json;
use std::{io::Write, path::Path};

const TARGET: &str = "example.org:443";
const SEGMENTS: [usize; 6] = [512, 1024, 2048, 6144, 8192, 12288];

pub(super) fn io_timeout() -> Duration {
    let seconds = std::env::var("MOON_NAIVE_CAPTURE_TIMEOUT_SECS")
        .ok()
        .map(|v| v.parse::<u64>().unwrap())
        .unwrap_or(5);
    assert!((1..=60).contains(&seconds));
    Duration::from_secs(seconds)
}

fn page(length: usize) -> Vec<u8> {
    let snippet = b"<!doctype html><html><head><style>body{font:16px sans-serif;margin:2em}</style></head><body><article><h1>Local test page</h1><p>Deterministic content for packet measurements.</p></article><script>document.documentElement.dataset.loaded='yes';</script></body></html>\n";
    snippet.iter().copied().cycle().take(length).collect()
}

/// Compare the decoded H1 representation for either length or chunk framing.
fn h1_body(response: &[u8]) -> Vec<u8> {
    let end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = std::str::from_utf8(&response[..end]).unwrap();
    let mut rest = &response[end + 4..];
    if !head
        .lines()
        .any(|line| line.eq_ignore_ascii_case("transfer-encoding: chunked"))
    {
        return rest.to_vec();
    }
    let mut body = Vec::new();
    loop {
        let end = rest.windows(2).position(|w| w == b"\r\n").unwrap();
        let header = std::str::from_utf8(&rest[..end]).unwrap();
        let length = usize::from_str_radix(header.split(';').next().unwrap().trim(), 16).unwrap();
        rest = &rest[end + 2..];
        if length == 0 {
            assert!(rest.starts_with(b"\r\n"));
            break;
        }
        assert!(rest.len() >= length + 2);
        body.extend_from_slice(&rest[..length]);
        assert_eq!(&rest[length..length + 2], b"\r\n");
        rest = &rest[length + 2..];
    }
    body
}

fn context(binding: &Binding) -> Context<'_> {
    Context {
        binding,
        method: "CONNECT",
        authority: TARGET,
        scheme: None,
        path: None,
        protocol: None,
    }
}

fn secret_file(path: &Path) -> std::fs::File {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    file
}

fn connector(ca: &Path, keylog: &Path, alpn: &[u8]) -> SslConnector {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(ca).unwrap();
    connector.set_alpn_protos(alpn).unwrap();
    if std::env::var("MOON_NAIVE_CAPTURE_TLS_VERSION").is_ok_and(|v| v == "1.2") {
        // Only H1 website scenarios use TLS 1.2. Proxy authentication remains
        // TLS 1.3/exporter-bound and is never disabled for this experiment.
        connector
            .set_max_proto_version(Some(boring::ssl::SslVersion::TLS1_2))
            .unwrap();
    }
    let log = std::sync::Mutex::new(secret_file(keylog));
    connector.set_keylog_callback(move |_, line| {
        writeln!(log.lock().unwrap(), "{line}").unwrap();
    });
    connector.build()
}

fn capture_fixture() -> (Fixture, serde_json::Value) {
    use boring::{
        ec::{EcGroup, EcKey},
        nid::Nid,
        rsa::Rsa,
    };
    let profile = std::env::var("MOON_NAIVE_CAPTURE_CERT").unwrap_or("p256-ca".into());
    let make_key = || match profile.as_str() {
        "p256-leaf-only" | "p256-ca" => key(),
        "rsa2048-ca" => PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
        "p384-chain" => PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap(),
        )
        .unwrap(),
        _ => panic!("unknown capture certificate profile"),
    };
    let digest = if profile == "p384-chain" {
        MessageDigest::sha384()
    } else {
        MessageDigest::sha256()
    };
    let certificate =
        |key: &PKey<Private>, issuer: Option<(&X509, &PKey<Private>)>, ca: bool, serial: u32| {
            let mut subject = X509NameBuilder::new().unwrap();
            subject
                .append_entry_by_text(
                    "CN",
                    &if ca {
                        format!("moon-naive local CA {serial}")
                    } else {
                        "proxy.example.test".into()
                    },
                )
                .unwrap();
            let subject = subject.build();
            let mut cert = X509::builder().unwrap();
            cert.set_version(2).unwrap();
            cert.set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
                .unwrap();
            cert.set_subject_name(&subject).unwrap();
            cert.set_issuer_name(issuer.map_or(subject.as_ref(), |(cert, _)| cert.subject_name()))
                .unwrap();
            cert.set_pubkey(key).unwrap();
            cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            cert.set_not_after(&Asn1Time::days_from_now(60).unwrap())
                .unwrap();
            let mut constraints = BasicConstraints::new();
            constraints.critical();
            if ca {
                constraints.ca();
            }
            cert.append_extension(&constraints.build().unwrap())
                .unwrap();
            if ca {
                cert.append_extension(&KeyUsage::new().key_cert_sign().crl_sign().build().unwrap())
                    .unwrap();
            } else {
                cert.append_extension(
                    &KeyUsage::new()
                        .digital_signature()
                        .key_encipherment()
                        .build()
                        .unwrap(),
                )
                .unwrap();
                cert.append_extension(&ExtendedKeyUsage::new().server_auth().build().unwrap())
                    .unwrap();
                cert.append_extension(
                    &SubjectAlternativeName::new()
                        .dns("proxy.example.test")
                        .dns("public.example.test")
                        .build(&cert.x509v3_context(issuer.map(|(cert, _)| cert.as_ref()), None))
                        .unwrap(),
                )
                .unwrap();
            }
            cert.sign(issuer.map_or(key, |(_, key)| key), digest)
                .unwrap();
            cert.build()
        };
    let mut f = fixture();
    let root_key = make_key();
    let root = certificate(&root_key, None, true, 1);
    let leaf_key = make_key();
    let mut chain = if profile == "p384-chain" {
        let intermediate_key = make_key();
        let intermediate = certificate(&intermediate_key, Some((&root, &root_key)), true, 2);
        vec![
            certificate(
                &leaf_key,
                Some((&intermediate, &intermediate_key)),
                false,
                3,
            ),
            intermediate,
            root.clone(),
        ]
    } else {
        vec![
            certificate(&leaf_key, Some((&root, &root_key)), false, 2),
            root.clone(),
        ]
    };
    if profile == "p256-leaf-only" {
        chain.truncate(1);
    }
    std::fs::write(&f.ca, root.to_pem().unwrap()).unwrap();
    let candidate = crate::acme::certificate::Candidate {
        chain_pem: chain
            .iter()
            .flat_map(|cert| cert.to_pem().unwrap())
            .collect(),
        key_pem: leaf_key.private_key_to_pem_pkcs8().unwrap(),
    };
    let bundle = crate::acme::certificate::Validator::for_config(&f.config)
        .unwrap()
        .verify(candidate, crate::acme::now())
        .unwrap();
    DiskStore::open(&f.config.state_dir.join("certificates"))
        .unwrap()
        .install(&bundle)
        .unwrap();
    f.ca_key = root_key;
    f.ca_cert = root;
    let metadata = json!({"profile":profile,"chain_der_lengths":chain.iter().map(|cert| cert.to_der().unwrap().len()).collect::<Vec<_>>(),
        "chain_der_sha256":chain.iter().map(|cert| cert.digest(MessageDigest::sha256()).unwrap().iter().map(|b| format!("{b:02x}")).collect::<String>()).collect::<Vec<_>>(),
        "leaf_bits":leaf_key.bits(),"trust_and_hostname_verified":true});
    (f, metadata)
}

async fn capture_tcp(address: std::net::SocketAddr) -> TcpStream {
    let socket = TcpStream::connect(address).await.unwrap();
    socket.set_nodelay(true).unwrap();
    socket
}

async fn h2_capture(
    address: std::net::SocketAddr,
    ca: &Path,
    keylog: &Path,
) -> (H2Client, tokio::task::JoinHandle<()>) {
    let io = tokio_boring::connect(
        connector(ca, keylog, b"\x02h2").configure().unwrap(),
        "proxy.example.test",
        capture_tcp(address).await,
    )
    .await
    .unwrap();
    let exporter = super::super::exporter(io.ssl()).unwrap();
    let (sender, connection) = ::h2::client::Builder::new()
        // Avoid the deliberately tiny flow-control windows of stress tests.
        .initial_window_size(1024 * 1024)
        .initial_connection_window_size(8 * 1024 * 1024)
        .handshake(io)
        .await
        .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (
        H2Client {
            sender,
            exporter,
            next_id: 1,
            last_proof: None,
        },
        driver,
    )
}

async fn h3_capture(address: std::net::SocketAddr, ca: &Path, keylog: &Path) -> QClient {
    // Optional local datagram relay impairs QUIC end to end, without terminating
    // TLS/QUIC or touching the production listener/transport configuration.
    let address = std::env::var("MOON_NAIVE_CAPTURE_QUIC_RELAY")
        .map(|value| value.parse().unwrap())
        .unwrap_or(address);
    // Precreate with restrictive permissions before quiche opens the writer.
    drop(secret_file(keylog));
    let mut q = QClient::initial_with_keylog(address, ca, Some(keylog)).await;
    let deadline = std::time::Instant::now() + q.io_timeout;
    while q.h3.is_none() {
        assert!(std::time::Instant::now() < deadline);
        q.step().await;
    }
    assert_eq!(q.conn.application_proto(), b"h3");
    q
}

fn wire_upload(mode: Mode) -> Vec<u8> {
    let mut encoder = Encoder::new(mode);
    let mut wire = Vec::new();
    // Zero upload padding deliberately separates server policy from this
    // reference client's behavior. This is not a Chromium upload model.
    for i in 0..24 {
        wire.extend(encoder.encode(&page(128 + i * 17), 0).unwrap());
    }
    wire
}

fn record_summary(wire: &[u8], mode: Mode) -> serde_json::Value {
    let mut records = Vec::new();
    let mut rest = wire;
    let mut padding = 0;
    while !rest.is_empty() && (mode.sparse() || records.len() < usize::from(mode.initial())) {
        assert!(rest.len() >= 3);
        let n = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        let p = usize::from(rest[2]);
        assert!(rest.len() >= 3 + n + p);
        records.push(json!({"payload": n, "padding": p, "wire": 3 + n + p}));
        padding += p;
        rest = &rest[3 + n + p..];
    }
    json!({"records":records,"padding_bytes":padding,"raw_tail_bytes":rest.len(),"wire_bytes":wire.len()})
}

fn bulk_bytes() -> usize {
    let bytes = std::env::var("MOON_NAIVE_CAPTURE_BULK_BYTES")
        .ok()
        .map(|v| v.parse::<usize>().unwrap())
        .unwrap_or(1024 * 1024);
    assert!((1024..=16 * 1024 * 1024).contains(&bytes));
    bytes
}

async fn raw_origin(listener: TcpListener, bulk: bool) {
    let mut jobs = tokio::task::JoinSet::new();
    for _ in 0..2 {
        let (mut stream, _) = listener.accept().await.unwrap();
        jobs.spawn(async move {
            let mut upload = Vec::new();
            stream.read_to_end(&mut upload).await.unwrap();
            let expected: Vec<_> = (0..24).flat_map(|i| page(128 + i * 17)).collect();
            assert_eq!(upload, expected);
            for length in SEGMENTS.into_iter().cycle().take(24) {
                stream.write_all(&page(length)).await.unwrap();
                stream.flush().await.unwrap();
                // Controlled fixture pacing makes more than 16 distinct reads
                // observable. It is not production behavior or a fitted model.
                tokio::time::sleep(Duration::from_millis(4)).await;
            }
            if bulk {
                stream.write_all(&page(bulk_bytes())).await.unwrap();
            }
            stream.shutdown().await.unwrap();
        });
    }
    while let Some(result) = jobs.join_next().await {
        result.unwrap();
    }
}

async fn inner_tls_origin(listener: TcpListener, f: &Fixture) -> tokio::task::JoinHandle<()> {
    let stored = DiskStore::open(&f.config.state_dir.join("certificates"))
        .unwrap()
        .read_current()
        .unwrap()
        .unwrap();
    let mut acceptor = boring::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    let chain = X509::stack_from_pem(&stored.candidate.chain_pem).unwrap();
    acceptor.set_certificate(&chain[0]).unwrap();
    for certificate in &chain[1..] {
        acceptor.add_extra_chain_cert(certificate.clone()).unwrap();
    }
    acceptor
        .set_private_key(&PKey::private_key_from_pem(&stored.candidate.key_pem).unwrap())
        .unwrap();
    let acceptor = acceptor.build();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = tokio_boring::accept(&acceptor, stream).await.unwrap();
        for i in 0..24 {
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(tls.read_u8().await.unwrap());
                assert!(header.len() <= 4096);
            }
            assert!(header.starts_with(format!("GET /asset/{i} ").as_bytes()));
            let body = page(SEGMENTS[i % SEGMENTS.len()]);
            tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",body.len(),if i == 23 {"close"} else {"keep-alive"}).as_bytes()).await.unwrap();
            tls.write_all(&body).await.unwrap();
            tls.flush().await.unwrap();
        }
        tls.shutdown().await.unwrap();
    })
}

async fn inner_tls(
    f: &Fixture,
    mut upload: ::h2::SendStream<Bytes>,
    mut response: ::h2::RecvStream,
    mode: Mode,
) -> Vec<u8> {
    let (application, bridge) = tokio::io::duplex(256 * 1024);
    let (mut read, mut write) = tokio::io::split(bridge);
    let tx = tokio::spawn(async move {
        let mut encoder = Encoder::new(mode);
        let mut buffer = [0; moon_naive_core::codec::MAX_PAYLOAD];
        loop {
            let n = read.read(&mut buffer).await.unwrap();
            if n == 0 {
                upload.send_data(Bytes::new(), true).unwrap();
                break;
            }
            v2_send(
                &mut upload,
                Bytes::from(encoder.encode(&buffer[..n], 0).unwrap()),
                false,
            )
            .await;
        }
    });
    let rx = tokio::spawn(async move {
        let mut decoder = Decoder::new(mode);
        let mut wire = Vec::new();
        while let Some(part) = response.data().await {
            let part = part.unwrap();
            response
                .flow_control()
                .release_capacity(part.len())
                .unwrap();
            wire.extend_from_slice(&part);
            write
                .write_all(&decoder.feed(&part).unwrap())
                .await
                .unwrap();
        }
        decoder.finish().unwrap();
        write.shutdown().await.unwrap();
        wire
    });
    // The inner HTTPS peer is verified independently; no insecure TLS flag.
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(&f.ca).unwrap();
    let mut tls = tokio_boring::connect(
        connector.build().configure().unwrap(),
        "proxy.example.test",
        application,
    )
    .await
    .unwrap();
    for i in 0..24 {
        tls.write_all(format!("GET /asset/{i} HTTP/1.1\r\nHost: proxy.example.test\r\nAccept: text/html\r\nConnection: {}\r\n\r\n",if i == 23 {"close"} else {"keep-alive"}).as_bytes()).await.unwrap();
        tls.flush().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(tls.read_u8().await.unwrap());
            assert!(header.len() <= 4096);
        }
        assert!(header.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let mut received = vec![0; SEGMENTS[i % SEGMENTS.len()]];
        tls.read_exact(&mut received).await.unwrap();
        assert_eq!(received, page(received.len()));
    }
    let mut trailing = Vec::new();
    tls.read_to_end(&mut trailing).await.unwrap();
    assert!(trailing.is_empty());
    tls.shutdown().await.unwrap();
    drop(tls);
    tx.await.unwrap();
    rx.await.unwrap()
}

/// Run explicitly with `--ignored --exact net::tests::capture::packet_capture_lab`
/// and capture loopback TCP/UDP MOON_NAIVE_CAPTURE_PORT (default 18443).
#[tokio::test]
#[ignore = "opt-in local packet capture; requires MOON_NAIVE_CAPTURE_DIR"]
async fn packet_capture_lab() {
    let Ok(directory) = std::env::var("MOON_NAIVE_CAPTURE_DIR") else {
        eprintln!("packet_capture_lab: skipped (MOON_NAIVE_CAPTURE_DIR unset)");
        return;
    };
    let directory = PathBuf::from(directory);
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let scenario = std::env::var("MOON_NAIVE_CAPTURE_SCENARIO").unwrap_or("h2-site".into());
    if matches!(scenario.as_str(), "h2-soak" | "h3-soak") {
        soak_capture(&directory, &scenario).await;
        return;
    }
    if matches!(
        scenario.as_str(),
        "h2-site-burst"
            | "h2-tunnel-burst"
            | "h2-site-idle"
            | "h2-tunnel-idle"
            | "h2-site-h2origin-burst"
            | "h2-site-h2origin-idle"
            | "h2-site-long"
            | "h2-tunnel-long"
    ) {
        mirror_capture(&directory, &scenario).await;
        return;
    }
    assert!(matches!(
        scenario.as_str(),
        "h1-site"
            | "h1-connect"
            | "h1-head"
            | "h1-unknown-host"
            | "h1-ambiguous"
            | "h2-site"
            | "h2-probe"
            | "h3-site"
            | "h3-probe"
            | "h2-tunnel8"
            | "h2-tunnel16"
            | "h2-sparse8"
            | "h2-sparse16"
            | "h3-tunnel8"
            | "h3-tunnel16"
            | "h3-sparse8"
            | "h3-sparse16"
            | "h2-inner-tls"
            | "h2-bulk8"
            | "h2-bulk16"
            | "h3-bulk8"
            | "h3-bulk16"
    ));
    let port = std::env::var("MOON_NAIVE_CAPTURE_PORT")
        .unwrap_or("18443".into())
        .parse::<u16>()
        .unwrap();
    let keylog = directory.join("tls.keys");
    let (mut f, certificate) = capture_fixture();
    let config = Arc::get_mut(&mut f.config).unwrap();
    config.listener.h1 = true;
    config.limits.idle_timeout_secs = 10;
    let web_page = page(96 * 1024);
    std::fs::write(f.site_root.join("index.html"), &web_page).unwrap();
    std::fs::copy(&f.ca, directory.join("ca.pem")).unwrap();
    let stored = DiskStore::open(&f.config.state_dir.join("certificates"))
        .unwrap()
        .read_current()
        .unwrap()
        .unwrap();
    std::fs::write(directory.join("chain.pem"), &stored.candidate.chain_pem).unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut server = network(&f, Some(target.local_addr().unwrap())).await;
    server.tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let address = server.tcp_addr().unwrap();
    server.udp = UdpSocket::bind(address).await.unwrap();
    let stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let tunnel = scenario.contains("tunnel")
        || scenario.contains("sparse")
        || scenario.contains("bulk")
        || scenario.ends_with("inner-tls");
    let inner = scenario.ends_with("inner-tls");
    let origin = if inner {
        Some(inner_tls_origin(target, &f).await)
    } else if tunnel {
        Some(tokio::spawn(raw_origin(target, scenario.contains("bulk"))))
    } else {
        None
    };
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros();
    let credentials = Credentials::new(&[("alice", "long-loopback-test-password")]).unwrap();
    let bits = if scenario.contains("sparse8") {
        5
    } else if scenario.contains("sparse16") || inner {
        6
    } else if scenario.ends_with('8') {
        1
    } else {
        2
    };
    let offer = Offer::from_bits(bits).unwrap();
    let mut expected: Vec<_> = SEGMENTS
        .into_iter()
        .cycle()
        .take(24)
        .flat_map(page)
        .collect();
    if scenario.contains("bulk") {
        expected.extend(page(bulk_bytes()));
    }
    let mut streams = Vec::new();
    let transfer_started;
    let transfer_finished;
    let mut quic_path = None;
    if scenario.starts_with("h1") {
        let mut io = tokio_boring::connect(
            connector(&f.ca, &keylog, b"\x08http/1.1")
                .configure()
                .unwrap(),
            "proxy.example.test",
            capture_tcp(address).await,
        )
        .await
        .unwrap();
        transfer_started = unix_us();
        let request = match scenario.as_str() {
            "h1-connect" => {
                "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\nConnection: close\r\n\r\n"
            }
            "h1-head" => "HEAD / HTTP/1.1\r\nHost: proxy.example.test\r\nConnection: close\r\n\r\n",
            "h1-unknown-host" => {
                "GET / HTTP/1.1\r\nHost: unknown.example.test\r\nConnection: close\r\n\r\n"
            }
            "h1-ambiguous" => {
                "POST / HTTP/1.1\r\nHost: proxy.example.test\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
            }
            _ => {
                "GET / HTTP/1.1\r\nHost: proxy.example.test\r\nAccept: text/html\r\nConnection: close\r\n\r\n"
            }
        };
        io.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        io.read_to_end(&mut response).await.unwrap();
        if scenario.ends_with("site") {
            assert!(response.starts_with(b"HTTP/1.1 200"));
            assert_eq!(h1_body(&response), web_page);
        } else if scenario == "h1-head" {
            assert!(response.starts_with(b"HTTP/1.1 200"));
            assert!(h1_body(&response).is_empty());
        } else {
            assert!(!response.starts_with(b"HTTP/1.1 200"));
            assert!(!response.starts_with(b"HTTP/1.1 407"));
        }
        transfer_finished = unix_us();
        let status = std::str::from_utf8(&response[..12])
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap();
        streams.push(json!({"id":0,"status":status,"http_response_bytes":response.len(),"tls_version":io.ssl().version_str()}));
    } else if scenario.starts_with("h2") {
        let (mut client, driver) = h2_capture(address, &f.ca, &keylog).await;
        transfer_started = unix_us();
        if tunnel {
            let mut requests = Vec::new();
            for _ in 0..if inner { 1 } else { 2 } {
                let binding = Binding {
                    exporter: client.exporter,
                    stream_id: client.next_id,
                };
                let mut value = http::HeaderValue::from_str(
                    &credentials
                        .authorization_with(0, &context(&binding), offer)
                        .unwrap(),
                )
                .unwrap();
                value.set_sensitive(true);
                let (response, upload) = client
                    .send_request(
                        http::Request::builder()
                            .method("CONNECT")
                            .uri(TARGET)
                            .header("proxy-authorization", value)
                            .body(())
                            .unwrap(),
                        false,
                    )
                    .unwrap();
                requests.push((binding, response, upload));
            }
            let mut jobs = tokio::task::JoinSet::new();
            for (binding, response, mut upload) in requests {
                let response = response.await.unwrap();
                assert_eq!(response.status(), 200);
                let proof = response.headers()["proxy-authentication-info"]
                    .to_str()
                    .unwrap();
                let mode = credentials
                    .verify_selection(0, &context(&binding), offer, proof)
                    .unwrap();
                assert!(!response.headers().contains_key("padding"));
                if inner {
                    let wire = inner_tls(&f, upload, response.into_body(), mode).await;
                    streams.push(json!({"id":binding.stream_id,"mode":bits,"server":record_summary(&wire,mode),"inner_https_responses":24}));
                    std::fs::write(
                        directory.join(format!("stream-{}.bin", binding.stream_id)),
                        wire,
                    )
                    .unwrap();
                } else {
                    jobs.spawn(async move {
                        v2_send(&mut upload, Bytes::from(wire_upload(mode)), true).await;
                        (binding.stream_id, mode, body(response.into_body()).await)
                    });
                }
            }
            while let Some(result) = jobs.join_next().await {
                let (id, mode, wire) = result.unwrap();
                let mut decoder = Decoder::new(mode);
                assert_eq!(decoder.feed(&wire).unwrap(), expected);
                decoder.finish().unwrap();
                streams.push(json!({"id":id,"mode":bits,"server":record_summary(&wire,mode),"payload_bytes":expected.len()}));
                std::fs::write(directory.join(format!("stream-{id}.bin")), wire).unwrap();
            }
        } else {
            for probe in [false, true] {
                let id = client.next_id;
                let mut request = http::Request::builder()
                    .uri("https://proxy.example.test/")
                    .header("accept", "text/html");
                if scenario.ends_with("probe") {
                    request = request.method("CONNECT").uri(TARGET);
                    if probe {
                        request = request.header(
                            "proxy-authorization",
                            "moon-naive 02.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        );
                    }
                }
                let (response, _) = client
                    .send_request(request.body(()).unwrap(), true)
                    .unwrap();
                let response = response.await.unwrap();
                let status = response.status().as_u16();
                let bytes = body(response.into_body()).await;
                if scenario.ends_with("site") {
                    assert_eq!(status, 200);
                    assert_eq!(bytes, web_page);
                } else {
                    assert_ne!(status, 200);
                    assert_ne!(status, 407);
                }
                streams.push(json!({"id":id,"status":status,"payload_bytes":bytes.len()}));
            }
        }
        transfer_finished = unix_us();
        driver.abort();
    } else {
        let mut client = h3_capture(address, &f.ca, &keylog).await;
        transfer_started = unix_us();
        if tunnel {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let binding = Binding {
                    exporter: super::super::exporter(client.conn.as_mut()).unwrap(),
                    stream_id: client.next_id,
                };
                let proof = credentials
                    .authorization_with(0, &context(&binding), offer)
                    .unwrap();
                let id = client.request("CONNECT", TARGET, None, Some(&proof), false, false);
                requests.push((id, binding));
            }
            let mut modes = Vec::new();
            for (id, binding) in requests {
                let deadline = std::time::Instant::now() + client.io_timeout;
                while client.responses.get(&id).is_none_or(|r| r.status == 0) {
                    assert!(std::time::Instant::now() < deadline);
                    client.step().await;
                }
                let response = &client.responses[&id];
                assert_eq!(response.status, 200);
                let mode = credentials
                    .verify_selection(
                        0,
                        &context(&binding),
                        offer,
                        response.headers["proxy-authentication-info"]
                            .to_str()
                            .unwrap(),
                    )
                    .unwrap();
                client.send(id, &wire_upload(mode)).await;
                modes.push((id, mode));
            }
            for (id, mode) in modes {
                let response = client.response(id).await;
                assert!(!response.reset);
                let mut decoder = Decoder::new(mode);
                assert_eq!(decoder.feed(&response.body).unwrap(), expected);
                decoder.finish().unwrap();
                streams.push(json!({"id":id,"mode":bits,"server":record_summary(&response.body,mode),"payload_bytes":expected.len()}));
                std::fs::write(directory.join(format!("stream-{id}.bin")), response.body).unwrap();
            }
        } else {
            for probe in [false, true] {
                let id = if scenario.ends_with("probe") {
                    client.request(
                        "CONNECT",
                        TARGET,
                        None,
                        if probe {
                            Some("moon-naive 02.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                        } else {
                            None
                        },
                        false,
                        true,
                    )
                } else {
                    client.request("GET", "proxy.example.test", Some("/"), None, false, true)
                };
                let response = client.response(id).await;
                if scenario.ends_with("site") {
                    assert_eq!(response.status, 200);
                    assert_eq!(response.body, web_page);
                } else {
                    assert_ne!(response.status, 200);
                    assert_ne!(response.status, 407);
                }
                streams.push(
                    json!({"id":id,"status":response.status,"payload_bytes":response.body.len()}),
                );
            }
        }
        transfer_finished = unix_us();
        quic_path = client.conn.path_stats().next().map(|path| json!({
            "client_rtt_us":path.rtt.as_micros(), "client_min_rtt_us":path.min_rtt.map(|rtt|rtt.as_micros()),
            "client_cwnd":path.cwnd,"client_lost_packets":path.lost,"client_pto":path.total_pto_count,
        }));
        client.conn.close(true, 0, b"lab complete").unwrap();
        client.step().await;
    }
    let dials = stats.dials.load(Ordering::Relaxed);
    assert_eq!(
        dials,
        if inner {
            1
        } else if tunnel {
            2
        } else {
            0
        }
    );
    if let Some(origin) = origin {
        tokio::time::timeout(Duration::from_secs(5), origin)
            .await
            .unwrap()
            .unwrap();
    }
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    let result = json!({"scenario":scenario,"tcp_udp_port":address.port(),"quic_path":quic_path,"transfer_start_unix_us":transfer_started,"transfer_end_unix_us":transfer_finished,"bulk_bytes_per_stream":if scenario.contains("bulk"){bulk_bytes()}else{0},"start_unix_us":started,"end_unix_us":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros(),"transport_connections":1,"target_dials":dials,"streams":streams,"client":"test-only BoringSSL/h2/quiche; not Chromium","certificate":certificate,"tcp_congestion":f.config.transport.tcp_congestion.as_str(),"quic_congestion":f.config.transport.quic_congestion.as_str(),"raw_tunnel_schedule_ms":if tunnel && !inner {Some(4)}else{None},"upload_padding":"zero in reference client","private_keys_saved":false});
    std::fs::write(
        directory.join("workload.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!(
        "MOON_NAIVE_CAPTURE {}",
        serde_json::to_string(&result).unwrap()
    );
}

const MIRROR_SIZES: [usize; 8] = [512, 1024, 2048, 4096, 8192, 12288, 24576, 65536];
fn mirror_size(resource: usize) -> usize {
    MIRROR_SIZES[resource % MIRROR_SIZES.len()]
}
fn unix_us() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros()
}

async fn mirror_tunnel(
    mut upload: ::h2::SendStream<Bytes>,
    mut response: ::h2::RecvStream,
    mode: Mode,
    resources: Vec<usize>,
    idle: bool,
) -> (Vec<u8>, Vec<serde_json::Value>) {
    let long = resources.len() > 4;
    let (mut application, bridge) = tokio::io::duplex(256 * 1024);
    let (mut read, mut write) = tokio::io::split(bridge);
    let tx = tokio::spawn(async move {
        let mut encoder = Encoder::new(mode);
        let mut buffer = [0; moon_naive_core::codec::MAX_PAYLOAD];
        loop {
            let n = read.read(&mut buffer).await.unwrap();
            if n == 0 {
                upload.send_data(Bytes::new(), true).unwrap();
                break;
            }
            v2_send(
                &mut upload,
                Bytes::from(encoder.encode(&buffer[..n], 0).unwrap()),
                false,
            )
            .await;
        }
    });
    let rx = tokio::spawn(async move {
        let mut decoder = Decoder::new(mode);
        let mut wire = Vec::new();
        while let Some(part) = response.data().await {
            let part = part.unwrap();
            response
                .flow_control()
                .release_capacity(part.len())
                .unwrap();
            wire.extend_from_slice(&part);
            write
                .write_all(&decoder.feed(&part).unwrap())
                .await
                .unwrap();
        }
        decoder.finish().unwrap();
        write.shutdown().await.unwrap();
        wire
    });
    let mut events = Vec::new();
    for (at, resource) in resources.into_iter().enumerate() {
        if idle && (at == 2 || (long && at % 4 == 2)) {
            let started = unix_us();
            tokio::time::sleep(Duration::from_secs(if long { 2 } else { 1 })).await;
            events.push(json!({"event":"idle","start_unix_us":started,"end_unix_us":unix_us()}));
        }
        let started = unix_us();
        application.write_all(format!("GET /resource/{resource} HTTP/1.1\r\nHost: proxy.example.test\r\nAccept: application/octet-stream\r\n\r\n").as_bytes()).await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(application.read_u8().await.unwrap());
            assert!(header.len() < 8192);
        }
        assert!(header.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let mut received = vec![0; mirror_size(resource)];
        application.read_exact(&mut received).await.unwrap();
        assert_eq!(received, page(received.len()));
        events.push(json!({"event":"response","resource":resource,"payload_bytes":received.len(),"start_unix_us":started,"end_unix_us":unix_us()}));
    }
    application.shutdown().await.unwrap();
    let mut tail = Vec::new();
    application.read_to_end(&mut tail).await.unwrap();
    assert!(tail.is_empty());
    drop(application);
    tx.await.unwrap();
    (rx.await.unwrap(), events)
}

async fn mirror_capture(directory: &Path, scenario: &str) {
    let burst = scenario.ends_with("burst");
    let tunnel = scenario.contains("tunnel");
    let origin_h2 = scenario.contains("h2origin");
    let long = scenario.ends_with("long");
    let count = if burst {
        32
    } else if long {
        16
    } else {
        4
    };
    let started = unix_us();
    let port = std::env::var("MOON_NAIVE_CAPTURE_PORT")
        .unwrap_or("18443".into())
        .parse::<u16>()
        .unwrap();
    let (mut f, certificate) = capture_fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let seen_connections = connections.clone();
    let seen_requests = requests.clone();
    let generation = tls::Slot::load(&f.config).unwrap().current().unwrap();
    f.origin.abort();
    f.origin = tokio::spawn(async move {
        let mut jobs = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = jobs.join_next(), if !jobs.is_empty() => {},
                accepted = listener.accept() => {
                    let (io, _) = accepted.unwrap();
                    seen_connections.fetch_add(1, Ordering::Relaxed);
                    let requests = seen_requests.clone();
                    let generation = generation.clone();
                    jobs.spawn(async move {
                        if origin_h2 {
                            let stream = pingora_core::protocols::tls::server::handshake(
                                &generation.h2,
                                pingora_core::protocols::l4::stream::Stream::from(io),
                            ).await.unwrap();
                            let mut connection = ::h2::server::handshake(stream).await.unwrap();
                            let mut responses = tokio::task::JoinSet::new();
                            while let Some(Ok((request, mut sender))) = connection.accept().await {
                                requests.fetch_add(1, Ordering::Relaxed);
                                let resource = request.uri().path().strip_prefix("/resource/").unwrap().parse::<usize>().unwrap();
                                let (parts, bytes) = mirror_reply(resource).into_parts();
                                responses.spawn(async move {
                                    let mut stream = sender.send_response(http::Response::from_parts(parts, ()), false).unwrap();
                                    v2_send(&mut stream, bytes, true).await;
                                });
                            }
                            return;
                        }
                        let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                            requests.fetch_add(1, Ordering::Relaxed);
                            let resource = request.uri().path().strip_prefix("/resource/").unwrap().parse::<usize>().unwrap();
                            async move {
                                Ok::<_,std::convert::Infallible>(mirror_reply(resource).map(http_body_util::Full::new))
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(io), service).await;
                    });
                }
            }
        }
    });
    let config = Arc::get_mut(&mut f.config).unwrap();
    config.limits.max_streams = 64;
    config.limits.idle_timeout_secs = if long { 3 } else { 10 };
    config.website.upstreams[0].origins = vec![format!(
        "{}://{origin_address}",
        if origin_h2 { "https" } else { "http" }
    )];
    if origin_h2 {
        config.website.upstreams[0].http2 = true;
        config.website.upstreams[0].tls_server_name = Some("proxy.example.test".into());
        config.website.upstreams[0].ca_file = Some(f.ca.clone());
    }
    std::fs::copy(&f.ca, directory.join("ca.pem")).unwrap();
    let stored = DiskStore::open(&f.config.state_dir.join("certificates"))
        .unwrap()
        .read_current()
        .unwrap()
        .unwrap();
    std::fs::write(directory.join("chain.pem"), stored.candidate.chain_pem).unwrap();
    let mut server = network(&f, Some(origin_address)).await;
    server.tcp = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let address = server.tcp_addr().unwrap();
    server.udp = UdpSocket::bind(address).await.unwrap();
    let stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut client, driver) = h2_capture(address, &f.ca, &directory.join("tls.keys")).await;
    let mut streams = Vec::new();
    let mut events = Vec::new();
    if origin_h2 {
        // Warm the normal Pingora pool, then measure multiplexing on that
        // established origin connection (cold H2 races may open more than one).
        let id = client.next_id;
        let (reply, _) = client
            .send_request(
                http::Request::builder()
                    .uri("https://proxy.example.test/resource/0")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        let reply = reply.await.unwrap();
        assert_eq!(reply.status(), 200);
        let bytes = body(reply.into_body()).await;
        assert_eq!(bytes, page(mirror_size(0)));
        streams.push(
            json!({"id":id,"resource":0,"warmup":true,"payload_bytes":bytes.len(),"status":200}),
        );
    }
    if tunnel {
        let credentials = Credentials::new(&[("alice", "long-loopback-test-password")]).unwrap();
        let offer = Offer::from_bits(2).unwrap();
        let mut pending = Vec::new();
        for resource in 0..if burst { count } else { 1 } {
            let binding = Binding {
                exporter: client.exporter,
                stream_id: client.next_id,
            };
            let mut value = http::HeaderValue::from_str(
                &credentials
                    .authorization_with(0, &context(&binding), offer)
                    .unwrap(),
            )
            .unwrap();
            value.set_sensitive(true);
            let (response, upload) = client
                .send_request(
                    http::Request::builder()
                        .method("CONNECT")
                        .uri(TARGET)
                        .header("proxy-authorization", value)
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            pending.push((resource, binding, response, upload));
        }
        let mut jobs = tokio::task::JoinSet::new();
        for (resource, binding, response, upload) in pending {
            let response = response.await.unwrap();
            assert_eq!(response.status(), 200);
            let mode = credentials
                .verify_selection(
                    0,
                    &context(&binding),
                    offer,
                    response.headers()["proxy-authentication-info"]
                        .to_str()
                        .unwrap(),
                )
                .unwrap();
            jobs.spawn(async move {
                let resources = if burst {
                    vec![resource]
                } else {
                    (0..count).collect()
                };
                let (wire, events) =
                    mirror_tunnel(upload, response.into_body(), mode, resources, !burst).await;
                (binding.stream_id, mode, wire, events)
            });
        }
        while let Some(result) = jobs.join_next().await {
            let (id, mode, wire, stream_events) = result.unwrap();
            streams.push(json!({"id":id,"mode":mode.bits(),"server":record_summary(&wire,mode),"events":stream_events}));
            std::fs::write(directory.join(format!("stream-{id}.bin")), wire).unwrap();
        }
    } else {
        let mut jobs = tokio::task::JoinSet::new();
        for resource in 0..count {
            if !burst && (resource == 2 || (long && resource % 4 == 2)) {
                let started = unix_us();
                tokio::time::sleep(Duration::from_secs(if long { 2 } else { 1 })).await;
                events
                    .push(json!({"event":"idle","start_unix_us":started,"end_unix_us":unix_us()}));
            }
            let id = client.next_id;
            let started = unix_us();
            let (response, _) = client
                .send_request(
                    http::Request::builder()
                        .uri(format!("https://proxy.example.test/resource/{resource}"))
                        .header("accept", "application/octet-stream")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let job = async move {
                let response = response.await.unwrap();
                assert_eq!(response.status(), 200);
                let received = body(response.into_body()).await;
                assert_eq!(received, page(mirror_size(resource)));
                json!({"id":id,"resource":resource,"payload_bytes":received.len(),"status":200,"start_unix_us":started,"end_unix_us":unix_us()})
            };
            if burst {
                jobs.spawn(job);
            } else {
                streams.push(job.await);
            }
        }
        while let Some(result) = jobs.join_next().await {
            streams.push(result.unwrap());
        }
    }
    assert_eq!(stats.h2_connections.load(Ordering::Relaxed), 1);
    let dials = stats.dials.load(Ordering::Relaxed);
    assert_eq!(
        dials,
        if tunnel {
            if burst { count } else { 1 }
        } else {
            0
        }
    );
    assert_eq!(
        requests.load(Ordering::Relaxed),
        count + usize::from(origin_h2)
    );
    if !burst || origin_h2 {
        assert_eq!(connections.load(Ordering::Relaxed), 1);
    }
    driver.abort();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    let result = json!({"scenario":scenario,"tcp_udp_port":port,"start_unix_us":started,"end_unix_us":unix_us(),"transport_connections":1,"target_dials":dials,"mirror_upstream_connections":connections.load(Ordering::Relaxed),"mirror_requests":count + usize::from(origin_h2),"mirror_origin_h2":origin_h2,"warmup_requests":usize::from(origin_h2),"streams":streams,"events":events,"synthetic_resources":MIRROR_SIZES,"client":"test-only BoringSSL/h2; not Chromium","tunnel_inner_protocol":"HTTP/1.1 (not inner TLS)","certificate":certificate,"idle_gap_ms":if burst {0}else if long {2000}else{1000},"configured_idle_timeout_secs":f.config.limits.idle_timeout_secs,"upload_padding":"zero in reference client","private_keys_saved":false});
    std::fs::write(
        directory.join("workload.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!(
        "MOON_NAIVE_CAPTURE {}",
        serde_json::to_string(&result).unwrap()
    );
}

fn mirror_reply(resource: usize) -> http::Response<Bytes> {
    let bytes = page(mirror_size(resource));
    http::Response::builder()
        .status(200)
        .header("content-type", "application/octet-stream")
        .header("content-length", bytes.len())
        .header("cache-control", "public, max-age=3600")
        .header("etag", format!("\"resource-{resource}\""))
        .body(Bytes::from(bytes))
        .unwrap()
}

// A single authenticated duplex channel, including idle gaps, for a bounded
// wall-clock duration. Payloads are verified incrementally, not just at EOF.
async fn soak_capture(directory: &Path, scenario: &str) {
    let seconds = std::env::var("MOON_NAIVE_CAPTURE_SOAK_SECS")
        .ok()
        .map(|v| v.parse::<u64>().unwrap())
        .unwrap_or(120);
    assert!((1..=300).contains(&seconds));
    let (mut f, certificate) = capture_fixture();
    Arc::get_mut(&mut f.config)
        .unwrap()
        .limits
        .idle_timeout_secs = 10;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        socket.set_nodelay(true).unwrap();
        let mut data = [0u8; 4096];
        loop {
            let n = socket.read(&mut data).await.unwrap();
            if n == 0 {
                break;
            }
            socket.write_all(&data[..n]).await.unwrap();
        }
        socket.shutdown().await.unwrap();
    });
    let mut server = network(&f, Some(address)).await;
    server.tcp = TcpListener::bind("127.0.0.1:18443").await.unwrap();
    let address = server.tcp_addr().unwrap();
    server.udp = UdpSocket::bind(address).await.unwrap();
    let stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let keylog = directory.join("tls.keys");
    std::fs::copy(&f.ca, directory.join("ca.pem")).unwrap();
    let credentials = Credentials::new(&[("alice", "long-loopback-test-password")]).unwrap();
    let offer = Offer::from_bits(2).unwrap();
    let mut tcp = None;
    let mut quic = None;
    let mut tcp_driver = None;
    let (id, mode) = if scenario.starts_with("h2") {
        let (mut client, driver) = h2_capture(address, &f.ca, &keylog).await;
        let binding = Binding {
            exporter: client.exporter,
            stream_id: client.next_id,
        };
        let proof = credentials
            .authorization_with(0, &context(&binding), offer)
            .unwrap();
        let (response, upload) = client
            .send_request(
                http::Request::builder()
                    .method("CONNECT")
                    .uri(TARGET)
                    .header("proxy-authorization", proof)
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        let mode = credentials
            .verify_selection(
                0,
                &context(&binding),
                offer,
                response.headers()["proxy-authentication-info"]
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
        tcp = Some((upload, response.into_body()));
        tcp_driver = Some((client, driver));
        (binding.stream_id, mode)
    } else {
        let mut client = h3_capture(address, &f.ca, &keylog).await;
        let binding = Binding {
            exporter: super::super::exporter(client.conn.as_mut()).unwrap(),
            stream_id: client.next_id,
        };
        let proof = credentials
            .authorization_with(0, &context(&binding), offer)
            .unwrap();
        let id = client.request("CONNECT", TARGET, None, Some(&proof), false, false);
        let end = std::time::Instant::now() + io_timeout();
        while client.responses.get(&id).is_none_or(|r| r.status == 0) {
            assert!(std::time::Instant::now() < end);
            client.step().await;
        }
        let response = &client.responses[&id];
        assert_eq!(response.status, 200);
        let mode = credentials
            .verify_selection(
                0,
                &context(&binding),
                offer,
                response.headers["proxy-authentication-info"]
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
        quic = Some(client);
        (id, mode)
    };
    let mut encoder = Encoder::new(mode);
    let mut decoder = Decoder::new(mode);
    let mut wire = Vec::new();
    let mut events = Vec::new();
    let mut resources = Vec::new();
    let started = unix_us();
    let clock = std::time::Instant::now();
    let mut count = 0u64;
    let mut total = 0;
    while clock.elapsed() < Duration::from_secs(seconds) {
        let mut payload = page(1024);
        payload[..8].copy_from_slice(&count.to_be_bytes());
        let bytes = encoder.encode(&payload, 0).unwrap();
        let sent = unix_us();
        if let Some((upload, _)) = &mut tcp {
            v2_send(upload, Bytes::from(bytes), false).await;
        } else {
            quic.as_mut().unwrap().send_part(id, &bytes, false).await;
        }
        let end = std::time::Instant::now() + io_timeout();
        let mut decoded = Vec::new();
        while decoded.len() < payload.len() {
            assert!(std::time::Instant::now() < end, "soak response stalled");
            let bytes = if let Some((_, body)) = &mut tcp {
                let bytes = tokio::time::timeout(io_timeout(), body.data())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                body.flow_control().release_capacity(bytes.len()).unwrap();
                bytes.to_vec()
            } else {
                let client = quic.as_mut().unwrap();
                client.step().await;
                let response = client.responses.get_mut(&id).unwrap();
                assert!(!response.reset && !response.finished);
                std::mem::take(&mut response.body)
            };
            decoded.extend(decoder.feed(&bytes).unwrap());
            wire.extend(bytes);
        }
        assert_eq!(decoded, payload);
        total += payload.len();
        count += 1;
        events.push(json!({"sequence":count,"round_trip_us":unix_us()-sent}));
        if count % 40 == 1 {
            let memory = std::fs::read_to_string("/proc/self/status")
                .unwrap_or_default()
                .lines()
                .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            resources.push(
                json!({"elapsed_ms":clock.elapsed().as_millis(),"memory":memory,
                "fds":std::fs::read_dir("/proc/self/fd").map(|v|v.count()).ok(),
                "active_streams":stats.streams.load(Ordering::Relaxed),
                "h3_driver_iterations":stats.h3_driver_iterations.load(Ordering::Relaxed)}),
            );
        }
        if let Some(client) = &mut quic {
            let until = std::time::Instant::now() + Duration::from_millis(250);
            while std::time::Instant::now() < until {
                client.step().await;
            }
        } else {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    let mut quic_path = None;
    if let Some((mut upload, mut body)) = tcp {
        upload.send_data(Bytes::new(), true).unwrap();
        while let Some(bytes) = tokio::time::timeout(io_timeout(), body.data())
            .await
            .unwrap()
        {
            let bytes = bytes.unwrap();
            assert!(decoder.feed(&bytes).unwrap().is_empty());
            wire.extend_from_slice(&bytes);
            body.flow_control().release_capacity(bytes.len()).unwrap();
        }
    } else {
        let client = quic.as_mut().unwrap();
        client.send_part(id, &[], true).await;
        let response = client.response(id).await;
        assert!(!response.reset);
        assert!(decoder.feed(&response.body).unwrap().is_empty());
        wire.extend(response.body);
        quic_path=client.conn.path_stats().next().map(|p|json!({"client_rtt_us":p.rtt.as_micros(),"client_lost_packets":p.lost,"client_pto":p.total_pto_count}));
        client.conn.close(true, 0, b"soak complete").unwrap();
        client.step().await;
    }
    decoder.finish().unwrap();
    origin.await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while stats.streams.load(Ordering::Relaxed) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let finished = unix_us();
    let dials = stats.dials.load(Ordering::Relaxed);
    assert_eq!(dials, 1);
    if let Some((_, driver)) = tcp_driver {
        driver.abort();
    }
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    std::fs::write(directory.join(format!("stream-{id}.bin")), &wire).unwrap();
    let result = json!({"scenario":scenario,"tcp_udp_port":18443,"certificate":certificate,"start_unix_us":started,"end_unix_us":unix_us(),
        "transfer_start_unix_us":started,"transfer_end_unix_us":finished,"transport_connections":1,"target_dials":dials,
        "streams":[{"id":id,"mode":2,"server":record_summary(&wire,mode),"payload_bytes":total,"status":200}],
        "round_trips":count,"events":events,"resources":resources,"quic_path":quic_path,
        "h3_driver_iterations":stats.h3_driver_iterations.load(Ordering::Relaxed),"active_streams_after":0,
        "client":"test-only BoringSSL/h2/quiche; not Chromium","private_keys_saved":false});
    std::fs::write(
        directory.join("workload.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
}
