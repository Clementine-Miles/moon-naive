//! Interop: the first-party client, carried by the Chromium native engine
//! (`libmoon_engine`), against the actual server. Real Chromium TLS 1.3 / QUIC
//! on the client, real Pingora/quiche on the server, real exporters and stream
//! IDs, real local SOCKS5 and HTTP CONNECT sockets.
//!
//! These tests need the engine library and are ignored by default. Run them
//! with `cargo xtask interop` (which builds or locates the library and sets
//! `MOON_NAIVE_ENGINE`).
//!
//! Server test hooks: the dial override (`test_target`), which sends
//! authenticated CONNECTs for public names to a loopback origin, and the
//! confirmation fault injection (`test_confirmation`).
use super::*;
use moon_naive_client::Config as ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PASSWORD: &str = "long-loopback-test-password";

/// Echo origin with half-close: echoes until EOF, then shuts down its writer.
async fn echo_origin() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut reader, mut writer) = socket.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
                let _ = writer.shutdown().await;
            });
        }
    });
    (address, task)
}

/// Like `network`, but TCP and UDP share one port, as in a real deployment
/// where a client reaches H2 and H3 at the same `host:port`.
async fn network_same_port(f: &Fixture, target: std::net::SocketAddr) -> Network {
    for _ in 0..32 {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        let Ok(tcp) = TcpListener::bind(("127.0.0.1", port)).await else {
            continue;
        };
        let mut server = network(f, Some(target)).await;
        server.tcp = Some(tcp);
        server.udp = Some(udp);
        return server;
    }
    panic!("no shared TCP/UDP loopback port");
}

struct Client {
    address: std::net::SocketAddr,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<(), String>>,
}
impl Client {
    async fn start(text: &str) -> Self {
        let settings = ClientConfig::parse(text).unwrap().settings().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(moon_naive_client::serve(
            Arc::new(settings),
            listener,
            shutdown,
        ));
        Self {
            address,
            stop,
            task,
        }
    }
    async fn stop(self) {
        self.stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
fn client_config(
    server: std::net::SocketAddr,
    ca: &std::path::Path,
    transport: &str,
    password: &str,
) -> String {
    format!(
        "server = '{server}'\nserver_name = 'proxy.example.test'\nusername = 'alice'\npassword = '{password}'\ntransport = '{transport}'\nca_file = '{}'\nconnect_timeout_secs = 5\nlog_level = 'error'\n",
        ca.display()
    )
}

/// SOCKS5 CONNECT to a domain target; returns the stream and the reply code.
async fn socks(client: std::net::SocketAddr, host: &str, port: u16) -> (TcpStream, u8) {
    let mut stream = TcpStream::connect(client).await.unwrap();
    let mut request = vec![5, 1, 0, 5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 12];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply[..2], [5, 0], "method selection");
    (stream, reply[3])
}

/// Upload `size` bytes, half-close, and expect the identical echo then EOF.
async fn echo_round_trip(mut stream: TcpStream, size: usize, seed: u8) {
    let payload: Vec<u8> = (0..size)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect();
    let (mut reader, mut writer) = stream.split();
    let upload = async {
        for chunk in payload.chunks(37_000) {
            writer.write_all(chunk).await.unwrap();
        }
        writer.shutdown().await.unwrap();
    };
    let download = async {
        let mut received = Vec::with_capacity(size);
        reader.read_to_end(&mut received).await.unwrap();
        received
    };
    let ((), received) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(upload, download)
    })
    .await
    .expect("echo round trip deadline");
    assert_eq!(received.len(), payload.len());
    assert!(received == payload, "payload corrupted");
}

async fn proxies_over(transport: &str) {
    let f = fixture();
    let (origin, origin_task) = echo_origin().await;
    let server = network_same_port(&f, origin).await;
    let address = server.tcp_addr().unwrap();
    let stats = server.stats.clone();
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown));
    let client = Client::start(&client_config(address, &f.ca, transport, PASSWORD)).await;

    // Small, large and concurrent tunnels on one shared connection.
    let (stream, code) = socks(client.address, "example.org", 443).await;
    assert_eq!(code, 0);
    echo_round_trip(stream, 5, 1).await;
    let (stream, code) = socks(client.address, "example.org", 443).await;
    assert_eq!(code, 0);
    echo_round_trip(stream, 3 * 1024 * 1024 + 17, 2).await;
    let mut jobs = tokio::task::JoinSet::new();
    for index in 0..6u8 {
        let local = client.address;
        jobs.spawn(async move {
            let (stream, code) = socks(local, "example.org", 443).await;
            assert_eq!(code, 0);
            echo_round_trip(stream, 200_000 + usize::from(index) * 4099, index).await;
        });
    }
    while let Some(job) = jobs.join_next().await {
        job.unwrap();
    }
    // HTTP CONNECT front end on the same listener.
    let mut stream = TcpStream::connect(client.address).await.unwrap();
    stream
        .write_all(b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n")
        .await
        .unwrap();
    let expected = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    let mut head = vec![0u8; expected.len()];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head, expected);
    echo_round_trip(stream, 100_000, 9).await;

    let (connections, dials) = if transport == "h3" {
        (
            stats.h3_connections.load(Ordering::Relaxed),
            stats.dials.load(Ordering::Relaxed),
        )
    } else {
        (
            stats.h2_connections.load(Ordering::Relaxed),
            stats.dials.load(Ordering::Relaxed),
        )
    };
    assert_eq!(connections, 1, "tunnels share one {transport} connection");
    assert_eq!(dials, 9);
    client.stop().await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    origin_task.abort();
}

#[tokio::test]
#[ignore = "interop: needs libmoon_engine; run with cargo xtask interop"]
async fn client_proxies_socks5_and_http_connect_over_h2() {
    proxies_over("h2").await;
}
#[tokio::test]
#[ignore = "interop: needs libmoon_engine; run with cargo xtask interop"]
async fn client_proxies_socks5_and_http_connect_over_h3() {
    proxies_over("h3").await;
}

#[tokio::test]
#[ignore = "interop: needs libmoon_engine; run with cargo xtask interop"]
async fn client_with_wrong_password_never_causes_a_dial() {
    let f = fixture();
    let (origin, origin_task) = echo_origin().await;
    let server = network_same_port(&f, origin).await;
    let address = server.tcp_addr().unwrap();
    let stats = server.stats.clone();
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown));
    for transport in ["h2", "h3"] {
        let client = Client::start(&client_config(
            address,
            &f.ca,
            transport,
            "a-different-but-long-password",
        ))
        .await;
        let (_stream, code) = socks(client.address, "example.org", 443).await;
        // The server routes unauthenticated CONNECT to its website, so the
        // client sees a non-200 answer and reports a general failure.
        assert_eq!(code, 0x01, "{transport}");
        client.stop().await;
    }
    assert_eq!(stats.dials.load(Ordering::Relaxed), 0);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    origin_task.abort();
}

#[tokio::test]
#[ignore = "interop: needs libmoon_engine; run with cargo xtask interop"]
async fn client_rejects_untrusted_server_certificate() {
    let f = fixture();
    let (origin, origin_task) = echo_origin().await;
    let server = network_same_port(&f, origin).await;
    let address = server.tcp_addr().unwrap();
    let stats = server.stats.clone();
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown));
    // A trust store without the fixture CA: the system store.
    for transport in ["h2", "h3"] {
        let text = client_config(address, &f.ca, transport, PASSWORD)
            .lines()
            .filter(|line| !line.starts_with("ca_file"))
            .collect::<Vec<_>>()
            .join("\n");
        let client = Client::start(&text).await;
        let (_stream, code) = socks(client.address, "example.org", 443).await;
        assert_ne!(code, 0, "{transport} must not trust an unknown CA");
        client.stop().await;
    }
    assert_eq!(stats.dials.load(Ordering::Relaxed), 0);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    origin_task.abort();
}

#[tokio::test]
#[ignore = "interop: needs libmoon_engine; run with cargo xtask interop"]
async fn h3_then_h2_falls_back_when_udp_is_unreachable() {
    let f = fixture();
    let (origin, origin_task) = echo_origin().await;
    let mut server = network(&f, Some(origin)).await;
    // TCP is reachable at this port; nothing answers UDP there.
    let tcp = server.tcp.take().unwrap();
    let address = tcp.local_addr().unwrap();
    server.tcp = Some(tcp);
    let stats = server.stats.clone();
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown));
    let mut text = client_config(address, &f.ca, "h3-then-h2", PASSWORD);
    text = text.replace("connect_timeout_secs = 5", "connect_timeout_secs = 2");
    let client = Client::start(&text).await;
    let (stream, code) = socks(client.address, "example.org", 443).await;
    assert_eq!(code, 0);
    echo_round_trip(stream, 50_000, 3).await;
    // During the cool-down, H2 is used immediately.
    let started = std::time::Instant::now();
    let (stream, code) = socks(client.address, "example.org", 443).await;
    assert_eq!(code, 0);
    assert!(started.elapsed() < Duration::from_secs(1));
    echo_round_trip(stream, 10, 4).await;
    assert_eq!(stats.h3_connections.load(Ordering::Relaxed), 0);
    assert_eq!(stats.h2_connections.load(Ordering::Relaxed), 1);
    client.stop().await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    origin_task.abort();
}

#[tokio::test]
#[ignore = "interop: needs libmoon_engine; run with cargo xtask interop"]
async fn client_reconnects_after_server_restart() {
    let f = fixture();
    let (origin, origin_task) = echo_origin().await;
    let server = network_same_port(&f, origin).await;
    let address = server.tcp_addr().unwrap();
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown));
    let clients = [
        Client::start(&client_config(address, &f.ca, "h2", PASSWORD)).await,
        Client::start(&client_config(address, &f.ca, "h3", PASSWORD)).await,
    ];
    for client in &clients {
        let (stream, code) = socks(client.address, "example.org", 443).await;
        assert_eq!(code, 0);
        echo_round_trip(stream, 1000, 5).await;
    }
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    // Restart on the same address; pooled connections are now dead.
    let mut server = network(&f, Some(origin)).await;
    server.tcp = Some(TcpListener::bind(address).await.unwrap());
    server.udp = Some(UdpSocket::bind(address).await.unwrap());
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown));
    for client in &clients {
        // The first attempt may observe the dead pooled connection; the
        // client then reconnects for subsequent requests.
        let mut opened = false;
        for _ in 0..3 {
            let (stream, code) = socks(client.address, "example.org", 443).await;
            if code == 0 {
                echo_round_trip(stream, 1000, 6).await;
                opened = true;
                break;
            }
        }
        assert!(opened, "client reconnected after server restart");
    }
    for client in clients {
        client.stop().await;
    }
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    origin_task.abort();
}

#[test]
fn client_has_no_transport_or_tfo_code_of_its_own() {
    // All proxy sockets are opened by Chromium's TCPClientSocket/UDP stack,
    // which never enables TCP Fast Open. Static audit: the client crate has
    // no HTTP/2, QUIC or TLS implementation and no socket options of its own.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("client");
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    for crate_name in ["quiche", "h2 ", "boring", "rustls", "tokio-boring"] {
        assert!(
            !manifest.contains(&format!("\n{crate_name}")),
            "client depends on {crate_name}"
        );
    }
    for entry in std::fs::read_dir(root.join("src")).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        let open = ["FAST", "OPEN"].concat();
        for forbidden in [
            format!("TCP_{open}"),
            format!("Tcp{}Open", "Fast"),
            format!("set_tcp_{}open", "fast"),
            "quiche::".to_owned(),
            "h2::".to_owned(),
        ] {
            assert!(
                !text.contains(&forbidden),
                "{}: {forbidden}",
                path.display()
            );
        }
    }
}

/// Configure server ECH like `ech_accepts_inner_name_and_preserves_plain_h2`
/// and return the Base64 ECHConfigList a client would be given.
fn enable_ech(f: &mut Fixture) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let (encoded, list, private) = ech_material(b"public.example.test");
    let root = f._root.path().to_owned();
    let keys = root.join("ech.toml");
    std::fs::write(
        &keys,
        format!(
            "[[keys]]\nconfig = '{}'\nprivate_key = '{}'\nretry = true\n",
            STANDARD.encode(&encoded),
            STANDARD.encode(private)
        ),
    )
    .unwrap();
    std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o600)).unwrap();
    let stored = DiskStore::open(&f.config.state_dir.join("certificates"))
        .unwrap()
        .read_current()
        .unwrap()
        .unwrap();
    let cert = root.join("public.pem");
    let key = root.join("public.key");
    std::fs::write(&cert, stored.candidate.chain_pem).unwrap();
    std::fs::write(&key, stored.candidate.key_pem).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    Arc::get_mut(&mut f.config).unwrap().ech = Some(moon_naive_core::config::Ech {
        keys_file: keys,
        public_name: "public.example.test".into(),
        certificate_file: cert,
        private_key_file: key,
    });
    STANDARD.encode(list)
}
/// (ECHConfig, ECHConfigList, HPKE private key) for a fresh X25519 key.
fn ech_material(name: &[u8]) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let hpke = PKey::generate(boring::pkey::Id::X25519).unwrap();
    let mut public = [0; 32];
    let mut private = [0; 32];
    hpke.raw_public_key(&mut public).unwrap();
    hpke.raw_private_key(&mut private).unwrap();
    let mut contents = vec![7, 0, 32, 0, 32];
    contents.extend_from_slice(&public);
    contents.extend_from_slice(&[0, 4, 0, 1, 0, 1, 64, name.len() as u8]);
    contents.extend_from_slice(name);
    contents.extend_from_slice(&[0, 0]);
    let mut encoded = vec![0xfe, 0x0d];
    encoded.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    encoded.extend(contents);
    let mut list = (encoded.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&encoded);
    (encoded, list, private)
}

#[tokio::test]
#[ignore = "interop: needs libmoon_engine; run with cargo xtask interop"]
async fn client_ech_is_accepted_on_h2_and_h3_and_never_bypassed() {
    let mut f = fixture();
    let ech = enable_ech(&mut f);
    let (origin, origin_task) = echo_origin().await;
    let server = network_same_port(&f, origin).await;
    let address = server.tcp_addr().unwrap();
    let stats = server.stats.clone();
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown));
    for transport in ["h2", "h3"] {
        let text = format!(
            "{}ech_config_list = '{ech}'\n",
            client_config(address, &f.ca, transport, PASSWORD)
        );
        let client = Client::start(&text).await;
        let (stream, code) = socks(client.address, "example.org", 443).await;
        assert_eq!(code, 0, "{transport} with accepted ECH");
        echo_round_trip(stream, 70_000, 7).await;
        client.stop().await;
    }
    let dials = stats.dials.load(Ordering::Relaxed);
    assert_eq!(dials, 2);
    // A configuration for a key the server does not hold. The server rejects
    // ECH and returns its retry configs inside the handshake authenticated by
    // the public name's certificate; Chromium (strict ECH) retries once with
    // them. A tunnel may therefore open, but only on a connection that
    // accepted ECH: the client refuses to sign a CONNECT on any connection
    // without accepted ECH, so the inner name is never sent in cleartext.
    use base64::{Engine, engine::general_purpose::STANDARD};
    let (_, stale, _) = ech_material(b"public.example.test");
    for transport in ["h2", "h3"] {
        let text = format!(
            "{}ech_config_list = '{}'\n",
            client_config(address, &f.ca, transport, PASSWORD),
            STANDARD.encode(&stale)
        );
        let client = Client::start(&text).await;
        let (stream, code) = socks(client.address, "example.org", 443).await;
        if transport == "h2" {
            assert_eq!(code, 0, "h2 recovers through ECH retry configs");
            echo_round_trip(stream, 1000, 8).await;
        } else {
            // Chromium's QUIC client does not retry with ECH retry configs at
            // this revision: H3 fails closed instead.
            assert_ne!(code, 0, "h3 must not bypass a required ECH");
        }
        client.stop().await;
    }
    let dials = dials + 1;
    assert_eq!(stats.dials.load(Ordering::Relaxed), dials);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    origin_task.abort();
}

/// Loopback throughput of the full client→server→origin path. Run with:
/// cargo xtask interop --release --bench
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement; run explicitly in release mode with the engine"]
async fn client_throughput_benchmark() {
    const SIZE: usize = 64 * 1024 * 1024;
    for transport in ["h2", "h3"] {
        let mut f = fixture();
        let config = Arc::get_mut(&mut f.config).unwrap();
        config.limits.idle_timeout_secs = 60;
        let (origin, origin_task) = echo_origin().await;
        let server = network_same_port(&f, origin).await;
        let address = server.tcp_addr().unwrap();
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(server.run(shutdown));
        let client = Client::start(&client_config(address, &f.ca, transport, PASSWORD)).await;
        for run in 0..3 {
            let (stream, code) = socks(client.address, "example.org", 443).await;
            assert_eq!(code, 0);
            let started = std::time::Instant::now();
            echo_round_trip(stream, SIZE, run).await;
            let seconds = started.elapsed().as_secs_f64();
            // Bytes cross the tunnel twice (upload and echoed download).
            println!(
                "client_throughput transport={transport} run={run} bytes_each_way={SIZE} seconds={seconds:.3} mbit_per_s_each_way={:.1}",
                SIZE as f64 * 8.0 / seconds / 1e6
            );
        }
        client.stop().await;
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
        origin_task.abort();
    }
}

/// Origin that counts every byte it receives and echoes nothing.
async fn counting_origin() -> (
    std::net::SocketAddr,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = received.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while let Ok(n) = socket.read(&mut buffer).await {
                    if n == 0 {
                        break;
                    }
                    counter.fetch_add(n, Ordering::SeqCst);
                }
            });
        }
    });
    (address, received, task)
}

/// Invalid confirmations (missing, duplicated, wrong MAC) never establish a
/// tunnel and never let payload reach the target; the same client then
/// recovers on the same pooled connection once confirmations are valid.
async fn invalid_confirmation_then_recovery(transport: &str) {
    let f = fixture();
    let (origin, received, origin_task) = counting_origin().await;
    let server = network_same_port(&f, origin).await;
    let address = server.tcp_addr().unwrap();
    let fault = server.app.egress.test_confirmation.clone();
    let stats = server.stats.clone();
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown));
    let client = Client::start(&client_config(address, &f.ca, transport, PASSWORD)).await;
    for injected in [
        egress::TEST_CONFIRMATION_MISSING,
        egress::TEST_CONFIRMATION_DUPLICATE,
        egress::TEST_CONFIRMATION_CORRUPT,
    ] {
        fault.store(injected, Ordering::SeqCst);
        let (mut stream, code) = socks(client.address, "example.org", 443).await;
        assert_ne!(code, 0, "{transport}: fault {injected} must not open");
        // Anything the application sends now must never reach the target.
        let _ = stream.write_all(b"must-not-arrive").await;
        drop(stream);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "{transport}: payload leaked"
    );
    assert_eq!(stats.dials.load(Ordering::Relaxed), 3);
    fault.store(egress::TEST_CONFIRMATION_VALID, Ordering::SeqCst);
    let (mut stream, code) = socks(client.address, "example.org", 443).await;
    assert_eq!(code, 0, "{transport}: recovery");
    stream.write_all(b"0123456789").await.unwrap();
    stream.shutdown().await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while received.load(Ordering::SeqCst) < 10 {
        assert!(
            std::time::Instant::now() < deadline,
            "{transport}: payload after recovery"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(received.load(Ordering::SeqCst), 10);
    let connections = if transport == "h3" {
        stats.h3_connections.load(Ordering::Relaxed)
    } else {
        stats.h2_connections.load(Ordering::Relaxed)
    };
    assert_eq!(
        connections, 1,
        "{transport}: a stream failure keeps the connection"
    );
    client.stop().await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    origin_task.abort();
}

#[tokio::test]
#[ignore = "interop: needs libmoon_engine; run with cargo xtask interop"]
async fn invalid_confirmations_never_open_and_h2_recovers() {
    invalid_confirmation_then_recovery("h2").await;
}
#[tokio::test]
#[ignore = "interop: needs libmoon_engine; run with cargo xtask interop"]
async fn invalid_confirmations_never_open_and_h3_recovers() {
    invalid_confirmation_then_recovery("h3").await;
}

/// The target half-closes first: it greets, shuts down its writer, then keeps
/// reading. The client must deliver the greeting plus EOF and still carry its
/// own upload afterwards, then half-close in turn.
async fn half_close_both_directions(transport: &str) {
    let f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = listener.local_addr().unwrap();
    let (report, uploaded) = tokio::sync::oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"greeting").await.unwrap();
        socket.shutdown().await.unwrap();
        let mut received = Vec::new();
        socket.read_to_end(&mut received).await.unwrap();
        let _ = report.send(received);
    });
    let server = network_same_port(&f, origin).await;
    let address = server.tcp_addr().unwrap();
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown));
    let client = Client::start(&client_config(address, &f.ca, transport, PASSWORD)).await;
    let (mut stream, code) = socks(client.address, "example.org", 443).await;
    assert_eq!(code, 0);
    let mut greeting = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut greeting))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(greeting, b"greeting", "{transport}: download then EOF");
    // The read side is finished; the upload side still works.
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(20), uploaded)
        .await
        .unwrap()
        .unwrap();
    assert!(received == payload, "{transport}: upload after peer EOF");
    client.stop().await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    origin_task.await.unwrap();
}

#[tokio::test]
#[ignore = "interop: needs libmoon_engine; run with cargo xtask interop"]
async fn half_close_is_independent_per_direction_over_h2() {
    half_close_both_directions("h2").await;
}
#[tokio::test]
#[ignore = "interop: needs libmoon_engine; run with cargo xtask interop"]
async fn half_close_is_independent_per_direction_over_h3() {
    half_close_both_directions("h3").await;
}
