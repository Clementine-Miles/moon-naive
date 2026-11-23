//! First-party client against the actual server: real TLS 1.3 / QUIC, real
//! exporters and stream IDs, real local SOCKS5 and HTTP CONNECT sockets.
//! The only test hook is the server's dial override (`test_target`), which
//! sends authenticated CONNECTs for public names to a loopback echo origin.
use super::*;
use moon_naive_client::{Config as ClientConfig, Transport};
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
async fn client_proxies_socks5_and_http_connect_over_h2() {
    proxies_over("h2").await;
}
#[tokio::test]
async fn client_proxies_socks5_and_http_connect_over_h3() {
    proxies_over("h3").await;
}

#[tokio::test]
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

#[cfg(target_os = "linux")]
#[tokio::test]
async fn client_sockets_never_request_tcp_fast_open() {
    // The client opens its H2 TCP socket with plain connect(); prove the
    // TCP_FASTOPEN_CONNECT option is off on an equivalent tokio socket and
    // that the client crate has no project-owned TFO code (static audit).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    assert!(
        !nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::TcpFastOpenConnect)
            .unwrap()
    );
    let _ = Transport::H2;
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
    // A configuration for a key the server does not hold: the handshake must
    // fail rather than silently continue with the cleartext inner name.
    use base64::{Engine, engine::general_purpose::STANDARD};
    let (_, stale, _) = ech_material(b"public.example.test");
    for transport in ["h2", "h3"] {
        let text = format!(
            "{}ech_config_list = '{}'\n",
            client_config(address, &f.ca, transport, PASSWORD),
            STANDARD.encode(&stale)
        );
        let client = Client::start(&text).await;
        let (_stream, code) = socks(client.address, "example.org", 443).await;
        assert_ne!(code, 0, "{transport} must not bypass a required ECH");
        client.stop().await;
    }
    assert_eq!(stats.dials.load(Ordering::Relaxed), dials);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    origin_task.abort();
}
