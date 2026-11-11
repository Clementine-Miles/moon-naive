use super::*;
use tokio::net::TcpStream;
mod acme_live;
mod evolution;
mod website;
use crate::acme::persist::DiskStore;
use boring::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    ssl::{SslConnector, SslMethod},
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use std::{os::unix::fs::PermissionsExt, path::PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) struct Fixture {
    _root: tempfile::TempDir,
    config: Arc<Config>,
    pub(super) ca: PathBuf,
    ca_key: PKey<Private>,
    ca_cert: X509,
    origin: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.origin.abort();
    }
}
fn key() -> PKey<Private> {
    crate::acme::crypto::p256().unwrap()
}
pub(super) fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let ca_key = key();
    let leaf_key = key();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "moon-naive loopback test CA")
        .unwrap();
    let name = name.build();
    let mut ca = X509::builder().unwrap();
    ca.set_version(2).unwrap();
    ca.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    ca.set_subject_name(&name).unwrap();
    ca.set_issuer_name(&name).unwrap();
    ca.set_pubkey(&ca_key).unwrap();
    ca.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    ca.set_not_after(&Asn1Time::days_from_now(90).unwrap())
        .unwrap();
    ca.append_extension(&BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    ca.append_extension(&KeyUsage::new().key_cert_sign().crl_sign().build().unwrap())
        .unwrap();
    ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca = ca.build();
    let mut subject = X509NameBuilder::new().unwrap();
    subject
        .append_entry_by_text("CN", "proxy.example.test")
        .unwrap();
    let subject = subject.build();
    let mut leaf = X509::builder().unwrap();
    leaf.set_version(2).unwrap();
    leaf.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    leaf.set_subject_name(&subject).unwrap();
    leaf.set_issuer_name(ca.subject_name()).unwrap();
    leaf.set_pubkey(&leaf_key).unwrap();
    leaf.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    leaf.set_not_after(&Asn1Time::days_from_now(60).unwrap())
        .unwrap();
    leaf.append_extension(&BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    leaf.append_extension(&ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    leaf.append_extension(
        &SubjectAlternativeName::new()
            .dns("proxy.example.test")
            .dns("public.example.test")
            .build(&leaf.x509v3_context(Some(&ca), None))
            .unwrap(),
    )
    .unwrap();
    leaf.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let leaf = leaf.build();
    let ca_file = root.path().join("ca.crt");
    std::fs::write(&ca_file, ca.to_pem().unwrap()).unwrap();
    let mut config = Config::parse(include_str!("../../config.example.toml")).unwrap();
    if let Ok(value) = std::env::var("MOON_NAIVE_TEST_QUIC_CONGESTION") {
        config.transport.quic_congestion = match value.as_str() {
            "cubic" => moon_naive_core::config::QuicCongestion::Cubic,
            "bbr2" => moon_naive_core::config::QuicCongestion::Bbr2,
            _ => panic!("invalid test congestion profile"),
        };
    }
    if std::env::var("MOON_NAIVE_TEST_TCP_CONGESTION").is_ok_and(|v| v == "bbr") {
        config.transport.tcp_congestion = moon_naive_core::config::TcpCongestion::Bbr;
    }
    super::congestion::check(&config).unwrap();
    config.website.upstreams.clear();
    config.website.routes.clear();
    config.domain = "proxy.example.test".into();
    config.acme.dns_zone = Some("example.test".into());
    config.proxy.users.clear();
    config.listener.h1 = false;
    config.listener.tcp = "127.0.0.1:8443".parse().unwrap();
    config.listener.udp = config.listener.tcp;
    config.state_dir = root.path().join("state");
    config.credentials_file = root.path().join("users.toml");
    let site_root = root.path().join("site");
    config.acme.certificate_ca_file = Some(ca_file.clone());
    config.limits.max_streams = 8;
    config.limits.idle_timeout_secs = 3;
    config.limits.graceful_timeout_secs = 1;
    std::fs::write(
        &config.credentials_file,
        b"[[users]]\nusername = 'alice'\npassword = 'long-loopback-test-password'\n",
    )
    .unwrap();
    std::fs::set_permissions(
        &config.credentials_file,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::create_dir(&site_root).unwrap();
    std::fs::write(
        site_root.join("index.html"),
        b"<!doctype html><title>moon-naive test site</title>",
    )
    .unwrap();
    let mut chain = leaf.to_pem().unwrap();
    chain.extend(ca.to_pem().unwrap());
    let candidate = crate::acme::certificate::Candidate {
        chain_pem: chain,
        key_pem: leaf_key.private_key_to_pem_pkcs8().unwrap(),
    };
    let bundle = crate::acme::certificate::Validator::for_config(&config)
        .unwrap()
        .verify(candidate, crate::acme::now())
        .unwrap();
    DiskStore::open(&config.state_dir.join("certificates"))
        .unwrap()
        .install(&bundle)
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(listener).unwrap();
    let content_root = site_root.clone();
    let origin = tokio::spawn(async move {
        let mut jobs = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = jobs.join_next(), if !jobs.is_empty() => {},
                accepted = listener.accept() => {
                    let (socket, _) = accepted.unwrap();
                    let content_root = content_root.clone();
                    jobs.spawn(async move {
                        let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                            let content_root = content_root.clone();
                            async move {
                                let path = request.uri().path();
                                let status = if path.contains("%2e") {400} else if matches!(path, "/" | "/probe.txt") {200} else {404};
                                let data = if status == 200 {
                                    tokio::fs::read(content_root.join(if path == "/" {"index.html"} else {"probe.txt"})).await.unwrap()
                                } else { b"Not Found".to_vec() };
                                let length = data.len();
                                let data = if request.method() == http::Method::HEAD {Vec::new()} else {data};
                                Ok::<_,std::convert::Infallible>(hyper::Response::builder().status(status).header("content-type","text/html; charset=utf-8").header("content-length",length).body(http_body_util::Full::new(Bytes::from(data))).unwrap())
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(socket), service).await;
                    });
                }
            }
        }
    });
    config
        .website
        .upstreams
        .push(moon_naive_core::website::Upstream {
            name: "fixture".into(),
            origins: vec![format!("http://{address}")],
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
    Fixture {
        _root: root,
        config: Arc::new(config),
        ca: ca_file,
        ca_key,
        ca_cert: ca,
        origin,
    }
}
pub(super) async fn network(f: &Fixture, target: Option<std::net::SocketAddr>) -> Network {
    // Port zero is deliberately test-only. Production Config rejects it.
    let mut app = App::load(&f.config).unwrap();
    app.egress.test_target = target;
    let stats = app.stats.clone();
    Network {
        redirect: None,
        app: Arc::new(app),
        tls: tls::Slot::load(&f.config).unwrap(),
        tcp: TcpListener::bind("127.0.0.1:0").await.unwrap(),
        udp: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        connections: Budget::new(8).unwrap(),
        config: f.config.clone(),
        stats,
    }
}
// The test client signs requests on the actual transport, exactly where a
// Chromium adapter must obtain its exporter and allocated stream ID.
const SIGN: &str = "moon-naive test-client-sign-this-request";
fn auth() -> String {
    SIGN.into()
}
fn proof(
    binding: &moon_naive_core::auth::Binding,
    method: &str,
    authority: &str,
    scheme: Option<&str>,
    path: Option<&str>,
    protocol: Option<&str>,
) -> String {
    Credentials::new(&[("alice", "long-loopback-test-password")])
        .unwrap()
        .authorization(
            0,
            &moon_naive_core::auth::Context {
                binding,
                method,
                authority,
                scheme,
                path,
                protocol,
            },
        )
        .unwrap()
}
fn frame(payload: &[u8]) -> Bytes {
    Bytes::from(
        moon_naive_core::codec::Encoder::default()
            .encode(payload, 0)
            .unwrap(),
    )
}
fn unframe(wire: &[u8]) -> Vec<u8> {
    let mut decoder = moon_naive_core::codec::Decoder::default();
    let out = decoder.feed(wire).unwrap();
    decoder.finish().unwrap();
    out
}
struct H2Client {
    sender: ::h2::client::SendRequest<Bytes>,
    exporter: [u8; 32],
    next_id: u64,
    last_proof: Option<String>,
}
impl H2Client {
    fn send_request(
        &mut self,
        mut request: http::Request<()>,
        fin: bool,
    ) -> std::result::Result<(::h2::client::ResponseFuture, ::h2::SendStream<Bytes>), ::h2::Error>
    {
        if request
            .headers()
            .get("proxy-authorization")
            .is_some_and(|v| v == SIGN)
        {
            let binding = moon_naive_core::auth::Binding {
                exporter: self.exporter,
                stream_id: self.next_id,
            };
            let auth = proof(
                &binding,
                request.method().as_str(),
                request.uri().authority().map(|v| v.as_str()).unwrap_or(""),
                request.uri().scheme_str(),
                request.uri().path_and_query().map(|v| v.as_str()),
                request
                    .extensions()
                    .get::<::h2::ext::Protocol>()
                    .map(|v| v.as_str()),
            );
            self.last_proof = Some(auth.clone());
            // Preserve duplicates: they must still fail server authentication.
            let count = request
                .headers()
                .get_all("proxy-authorization")
                .iter()
                .count();
            request.headers_mut().remove("proxy-authorization");
            for _ in 0..count {
                let mut value = http::HeaderValue::from_str(&auth).unwrap();
                value.set_sensitive(true);
                request.headers_mut().append("proxy-authorization", value);
            }
        }
        let result = self.sender.send_request(request, fin)?;
        assert_eq!(u64::from(result.1.stream_id().as_u32()), self.next_id);
        self.next_id += 2;
        Ok(result)
    }
}
async fn h2_client(
    address: std::net::SocketAddr,
    ca: &std::path::Path,
) -> (H2Client, tokio::task::JoinHandle<()>) {
    let mut tls = SslConnector::builder(SslMethod::tls()).unwrap();
    tls.set_ca_file(ca).unwrap();
    tls.set_alpn_protos(b"\x02h2").unwrap();
    let io = tokio_boring::connect(
        tls.build().configure().unwrap(),
        "proxy.example.test",
        TcpStream::connect(address).await.unwrap(),
    )
    .await
    .unwrap();
    let exporter = super::exporter(io.ssl()).unwrap();
    let (sender, connection) = ::h2::client::Builder::new()
        .initial_window_size(4096)
        .initial_connection_window_size(8192)
        .handshake(io)
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    (
        H2Client {
            sender,
            exporter,
            next_id: 1,
            last_proof: None,
        },
        task,
    )
}
async fn body(mut body: ::h2::RecvStream) -> Vec<u8> {
    let mut result = Vec::new();
    while let Some(data) = tokio::time::timeout(Duration::from_secs(5), body.data())
        .await
        .unwrap()
    {
        let data = data.unwrap();
        body.flow_control().release_capacity(data.len()).unwrap();
        result.extend(data);
    }
    result
}
#[tokio::test]
async fn real_h2_serves_site_with_forced_tls12_and_tls13() {
    use boring::ssl::SslVersion;
    let fixture = fixture();
    let server = network(&fixture, None).await;
    let address = server.tcp_addr().unwrap();
    let stats = server.stats.clone();
    let (stop, receive) = watch::channel(false);
    let task = tokio::spawn(server.run(receive));
    for (version, name) in [
        (SslVersion::TLS1_2, "TLSv1.2"),
        (SslVersion::TLS1_3, "TLSv1.3"),
    ] {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_ca_file(&fixture.ca).unwrap();
        connector.set_alpn_protos(b"\x02h2").unwrap();
        connector.set_min_proto_version(Some(version)).unwrap();
        connector.set_max_proto_version(Some(version)).unwrap();
        let stream = tokio::time::timeout(
            Duration::from_secs(3),
            tokio_boring::connect(
                connector.build().configure().unwrap(),
                "proxy.example.test",
                TcpStream::connect(address).await.unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stream.ssl().version_str(), name);
        assert_eq!(
            stream.ssl().selected_alpn_protocol(),
            Some(b"h2".as_slice())
        );
        let (mut client, connection) = ::h2::client::handshake(stream).await.unwrap();
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = http::Request::builder()
            .uri("https://proxy.example.test/")
            .body(())
            .unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            body(response.into_body())
                .await
                .starts_with(b"<!doctype html>")
        );
        connection.abort();
    }
    assert_eq!(stats.dials.load(Ordering::Relaxed), 0);
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
}
#[tokio::test]
async fn real_h2_tls_site_auth_padding_half_close_and_no_early_success() {
    let fixture = fixture();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = origin.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = origin.accept().await.unwrap();
            tokio::spawn(async move {
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await.unwrap();
                stream.write_all(&data).await.unwrap();
                stream.shutdown().await.unwrap();
            });
        }
    });
    let server = network(&fixture, Some(target)).await;
    let address = server.tcp_addr().unwrap();
    let stats = server.stats.clone();
    let permits = server.connections.clone();
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown));
    let (mut client, connection) = h2_client(address, &fixture.ca).await;
    let request = http::Request::builder()
        .uri("https://proxy.example.test/")
        .body(())
        .unwrap();
    let (response, _) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("padding"));
    let expected = body(response.into_body()).await;
    assert!(expected.starts_with(b"<!doctype html>"));
    let request = http::Request::builder()
        .method("CONNECT")
        .uri("example.org:443")
        .header("proxy-authorization", "Basic wrong")
        .body(())
        .unwrap();
    let (response, _pending_upload) = client.send_request(request, false).unwrap();
    assert_eq!(response.await.unwrap().status(), 404);
    assert_eq!(stats.dials.load(Ordering::Relaxed), 0);
    for padded in [false, true] {
        let mut request = http::Request::builder()
            .method("CONNECT")
            .uri("example.org:443")
            .header("proxy-authorization", auth());
        if padded {
            request = request.header("padding", "~");
        }
        let (response, mut upload) = client
            .send_request(request.body(()).unwrap(), false)
            .unwrap();
        let payload = vec![b'x'; 100_000];
        let mut encoder = moon_naive_core::codec::Encoder::default();
        let mut wire = Vec::new();
        for chunk in payload.chunks(11000) {
            wire.extend(encoder.encode(chunk, 7).unwrap());
        }
        // Client is permitted to send DATA before receiving 200.
        let send = tokio::spawn(async move {
            v2_send(&mut upload, Bytes::from(wire), true).await;
        });
        let response = tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(!response.headers().contains_key("padding"));
        assert_eq!(
            response.headers()["proxy-authentication-info"]
                .as_bytes()
                .len(),
            58
        );
        assert!(!response.headers().contains_key("content-length"));
        let received = body(response.into_body()).await;
        send.await.unwrap();
        let result = {
            let mut decoder = moon_naive_core::codec::Decoder::default();
            let data = decoder.feed(&received).unwrap();
            decoder.finish().unwrap();
            data
        };
        assert_eq!(result, payload);
    }
    assert_eq!(stats.dials.load(Ordering::Relaxed), 2);
    assert_eq!(stats.resolutions.load(Ordering::Relaxed), 0);
    let request = http::Request::builder()
        .method("CONNECT")
        .uri("example.org:443")
        .body(())
        .unwrap();
    let (response, _) = client.send_request(request, true).unwrap();
    assert_eq!(response.await.unwrap().status(), 404);
    assert_eq!(stats.dials.load(Ordering::Relaxed), 2);
    connection.abort();
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
    echo.abort();
    assert_eq!(permits.active(), 0);
    assert_eq!(stats.streams.load(Ordering::Relaxed), 0);
    // Failed connect must produce a failure response, never an early 200.
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed = reservation.local_addr().unwrap();
    drop(reservation);
    let server = network(&fixture, Some(closed)).await;
    let addr = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut client, connection) = h2_client(addr, &fixture.ca).await;
    let request = http::Request::builder()
        .method("CONNECT")
        .uri("example.org:443")
        .header("proxy-authorization", auth())
        .body(())
        .unwrap();
    let (response, _) = client.send_request(request, false).unwrap();
    assert_eq!(response.await.unwrap().status(), 502);
    connection.abort();
    let mut client = QClient::new(udp, &fixture.ca).await;
    let id = client.request(
        "CONNECT",
        "example.org:443",
        None,
        Some(&auth()),
        false,
        false,
    );
    assert_eq!(client.response(id).await.status, 502);
    let _ = client.conn.close(true, 0x100, b"");
    client.step().await;
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
}
async fn v2_send(send: &mut ::h2::SendStream<Bytes>, bytes: Bytes, fin: bool) {
    pingora_core::protocols::http::v2::write_body(send, bytes, fin, Some(Duration::from_secs(5)))
        .await
        .unwrap();
}

#[tokio::test]
async fn real_h2_rejects_h1_absent_alpn_private_targets_and_site_traversal() {
    let fixture = fixture();
    let server = network(&fixture, None).await;
    let addr = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    for alpn in [Some(b"\x08http/1.1".as_slice()), None] {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_ca_file(&fixture.ca).unwrap();
        if let Some(alpn) = alpn {
            connector.set_alpn_protos(alpn).unwrap();
        }
        if let Ok(mut stream) = tokio_boring::connect(
            connector.build().configure().unwrap(),
            "proxy.example.test",
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        {
            let _ = stream
                .write_all(b"GET / HTTP/1.1\r\nHost: proxy.example.test\r\n\r\n")
                .await;
            let mut byte = [0; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
                .await
                .unwrap();
            assert!(read.is_err() || read.unwrap() == 0);
        }
    }
    let (mut client, connection) = h2_client(addr, &fixture.ca).await;
    for ip in [
        "127.0.0.1:80",
        "169.254.169.254:80",
        "[::1]:80",
        "proxy.example.test:443",
        "localhost:80",
    ] {
        let req = http::Request::builder()
            .method("CONNECT")
            .uri(ip)
            .header("proxy-authorization", auth())
            .body(())
            .unwrap();
        let (response, _) = client.send_request(req, false).unwrap();
        assert_eq!(response.await.unwrap().status(), 403);
    }
    assert_eq!(stats.dials.load(Ordering::Relaxed), 0);
    assert_eq!(stats.resolutions.load(Ordering::Relaxed), 1);
    let mut quic = QClient::new(udp, &fixture.ca).await;
    let id = quic.request("CONNECT", "127.0.0.1:80", None, Some(&auth()), false, false);
    assert_eq!(quic.response(id).await.status, 403);
    assert_eq!(stats.dials.load(Ordering::Relaxed), 0);
    let _ = quic.conn.close(true, 0x100, b"");
    quic.step().await;
    let req = http::Request::builder()
        .uri("https://proxy.example.test/%2e%2e/secret")
        .body(())
        .unwrap();
    let (response, _) = client.send_request(req, true).unwrap();
    assert_eq!(response.await.unwrap().status(), 400);
    let req = http::Request::builder()
        .method("HEAD")
        .uri("https://proxy.example.test/")
        .body(())
        .unwrap();
    let (response, _) = client.send_request(req, true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    assert!(body(response.into_body()).await.is_empty());
    connection.abort();
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
}

pub(super) struct QClient {
    socket: UdpSocket,
    server: std::net::SocketAddr,
    pub(super) conn: quiche::Connection,
    pub(super) h3: Option<quiche::h3::Connection>,
    next_id: u64,
    responses: std::collections::HashMap<u64, QResponse>,
    read_limit: usize,
    replay_packets: bool,
    io_timeout: Duration,
}
#[derive(Default)]
struct QResponse {
    headers: http::HeaderMap,
    status: u16,
    body: Vec<u8>,
    finished: bool,
    padding: bool,
    content_length: bool,
    reset: bool,
}
impl QClient {
    async fn initial(server: std::net::SocketAddr, ca: &std::path::Path) -> Self {
        Self::initial_with_keylog(server, ca, None).await
    }
    async fn initial_with_keylog(
        server: std::net::SocketAddr,
        ca: &std::path::Path,
        keylog: Option<&std::path::Path>,
    ) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        if keylog.is_some() {
            config.log_keys();
        }
        config.verify_peer(true);
        config
            .load_verify_locations_from_file(ca.to_str().unwrap())
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_max_idle_timeout(30000);
        config.set_max_recv_udp_payload_size(1350);
        config.set_max_send_udp_payload_size(1350);
        // Key logging is observation only: retain the same small receive windows.
        let stream_window = 65536;
        config.set_initial_max_data(1024 * 1024);
        config.set_initial_max_stream_data_bidi_local(stream_window);
        config.set_initial_max_stream_data_bidi_remote(stream_window);
        config.set_initial_max_stream_data_uni(65536);
        config.set_initial_max_streams_bidi(8);
        config.set_initial_max_streams_uni(16);
        let mut id = [0; 20];
        boring::rand::rand_bytes(&mut id).unwrap();
        let id = quiche::ConnectionId::from_ref(&id);
        let mut conn = quiche::connect(
            Some("proxy.example.test"),
            &id,
            socket.local_addr().unwrap(),
            server,
            &mut config,
        )
        .unwrap();
        if let Some(path) = keylog {
            conn.set_keylog(Box::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .unwrap(),
            ));
        }
        Self {
            socket,
            server,
            conn,
            h3: None,
            next_id: 0,
            responses: std::collections::HashMap::new(),
            read_limit: usize::MAX,
            replay_packets: false,
            io_timeout: Duration::from_secs(5),
        }
    }
    pub(super) async fn new(server: std::net::SocketAddr, ca: &std::path::Path) -> Self {
        let mut client = Self::initial(server, ca).await;
        let end = std::time::Instant::now() + Duration::from_secs(5);
        while client.h3.is_none() {
            assert!(
                std::time::Instant::now() < end,
                "H3 handshake deadline: {:?}",
                client.conn.local_error()
            );
            client.step().await;
        }
        assert_eq!(client.conn.application_proto(), b"h3");
        assert!(client.conn.peer_cert().is_some());
        client
    }
    async fn step(&mut self) {
        let mut out = [0; 1350];
        while let Ok((n, info)) = self.conn.send(&mut out) {
            self.socket.send_to(&out[..n], info.to).await.unwrap();
            if self.replay_packets {
                self.socket.send_to(&out[..n], info.to).await.unwrap();
            }
        }
        let mut buffer = [0; 65535];
        if let Ok(Ok((n, from))) =
            tokio::time::timeout(Duration::from_millis(2), self.socket.recv_from(&mut buffer)).await
        {
            assert_eq!(from, self.server);
            let _ = self.conn.recv(
                &mut buffer[..n],
                quiche::RecvInfo {
                    from,
                    to: self.socket.local_addr().unwrap(),
                },
            );
        }
        if self
            .conn
            .timeout_instant()
            .is_some_and(|t| t <= std::time::Instant::now())
        {
            self.conn.on_timeout();
        }
        if self.conn.is_established() && self.h3.is_none() {
            self.h3 = Some(
                quiche::h3::Connection::with_transport(
                    &mut self.conn,
                    &quiche::h3::Config::new().unwrap(),
                )
                .unwrap(),
            );
        }
        if let Some(h3) = &mut self.h3 {
            for _ in 0..128 {
                use quiche::h3::{Event, NameValue};
                match h3.poll(&mut self.conn) {
                    Ok((id, Event::Headers { list, .. })) => {
                        let response = self.responses.entry(id).or_default();
                        for field in list {
                            if !field.name().starts_with(b":") {
                                response.headers.append(
                                    http::header::HeaderName::from_bytes(field.name()).unwrap(),
                                    http::HeaderValue::from_bytes(field.value()).unwrap(),
                                );
                            }
                            match field.name() {
                                b":status" => {
                                    response.status =
                                        std::str::from_utf8(field.value()).unwrap().parse().unwrap()
                                }
                                b"padding" => {
                                    response.padding = true;
                                }
                                b"content-length" => response.content_length = true,
                                _ => {}
                            }
                        }
                    }
                    Ok((id, Event::Data)) => {
                        let response = self.responses.entry(id).or_default();
                        let mut body = [0; CHUNK];
                        let mut received = 0;
                        while received < self.read_limit {
                            let capacity = (self.read_limit - received).min(body.len());
                            let Ok(n) = h3.recv_body(&mut self.conn, id, &mut body[..capacity])
                            else {
                                break;
                            };
                            if n == 0 {
                                break;
                            }
                            response.body.extend_from_slice(&body[..n]);
                            received += n;
                        }
                        if received == self.read_limit {
                            break;
                        }
                    }
                    Ok((id, Event::Finished)) => {
                        self.responses.entry(id).or_default().finished = true
                    }
                    Ok((id, Event::Reset(_))) => self.responses.entry(id).or_default().reset = true,
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => panic!("test H3 receive: {e:?}"),
                }
            }
            // A deliberately slow consumer must retry recv_body itself after
            // yielding; it cannot rely on a new DATA event for bytes already
            // buffered in quiche when the peer is blocked by receive credit.
            if self.read_limit > 0 && self.read_limit != usize::MAX {
                for (id, response) in &mut self.responses {
                    let mut body = vec![0; self.read_limit.min(CHUNK)];
                    if let Ok(n) = h3.recv_body(&mut self.conn, *id, &mut body) {
                        response.body.extend_from_slice(&body[..n]);
                    }
                }
            }
        }
    }
    fn send_headers(
        &mut self,
        headers: &[quiche::h3::Header],
        fin: bool,
    ) -> std::result::Result<u64, quiche::h3::Error> {
        use quiche::h3::NameValue;
        let get = |name: &[u8]| {
            headers
                .iter()
                .find(|h| h.name() == name)
                .map(|h| std::str::from_utf8(h.value()).unwrap())
        };
        let auth = if get(b"proxy-authorization") == Some(SIGN) {
            let binding = moon_naive_core::auth::Binding {
                exporter: super::exporter(self.conn.as_mut()).unwrap(),
                stream_id: self.next_id,
            };
            Some(proof(
                &binding,
                get(b":method").unwrap(),
                get(b":authority").unwrap(),
                get(b":scheme"),
                get(b":path"),
                get(b":protocol"),
            ))
        } else {
            None
        };
        let headers: Vec<_> = headers
            .iter()
            .map(|h| {
                quiche::h3::Header::new(
                    h.name(),
                    if h.name() == b"proxy-authorization" {
                        auth.as_ref().map_or(h.value(), |v| v.as_bytes())
                    } else {
                        h.value()
                    },
                )
            })
            .collect();
        let id = self
            .h3
            .as_mut()
            .unwrap()
            .send_request(&mut self.conn, &headers, fin)?;
        assert_eq!(id, self.next_id);
        self.next_id += 4;
        Ok(id)
    }
    fn request(
        &mut self,
        method: &str,
        authority: &str,
        path: Option<&str>,
        authorization: Option<&str>,
        padded: bool,
        fin: bool,
    ) -> u64 {
        let mut headers = vec![
            quiche::h3::Header::new(b":method", method.as_bytes()),
            quiche::h3::Header::new(b":authority", authority.as_bytes()),
        ];
        if let Some(path) = path {
            headers.push(quiche::h3::Header::new(b":scheme", b"https"));
            headers.push(quiche::h3::Header::new(b":path", path.as_bytes()));
        }
        if let Some(auth) = authorization {
            headers.push(quiche::h3::Header::new(
                b"proxy-authorization",
                auth.as_bytes(),
            ));
        }
        if padded {
            headers.push(quiche::h3::Header::new(b"padding", b"~"));
        }
        self.send_headers(&headers, fin).unwrap()
    }
    async fn send(&mut self, id: u64, data: &[u8]) {
        self.send_part(id, data, true).await;
    }
    async fn send_part(&mut self, id: u64, mut data: &[u8], fin: bool) {
        let end = std::time::Instant::now() + self.io_timeout;
        loop {
            assert!(std::time::Instant::now() < end, "H3 upload deadline");
            match self
                .h3
                .as_mut()
                .unwrap()
                .send_body(&mut self.conn, id, data, fin)
            {
                Ok(n) => {
                    data = &data[n..];
                    if data.is_empty() {
                        break;
                    }
                }
                Err(quiche::h3::Error::Done) => {}
                Err(e) => panic!("H3 test send: {e:?}"),
            }
            self.step().await;
        }
    }
    async fn response(&mut self, id: u64) -> QResponse {
        let end = std::time::Instant::now() + self.io_timeout;
        loop {
            if self
                .responses
                .get(&id)
                .is_some_and(|r| r.finished || r.reset)
            {
                return self.responses.remove(&id).unwrap();
            }
            assert!(
                std::time::Instant::now() < end,
                "H3 response deadline, connection={:?}, received={:?}, stats={:?}",
                self.conn.local_error(),
                self.responses
                    .get(&id)
                    .map(|r| (r.status, r.body.len(), r.finished, r.reset)),
                self.conn.stats()
            );
            self.step().await;
        }
    }
}
#[tokio::test]
async fn real_h3_retry_tls_site_auth_padding_flow_control_half_close() {
    let fixture = fixture();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = origin.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = origin.accept().await.unwrap();
            tokio::spawn(async move {
                let mut payload = Vec::new();
                stream.read_to_end(&mut payload).await.unwrap();
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
            });
        }
    });
    let server = network(&fixture, Some(target)).await;
    let address = server.udp_addr().unwrap();
    let stats = server.stats.clone();
    let permits = server.connections.clone();
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(server.run(shutdown));
    let mut client = QClient::new(address, &fixture.ca).await;
    let id = client.request("GET", "proxy.example.test", Some("/"), None, false, true);
    let response = client.response(id).await;
    assert_eq!(response.status, 200);
    assert!(!response.padding);
    assert!(response.body.starts_with(b"<!doctype html>"));
    let id = client.request(
        "CONNECT",
        "example.org:443",
        None,
        Some("Basic wrong"),
        false,
        false,
    );
    assert_eq!(client.response(id).await.status, 404);
    assert_eq!(stats.dials.load(Ordering::Relaxed), 0);
    for padded in [false, true] {
        let id = client.request(
            "CONNECT",
            "example.org:443",
            None,
            Some(&auth()),
            padded,
            false,
        );
        let payload: Vec<_> = (0..300_000).map(|n| (n % 251) as u8).collect();
        let mut wire = Vec::new();
        // Client-side wire is independent of the implementation's Encoder.
        for (i, chunk) in payload.chunks(12000).enumerate() {
            if i < 16 {
                wire.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
                wire.push(1);
            }
            wire.extend_from_slice(chunk);
            if i < 16 {
                wire.push(0);
            }
        }
        client.send(id, &wire).await;
        let response = client.response(id).await;
        assert_eq!(response.status, 200);
        assert!(!response.reset);
        assert!(!response.padding);
        assert!(!response.content_length);
        let data = {
            let mut decoder = moon_naive_core::codec::Decoder::default();
            let data = decoder.feed(&response.body).unwrap();
            decoder.finish().unwrap();
            data
        };
        assert_eq!(data, payload);
    }
    assert_eq!(stats.dials.load(Ordering::Relaxed), 2);
    let _ = client.conn.close(true, 0x100, b"");
    client.step().await;
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
    echo.abort();
    assert_eq!(permits.active(), 0);
    assert_eq!(stats.streams.load(Ordering::Relaxed), 0);
}

fn rotate(fixture: &Fixture) {
    let stored = DiskStore::open(&fixture.config.state_dir.join("certificates"))
        .unwrap()
        .read_current()
        .unwrap()
        .unwrap();
    let old = X509::stack_from_pem(&stored.candidate.chain_pem).unwrap();
    let key = key();
    let mut leaf = X509::builder().unwrap();
    leaf.set_version(2).unwrap();
    leaf.set_serial_number(&BigNum::from_u32(3).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    leaf.set_subject_name(old[0].subject_name()).unwrap();
    leaf.set_issuer_name(fixture.ca_cert.subject_name())
        .unwrap();
    leaf.set_pubkey(&key).unwrap();
    leaf.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    leaf.set_not_after(&Asn1Time::days_from_now(60).unwrap())
        .unwrap();
    leaf.append_extension(&BasicConstraints::new().build().unwrap())
        .unwrap();
    leaf.append_extension(&ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    leaf.append_extension(
        &SubjectAlternativeName::new()
            .dns(&fixture.config.domain)
            .build(&leaf.x509v3_context(Some(&fixture.ca_cert), None))
            .unwrap(),
    )
    .unwrap();
    leaf.sign(&fixture.ca_key, MessageDigest::sha256()).unwrap();
    let mut chain = leaf.build().to_pem().unwrap();
    chain.extend(fixture.ca_cert.to_pem().unwrap());
    let candidate = crate::acme::certificate::Candidate {
        chain_pem: chain,
        key_pem: key.private_key_to_pem_pkcs8().unwrap(),
    };
    let bundle = crate::acme::certificate::Validator::for_config(&fixture.config)
        .unwrap()
        .verify(candidate, crate::acme::now())
        .unwrap();
    DiskStore::open(&fixture.config.state_dir.join("certificates"))
        .unwrap()
        .install(&bundle)
        .unwrap();
}
fn serial(cert: &X509) -> Vec<u8> {
    cert.serial_number().to_bn().unwrap().to_vec()
}
async fn peer_serial(addr: std::net::SocketAddr, ca: &std::path::Path) -> Vec<u8> {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(ca).unwrap();
    connector.set_alpn_protos(b"\x02h2").unwrap();
    let stream = tokio_boring::connect(
        connector.build().configure().unwrap(),
        "proxy.example.test",
        TcpStream::connect(addr).await.unwrap(),
    )
    .await
    .unwrap();
    serial(&stream.ssl().peer_certificate().unwrap())
}
#[tokio::test]
async fn actual_h2_h3_certificate_reload_preserves_existing_connections_and_rejects_bad_current() {
    let mut fixture = fixture();
    Arc::get_mut(&mut fixture.config)
        .unwrap()
        .limits
        .idle_timeout_secs = 30;
    let server = network(&fixture, None).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let slot = server.tls.clone();
    let old = slot.current().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut existing, connection) = h2_client(tcp, &fixture.ca).await;
    let mut old_h3 = QClient::new(udp, &fixture.ca).await;
    assert_eq!(peer_serial(tcp, &fixture.ca).await, vec![2]);
    assert_eq!(
        serial(&X509::from_der(old_h3.conn.peer_cert().unwrap()).unwrap()),
        vec![2]
    );
    rotate(&fixture);
    tokio::time::timeout(Duration::from_secs(8), async {
        while slot.current().unwrap().id == old.id {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(peer_serial(tcp, &fixture.ca).await, vec![3]);
    let mut new_h3 = QClient::new(udp, &fixture.ca).await;
    assert_eq!(
        serial(&X509::from_der(new_h3.conn.peer_cert().unwrap()).unwrap()),
        vec![3]
    );
    let request = http::Request::builder()
        .uri("https://proxy.example.test/")
        .body(())
        .unwrap();
    let (response, _) = existing.send_request(request, true).unwrap();
    assert_eq!(response.await.unwrap().status(), 200);
    let id = old_h3.request("GET", "proxy.example.test", Some("/"), None, false, true);
    assert_eq!(old_h3.response(id).await.status, 200);
    let good = slot.current().unwrap().id.clone();
    std::fs::write(
        fixture.config.state_dir.join("certificates/CURRENT"),
        b"generation-corrupt",
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(5200)).await;
    assert_eq!(slot.current().unwrap().id, good);
    assert_ne!(old.id, good);
    assert_eq!(peer_serial(tcp, &fixture.ca).await, vec![3]);
    let _ = old_h3.conn.close(true, 0x100, b"");
    old_h3.step().await;
    let _ = new_h3.conn.close(true, 0x100, b"");
    new_h3.step().await;
    connection.abort();
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
}
#[tokio::test]
async fn resets_cancel_real_h2_h3_tunnels_and_release_quotas() {
    let fixture = fixture();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut buffer = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        }
    });
    let server = network(&fixture, Some(target)).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let app = server.app.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut client, connection) = h2_client(tcp, &fixture.ca).await;
    let req = http::Request::builder()
        .method("CONNECT")
        .uri("example.org:443")
        .header("proxy-authorization", auth())
        .body(())
        .unwrap();
    let (response, mut upload) = client.send_request(req, false).unwrap();
    assert_eq!(response.await.unwrap().status(), 200);
    upload.send_reset(::h2::Reason::CANCEL);
    tokio::time::timeout(Duration::from_secs(2), async {
        while app.stats.streams.load(Ordering::Relaxed) != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(app.resources.tunnels.active(), 0);
    assert_eq!(app.resources.requests.active(), 0);
    let mut client = QClient::new(udp, &fixture.ca).await;
    let id = client.request(
        "CONNECT",
        "example.org:443",
        None,
        Some(&auth()),
        false,
        false,
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while client.responses.get(&id).is_none_or(|r| r.status != 200) {
            client.step().await;
        }
    })
    .await
    .unwrap();
    client
        .conn
        .stream_shutdown(id, quiche::Shutdown::Write, 0x10c)
        .unwrap();
    client
        .conn
        .stream_shutdown(id, quiche::Shutdown::Read, 0x10c)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while app.stats.streams.load(Ordering::Relaxed) != 0 {
            client.step().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(app.resources.tunnels.active(), 0);
    assert_eq!(app.resources.requests.active(), 0);
    origin_task.await.unwrap();
    connection.abort();
    let _ = client.conn.close(true, 0x100, b"");
    client.step().await;
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
}
#[tokio::test]
async fn startup_checks_private_users_site_and_certificate_before_bind() {
    let mut fixture = fixture();
    std::fs::set_permissions(
        &fixture.config.credentials_file,
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let config = Arc::get_mut(&mut fixture.config).unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    config.listener.tcp = address;
    assert!(App::load(&fixture.config).is_err());
    let _rebound = TcpListener::bind(address).await.unwrap();
}

#[tokio::test]
async fn early_data_resets_cancel_pending_admission_without_dialing() {
    let fixture = fixture();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut server = network(&fixture, Some(origin.local_addr().unwrap())).await;
    Arc::get_mut(&mut server.app).unwrap().egress.test_delay = Some(Duration::from_secs(30));
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let app = server.app.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut client, connection) = h2_client(tcp, &fixture.ca).await;
    let req = http::Request::builder()
        .method("CONNECT")
        .uri("example.org:443")
        .header("proxy-authorization", auth())
        .body(())
        .unwrap();
    let (mut response, mut upload) = client.send_request(req, false).unwrap();
    upload
        .send_data(Bytes::from_static(b"early data"), false)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while app.resources.tunnels.active() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut response)
            .await
            .is_err()
    );
    assert_eq!(app.stats.dials.load(Ordering::Relaxed), 0);
    upload.send_reset(::h2::Reason::CANCEL);
    tokio::time::timeout(Duration::from_secs(2), async {
        while app.resources.requests.active() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(app.resources.tunnels.active(), 0);
    let mut client = QClient::new(udp, &fixture.ca).await;
    for (stop_read, reset_write, fin) in [
        (true, true, true),
        (true, false, false),
        (false, true, false),
    ] {
        let id = client.request(
            "CONNECT",
            "example.org:443",
            None,
            Some(&auth()),
            false,
            false,
        );
        if fin {
            client.send(id, b"early data").await;
        } else {
            assert_eq!(
                client
                    .h3
                    .as_mut()
                    .unwrap()
                    .send_body(&mut client.conn, id, b"early data", false)
                    .unwrap(),
                10
            );
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while app.resources.tunnels.active() != 1 {
                client.step().await;
            }
        })
        .await
        .unwrap();
        assert!(client.responses.get(&id).is_none_or(|r| r.status != 200));
        assert_eq!(app.stats.dials.load(Ordering::Relaxed), 0);
        if stop_read {
            client
                .conn
                .stream_shutdown(id, quiche::Shutdown::Read, 0x10c)
                .unwrap();
        }
        if reset_write {
            client
                .conn
                .stream_shutdown(id, quiche::Shutdown::Write, 0x10c)
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while app.resources.requests.active() != 0 {
                client.step().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(app.resources.tunnels.active(), 0);
        assert_eq!(app.stats.dials.load(Ordering::Relaxed), 0);
    }
    connection.abort();
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn early_data_and_clean_fin_survive_delayed_h3_admission() {
    let fixture = fixture();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut server = network(&fixture, Some(origin.local_addr().unwrap())).await;
    Arc::get_mut(&mut server.app).unwrap().egress.test_delay = Some(Duration::from_millis(100));
    let address = server.udp_addr().unwrap();
    let app = server.app.clone();
    let origin = tokio::spawn(async move {
        for data in [b"".as_slice(), b"early data and FIN"] {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut body = Vec::new();
            stream.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, data);
            stream
                .write_all(b"response after request FIN")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        }
    });
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let mut client = QClient::new(address, &fixture.ca).await;
    for data in [b"".as_slice(), b"early data and FIN"] {
        let id = client.request(
            "CONNECT",
            "example.org:443",
            None,
            Some(&auth()),
            false,
            false,
        );
        let wire = if data.is_empty() {
            Bytes::new()
        } else {
            frame(data)
        };
        client.send(id, &wire).await;
        let response = client.response(id).await;
        assert_eq!(response.status, 200);
        assert!(!response.reset);
        assert_eq!(unframe(&response.body), b"response after request FIN");
    }
    origin.await.unwrap();
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
    assert_eq!(app.resources.requests.active(), 0);
    assert_eq!(app.resources.tunnels.active(), 0);
}

#[tokio::test]
async fn users_toml_rejects_json_duplicates_unknown_keys_and_weak_passwords() {
    let fixture = fixture();
    assert!(App::load(&fixture.config).is_ok());
    for content in [
        r#"{"users":[{"username":"alice","password":"long-loopback-test-password"}]}"#,
        "[[users]]\nusername='alice'\npassword='short'",
        "[[users]]\nusername='alice'\npassword='long-loopback-test-password'\nextra=true",
        "[[users]]\nusername='alice'\npassword='long-loopback-test-password'\n[[users]]\nusername='alice'\npassword='another-long-loopback-password'",
        "users = []",
    ] {
        std::fs::write(&fixture.config.credentials_file, content).unwrap();
        assert!(App::load(&fixture.config).is_err());
    }
}

#[test]
fn shared_request_validation_reconciles_lengths_and_forbids_ambiguous_headers() {
    let head = Head {
        binding: None,
        client_ip: None,
        method: "GET".into(),
        authority: "proxy.example.test".into(),
        scheme: Some("https".into()),
        path: Some("/".into()),
        protocol: None,
        headers: vec![],
    };
    for headers in [
        vec![("te", "trailers")],
        vec![("content-length", "42, 42"), ("content-length", "42")],
        vec![("host", "PROXY.example.test")],
    ] {
        let mut head = head.clone();
        head.headers = headers
            .into_iter()
            .map(|(k, v)| (k.into(), v.as_bytes().to_vec()))
            .collect();
        assert!(head.valid());
    }
    for headers in [
        vec![("te", "gzip")],
        vec![("connection", "keep-alive")],
        vec![("content-length", "42, 43")],
        vec![("content-length", "42"), ("content-length", "43")],
        vec![("content-length", "")],
        vec![("content-length", "+42")],
        vec![("content-length", "18446744073709551616")],
        vec![("host", "other.example.test")],
        vec![
            ("host", "proxy.example.test"),
            ("host", "proxy.example.test"),
        ],
        vec![("bad name", "value")],
        vec![("x-test", "value\nsmuggled")],
    ] {
        let mut head = head.clone();
        head.headers = headers
            .into_iter()
            .map(|(k, v)| (k.into(), v.as_bytes().to_vec()))
            .collect();
        assert!(!head.valid());
    }
}

// The first origin continuously downloads with the request half left open.
// The second receives a continuous upload without responding until FIN. Both
// run for > 2x the configured idle timeout. The last origin is fully silent.
async fn directional_origin(listener: TcpListener) {
    for download in [true, false] {
        let (mut stream, _) = listener.accept().await.unwrap();
        if download {
            for _ in 0..12 {
                stream.write_all(b"tick").await.unwrap();
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            stream.shutdown().await.unwrap();
            let mut data = Vec::new();
            stream.read_to_end(&mut data).await.unwrap();
            assert!(data.is_empty());
        } else {
            let mut data = Vec::new();
            stream.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, b"tick".repeat(12));
            stream.write_all(&data).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    }
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut byte = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn real_h2_idle_allows_one_way_progress_and_reaps_silent_tunnels() {
    let mut fixture = fixture();
    Arc::get_mut(&mut fixture.config)
        .unwrap()
        .limits
        .idle_timeout_secs = 1;
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = network(&fixture, Some(origin.local_addr().unwrap())).await;
    let origin = tokio::spawn(directional_origin(origin));
    let address = server.tcp_addr().unwrap();
    let app = server.app.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut client, connection) = h2_client(address, &fixture.ca).await;
    for download in [true, false] {
        let req = http::Request::builder()
            .method("CONNECT")
            .uri("example.org:443")
            .header("proxy-authorization", auth())
            .body(())
            .unwrap();
        let (response, mut upload) = client.send_request(req, false).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        if download {
            assert_eq!(
                unframe(&body(response.into_body()).await),
                b"tick".repeat(12)
            );
            v2_send(&mut upload, Bytes::new(), true).await;
        } else {
            for _ in 0..12 {
                v2_send(&mut upload, frame(b"tick"), false).await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            v2_send(&mut upload, Bytes::new(), true).await;
            assert_eq!(
                unframe(&body(response.into_body()).await),
                b"tick".repeat(12)
            );
        }
    }
    let req = http::Request::builder()
        .method("CONNECT")
        .uri("example.org:443")
        .header("proxy-authorization", auth())
        .body(())
        .unwrap();
    let (response, _upload) = client.send_request(req, false).unwrap();
    let mut response = response.await.unwrap().into_body();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), response.data())
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    origin.await.unwrap();
    connection.abort();
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
    assert_eq!(app.resources.tunnels.active(), 0);
    assert_eq!(app.resources.requests.active(), 0);
}

#[tokio::test]
async fn real_h3_idle_allows_one_way_progress_and_reaps_silent_tunnels() {
    let mut fixture = fixture();
    Arc::get_mut(&mut fixture.config)
        .unwrap()
        .limits
        .idle_timeout_secs = 1;
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = network(&fixture, Some(origin.local_addr().unwrap())).await;
    let origin = tokio::spawn(directional_origin(origin));
    let address = server.udp_addr().unwrap();
    let app = server.app.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let mut client = QClient::new(address, &fixture.ca).await;
    for download in [true, false] {
        let id = client.request(
            "CONNECT",
            "example.org:443",
            None,
            Some(&auth()),
            false,
            false,
        );
        if download {
            let response = client.response(id).await;
            assert!(!response.reset);
            assert_eq!(response.status, 200);
            assert_eq!(unframe(&response.body), b"tick".repeat(12));
        } else {
            for _ in 0..12 {
                assert_eq!(
                    client
                        .h3
                        .as_mut()
                        .unwrap()
                        .send_body(&mut client.conn, id, &frame(b"tick"), false)
                        .unwrap(),
                    7 // Three-byte initial header plus four payload bytes.
                );
                let end = std::time::Instant::now() + Duration::from_millis(200);
                while std::time::Instant::now() < end {
                    client.step().await;
                }
            }
        }
        client.send(id, b"").await;
        if !download {
            let response = client.response(id).await;
            assert!(!response.reset);
            assert_eq!(response.status, 200);
            assert_eq!(unframe(&response.body), b"tick".repeat(12));
        }
    }
    let id = client.request(
        "CONNECT",
        "example.org:443",
        None,
        Some(&auth()),
        false,
        false,
    );
    while client.responses.get(&id).is_none_or(|r| r.status != 200) {
        client.step().await;
    }
    // Keep the QUIC connection active with independent site requests, so this
    // tests the tunnel deadline rather than a silent QUIC connection timeout.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut probe_at = std::time::Instant::now();
    while app.stats.streams.load(Ordering::Relaxed) != 0 {
        assert!(std::time::Instant::now() < deadline);
        if std::time::Instant::now() >= probe_at {
            let site = client.request("GET", "proxy.example.test", Some("/"), None, false, true);
            assert_eq!(client.response(site).await.status, 200);
            probe_at = std::time::Instant::now() + Duration::from_millis(250);
        }
        client.step().await;
    }
    assert!(client.response(id).await.reset);
    origin.await.unwrap();
    let _ = client.conn.close(true, 0x100, b"");
    client.step().await;
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
    assert_eq!(app.resources.tunnels.active(), 0);
    assert_eq!(app.resources.requests.active(), 0);
}

#[tokio::test]
async fn real_h2_h3_slow_readers_preserve_padded_bytes_across_small_windows() {
    let fixture = fixture();
    let payload: Vec<_> = (0..512 * 1024).map(|n| (n % 251) as u8).collect();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = network(&fixture, Some(origin.local_addr().unwrap())).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let app = server.app.clone();
    let origin = tokio::spawn({
        let payload = payload.clone();
        async move {
            for _ in 0..2 {
                let (mut stream, _) = origin.accept().await.unwrap();
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut upload = Vec::new();
                stream.read_to_end(&mut upload).await.unwrap();
                assert!(upload.is_empty());
            }
        }
    });
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut client, connection) = h2_client(tcp, &fixture.ca).await;
    let req = http::Request::builder()
        .method("CONNECT")
        .uri("example.org:443")
        .header("proxy-authorization", auth())
        .header("padding", "~")
        .body(())
        .unwrap();
    let (response, _upload) = client.send_request(req, true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut decoder = moon_naive_core::codec::Decoder::default();
    let mut received = Vec::new();
    while let Some(part) = tokio::time::timeout(Duration::from_secs(5), body.data())
        .await
        .unwrap()
    {
        let part = part.unwrap();
        received.extend(decoder.feed(&part).unwrap());
        tokio::time::sleep(Duration::from_millis(2)).await;
        body.flow_control().release_capacity(part.len()).unwrap();
    }
    decoder.finish().unwrap();
    assert_eq!(received, payload);
    connection.abort();
    let mut client = QClient::new(udp, &fixture.ca).await;
    client.read_limit = 0;
    let id = client.request(
        "CONNECT",
        "example.org:443",
        None,
        Some(&auth()),
        true,
        true,
    );
    while client.responses.get(&id).is_none_or(|r| r.status != 200) {
        client.step().await;
    }
    let until = std::time::Instant::now() + Duration::from_millis(200);
    while std::time::Instant::now() < until {
        client.step().await;
    }
    client.read_limit = 1024;
    let response = client.response(id).await;
    assert!(!response.reset);
    let mut decoder = moon_naive_core::codec::Decoder::default();
    assert_eq!(decoder.feed(&response.body).unwrap(), payload);
    decoder.finish().unwrap();
    origin.await.unwrap();
    let _ = client.conn.close(true, 0x100, b"");
    client.step().await;
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
    assert_eq!(app.resources.tunnels.active(), 0);
    assert_eq!(app.resources.requests.active(), 0);
}

#[tokio::test]
async fn ech_accepts_inner_name_and_preserves_plain_h2() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut f = fixture();
    let hpke = PKey::generate(boring::pkey::Id::X25519).unwrap();
    let mut public = [0; 32];
    let mut private = [0; 32];
    hpke.raw_public_key(&mut public).unwrap();
    hpke.raw_private_key(&mut private).unwrap();
    let name = b"public.example.test";
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
    let root = f._root.path();
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
    let original_keys = f.config.ech.as_ref().unwrap().keys_file.clone();
    Arc::get_mut(&mut f.config)
        .unwrap()
        .ech
        .as_mut()
        .unwrap()
        .keys_file = f._root.path().join("generated-ech.toml");
    tls::ech_command("init", &f.config).unwrap();
    tls::ech_command("check", &f.config).unwrap();
    tls::ech_command("dns", &f.config).unwrap();
    assert!(tls::ech_command("init", &f.config).is_err());
    Arc::get_mut(&mut f.config)
        .unwrap()
        .ech
        .as_mut()
        .unwrap()
        .keys_file = original_keys;
    Arc::get_mut(&mut f.config).unwrap().listener.h1 = true;
    let server = network(&f, None).await;
    let address = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let slot = server.tls.clone();
    let stats = server.stats.clone();
    let (stop, receive) = watch::channel(false);
    let task = tokio::spawn(server.run(receive));
    for (ech, domain) in [
        (true, "proxy.example.test"),
        (false, "proxy.example.test"),
        (false, "public.example.test"),
    ] {
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_ca_file(&f.ca).unwrap();
        connector.set_alpn_protos(b"\x02h2").unwrap();
        let mut client = connector.build().configure().unwrap();
        if ech {
            client.set_ech_config_list(&list).unwrap();
        }
        let stream =
            tokio_boring::connect(client, domain, TcpStream::connect(address).await.unwrap())
                .await
                .unwrap();
        assert_eq!(stream.ssl().ech_accepted(), ech);
        assert_eq!(
            stream.ssl().selected_alpn_protocol(),
            Some(b"h2".as_slice())
        );
        let (mut sender, connection) = ::h2::client::handshake(stream).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        for credential in [None, Some(auth())] {
            let mut request = http::Request::builder().uri(format!("https://{domain}/"));
            if let Some(credential) = credential {
                request = request.header("proxy-authorization", credential);
            }
            let (response, _) = sender
                .send_request(request.body(()).unwrap(), true)
                .unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status(), 200);
            assert!(!response.headers().contains_key("padding"));
            assert!(
                body(response.into_body())
                    .await
                    .starts_with(b"<!doctype html>")
            );
        }
        driver.abort();
    }
    let mut q = QClient::initial(udp, &f.ca).await;
    q.conn.as_mut().set_ech_config_list(&list).unwrap();
    let end = std::time::Instant::now() + Duration::from_secs(5);
    while q.h3.is_none() {
        assert!(std::time::Instant::now() < end, "ECH H3 handshake failed");
        q.step().await;
    }
    assert!(q.conn.as_mut().ech_accepted());
    assert_eq!(q.conn.application_proto(), b"h3");
    for name in ["proxy.example.test", "public.example.test"] {
        let id = q.request("GET", name, Some("/"), None, false, true);
        let reply = q.response(id).await;
        assert_eq!(reply.status, 200);
        assert!(!reply.padding);
    }
    // Public Host uses the same fixed site over H1, never an authenticated proxy.
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(&f.ca).unwrap();
    connector.set_alpn_protos(b"\x08http/1.1").unwrap();
    let mut h1 = tokio_boring::connect(
        connector.build().configure().unwrap(),
        "public.example.test",
        TcpStream::connect(address).await.unwrap(),
    )
    .await
    .unwrap();
    h1.write_all(b"GET / HTTP/1.1\r\nHost: public.example.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    h1.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert_eq!(stats.dials.load(Ordering::Relaxed), 0);
    let redirect_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirect_address = redirect_listener.local_addr().unwrap();
    let redirect_task = tokio::spawn(super::redirect::serve(
        redirect_listener,
        f.config.clone(),
        Budget::new(2).unwrap(),
        stop.subscribe(),
    ));
    for (host, status) in [
        ("PUBLIC.EXAMPLE.TEST", "308"),
        ("unknown.example.test", "404"),
    ] {
        let mut socket = TcpStream::connect(redirect_address).await.unwrap();
        socket
            .write_all(
                format!("GET /route?q=1 HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}")),
            "{response}"
        );
        if status == "308" {
            assert!(
                response.contains(&format!(
                    "https://public.example.test:{}/route?q=1",
                    f.config.listener.tcp.port()
                )),
                "{response}"
            );
            assert!(!response.contains("https://proxy.example.test"));
        }
    }
    let keys_path = &f.config.ech.as_ref().unwrap().keys_file;
    let original = std::fs::read(keys_path).unwrap();
    let old_generation = slot.current().unwrap();
    std::fs::write(keys_path, b"invalid ECH configuration").unwrap();
    assert!(slot.refresh(&f.config).is_err());
    assert!(Arc::ptr_eq(&old_generation, &slot.current().unwrap()));
    // A content change with the same certificate generation triggers a reload.
    let mut updated = original.clone();
    updated.extend_from_slice(b"\n# atomic deployment generation 2\n");
    std::fs::write(keys_path, updated).unwrap();
    assert!(slot.refresh(&f.config).unwrap());
    assert!(!Arc::ptr_eq(&old_generation, &slot.current().unwrap()));
    assert!(!slot.refresh(&f.config).unwrap());
    let id = q.request("GET", "public.example.test", Some("/"), None, false, true);
    assert_eq!(q.response(id).await.status, 200);
    let mut reloaded = QClient::initial(udp, &f.ca).await;
    reloaded.conn.as_mut().set_ech_config_list(&list).unwrap();
    let end = std::time::Instant::now() + Duration::from_secs(5);
    while reloaded.h3.is_none() {
        assert!(std::time::Instant::now() < end);
        reloaded.step().await;
    }
    assert!(reloaded.conn.as_mut().ech_accepted());
    let mut stale = list.clone();
    stale[6] ^= 1;
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(&f.ca).unwrap();
    connector.set_alpn_protos(b"\x02h2").unwrap();
    let mut client = connector.build().configure().unwrap();
    client.set_ech_config_list(&stale).unwrap();
    assert!(
        tokio_boring::connect(
            client,
            "proxy.example.test",
            TcpStream::connect(address).await.unwrap()
        )
        .await
        .is_err()
    );
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    redirect_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn finite_framing_h2_h3_roundtrip_ignores_legacy_negotiation() {
    let f = fixture();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = origin.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = origin.accept().await.unwrap();
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                socket.read_to_end(&mut bytes).await.unwrap();
                socket.write_all(&bytes).await.unwrap();
                socket.shutdown().await.unwrap();
            });
        }
    });
    let server = network(&f, Some(target)).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let payload: Vec<u8> = (0..300_000).map(|n| (n % 251) as u8).collect();
    let mut wire = Vec::new();
    for (i, chunk) in payload.chunks(11000).enumerate() {
        if i < 16 {
            wire.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            wire.push(1);
        }
        wire.extend_from_slice(chunk);
        if i < 16 {
            wire.push(0);
        }
    }
    let (mut client, driver) = h2_client(tcp, &f.ca).await;
    let request = http::Request::builder()
        .method("CONNECT")
        .uri("example.org:443")
        .header("proxy-authorization", auth())
        .header("padding", "~")
        .header("padding-type-request", "moon-naive-16, 1")
        .body(())
        .unwrap();
    let (response, mut upload) = client.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("padding-type-reply"));
    let data = wire.clone();
    let send = tokio::spawn(async move {
        v2_send(&mut upload, Bytes::from(data), true).await;
    });
    let data = body(response.into_body()).await;
    send.await.unwrap();
    let mut decoder = moon_naive_core::codec::Decoder::default();
    assert_eq!(decoder.feed(&data).unwrap(), payload);
    decoder.finish().unwrap();
    assert_eq!(decoder.records(), 16);
    driver.abort();
    let mut q = QClient::new(udp, &f.ca).await;
    let authorization = auth();
    let headers = [
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":authority", b"example.org:443"),
        quiche::h3::Header::new(b"proxy-authorization", authorization.as_bytes()),
        quiche::h3::Header::new(b"padding", b"~"),
        quiche::h3::Header::new(b"padding-type-request", b"moon-naive-16, 1"),
    ];
    let id = q.send_headers(&headers, false).unwrap();
    let end = std::time::Instant::now() + Duration::from_secs(5);
    while q
        .responses
        .get(&id)
        .is_none_or(|response| response.status == 0)
    {
        assert!(std::time::Instant::now() < end);
        q.step().await;
    }
    assert_eq!(q.responses[&id].status, 200);
    assert!(!q.responses[&id].headers.contains_key("padding-type-reply"));
    q.send(id, &wire).await;
    let response = q.response(id).await;
    let mut decoder = moon_naive_core::codec::Decoder::default();
    assert_eq!(decoder.feed(&response.body).unwrap(), payload);
    decoder.finish().unwrap();
    assert_eq!(decoder.records(), 16);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    echo.await.unwrap();
}

#[tokio::test]
async fn moon_naive_proofs_cannot_move_between_streams_connections_or_transports() {
    let f = fixture();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = network(&f, Some(origin.local_addr().unwrap())).await;
    let origin = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut s, _) = origin.accept().await.unwrap();
            s.write_all(b"accepted").await.unwrap();
            s.shutdown().await.unwrap();
        }
    });
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut h2, driver) = h2_client(tcp, &f.ca).await;
    let binding = moon_naive_core::auth::Binding {
        exporter: h2.exporter,
        stream_id: 1,
    };
    let credential = proof(&binding, "CONNECT", "example.org:443", None, None, None);
    let request = |credential: &str| {
        http::Request::builder()
            .method("CONNECT")
            .uri("example.org:443")
            .header("proxy-authorization", credential)
            .body(())
            .unwrap()
    };
    let (reply, _) = h2.send_request(request(&credential), true).unwrap();
    let reply = reply.await.unwrap();
    assert_eq!(reply.status(), 200);
    let credentials = Credentials::new(&[("alice", "long-loopback-test-password")]).unwrap();
    let context = moon_naive_core::auth::Context {
        binding: &binding,
        method: "CONNECT",
        authority: "example.org:443",
        scheme: None,
        path: None,
        protocol: None,
    };
    assert!(
        credentials.verify_confirmation(
            0,
            &context,
            reply.headers()["proxy-authentication-info"]
                .to_str()
                .unwrap()
        )
    );
    assert!(!credentials.verify_confirmation(0, &context, &credential));
    assert_eq!(unframe(&body(reply.into_body()).await), b"accepted");
    let (reply, _) = h2.send_request(request(&credential), true).unwrap();
    assert_eq!(reply.await.unwrap().status(), 404);
    let (mut other, other_driver) = h2_client(tcp, &f.ca).await;
    let (reply, _) = other.send_request(request(&credential), true).unwrap();
    assert_eq!(reply.await.unwrap().status(), 404);
    let mut q = QClient::new(udp, &f.ca).await;
    let id = q.request(
        "CONNECT",
        "example.org:443",
        None,
        Some(&credential),
        false,
        true,
    );
    assert_eq!(q.response(id).await.status, 404);
    let binding = moon_naive_core::auth::Binding {
        exporter: super::exporter(q.conn.as_mut()).unwrap(),
        stream_id: q.next_id,
    };
    let credential = proof(&binding, "CONNECT", "example.org:443", None, None, None);
    let id = q.request(
        "CONNECT",
        "example.org:443",
        None,
        Some(&credential),
        false,
        true,
    );
    let reply = q.response(id).await;
    assert_eq!(reply.status, 200);
    let context = moon_naive_core::auth::Context {
        binding: &binding,
        method: "CONNECT",
        authority: "example.org:443",
        scheme: None,
        path: None,
        protocol: None,
    };
    assert!(credentials.verify_confirmation(
        0,
        &context,
        reply.headers["proxy-authentication-info"].to_str().unwrap()
    ));
    assert_eq!(unframe(&reply.body), b"accepted");
    let id = q.request(
        "CONNECT",
        "example.org:443",
        None,
        Some(&credential),
        false,
        true,
    );
    assert_eq!(q.response(id).await.status, 404);
    let mut other_q = QClient::new(udp, &f.ca).await;
    let id = other_q.request(
        "CONNECT",
        "example.org:443",
        None,
        Some(&credential),
        false,
        true,
    );
    assert_eq!(other_q.response(id).await.status, 404);
    assert_eq!(stats.dials.load(Ordering::Relaxed), 2);
    assert_eq!(stats.resolutions.load(Ordering::Relaxed), 0);
    origin.await.unwrap();
    driver.abort();
    other_driver.abort();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn negotiated_windows_share_h2_h3_connections_without_content_changes() {
    use moon_naive_core::{
        auth::{Binding, Context},
        codec::{Decoder, Encoder, Offer},
    };
    let case = crate::acme::lab_support::Case::new("codec-windows");
    let f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = listener.local_addr().unwrap();
    let server = network(&f, Some(origin_addr)).await;
    let origin = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let (mut stream, _) = listener.accept().await.unwrap();
            tasks.spawn(async move {
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
                stream.shutdown().await.unwrap();
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    });
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let _capture = case.capture(&[tcp.port(), udp.port(), origin_addr.port()]);
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let credentials = Credentials::new(&[("alice", "long-loopback-test-password")]).unwrap();
    fn context(binding: &Binding) -> Context<'_> {
        Context {
            binding,
            method: "CONNECT",
            authority: "example.org:443",
            scheme: None,
            path: None,
            protocol: None,
        }
    }
    let payload: Vec<u8> = (0..320000).map(|i| (i % 251) as u8).collect();
    let encode = |mode| {
        let mut encoder = Encoder::new(mode);
        let mut wire = Vec::new();
        for part in payload.chunks(7000) {
            wire.extend(encoder.encode(part, 0).unwrap());
        }

        wire
    };
    let (mut h2, driver) = h2_client(tcp, &f.ca).await;
    let mut requests = Vec::new();
    // All four CONNECTs are open on the same TLS connection before payload is sent.
    for bits in [1, 2, 5, 7] {
        let binding = Binding {
            exporter: h2.exporter,
            stream_id: h2.next_id,
        };
        let offer = Offer::from_bits(bits).unwrap();
        let proof = credentials
            .authorization_with(0, &context(&binding), offer)
            .unwrap();
        let (response, upload) = h2
            .send_request(
                http::Request::builder()
                    .method("CONNECT")
                    .uri("example.org:443")
                    .header("proxy-authorization", proof)
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        requests.push((binding, offer, response, upload));
    }
    for (binding, offer, response, mut upload) in requests {
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        let proof = response.headers()["proxy-authentication-info"]
            .to_str()
            .unwrap();
        assert_eq!(proof.len(), 58);
        let mode = credentials
            .verify_selection(0, &context(&binding), offer, proof)
            .unwrap();
        assert_eq!(mode, f.config.traffic.select(offer));
        assert!(!response.headers().contains_key("padding"));
        let wire = encode(mode);
        let send = tokio::spawn(async move {
            v2_send(&mut upload, Bytes::from(wire), true).await;
        });
        let wire = body(response.into_body()).await;
        send.await.unwrap();
        let mut decoder = Decoder::new(mode);
        assert_eq!(decoder.feed(&wire).unwrap(), payload);
        decoder.finish().unwrap();
    }
    let mut q = QClient::initial_with_keylog(udp, &f.ca, Some(&case.path().join("h3.keys"))).await;
    q.io_timeout = Duration::from_secs(5);
    tokio::time::timeout(Duration::from_secs(5), async {
        while q.h3.is_none() {
            q.step().await;
        }
    })
    .await
    .unwrap();
    let mut requests = Vec::new();
    for bits in [1, 2, 5, 7] {
        let binding = Binding {
            exporter: super::exporter(q.conn.as_mut()).unwrap(),
            stream_id: q.next_id,
        };
        let offer = Offer::from_bits(bits).unwrap();
        let proof = credentials
            .authorization_with(0, &context(&binding), offer)
            .unwrap();
        let id = q.request(
            "CONNECT",
            "example.org:443",
            None,
            Some(&proof),
            false,
            false,
        );
        requests.push((id, binding, offer));
    }
    for (id, binding, offer) in requests {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while q.responses.get(&id).is_none_or(|r| r.status == 0) {
            assert!(std::time::Instant::now() < deadline);
            q.step().await;
        }
        let response = &q.responses[&id];
        assert_eq!(response.status, 200);
        let proof = response.headers["proxy-authentication-info"]
            .to_str()
            .unwrap();
        let mode = credentials
            .verify_selection(0, &context(&binding), offer, proof)
            .unwrap();
        assert_eq!(mode, f.config.traffic.select(offer));
        case.event(
            "codec_upload",
            serde_json::json!({"id":id,"bytes":payload.len(),"offer":offer.bits()}),
        );
        q.send(id, &encode(mode)).await;
        let response = q.response(id).await;
        case.event("codec_download", serde_json::json!({"id":id,"wire_bytes":response.body.len(),"stats":format!("{:?}",q.conn.stats())}));
        let mut decoder = Decoder::new(mode);
        assert_eq!(decoder.feed(&response.body).unwrap(), payload);
        decoder.finish().unwrap();
    }
    driver.abort();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    origin.await.unwrap();
}

#[tokio::test]
async fn fifth_mixed_connection_is_admitted_with_default_limits() {
    let mut f = fixture();
    Arc::get_mut(&mut f.config).unwrap().limits = moon_naive_core::config::Limits::default();
    let server = network(&f, None).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let app = server.app.clone();
    let window = app.profile.connection_window();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let mut clients = Vec::new();
    let mut drivers = Vec::new();
    let mut quic = Vec::new();
    for index in 0..5 {
        if index % 2 == 0 {
            let (mut client, driver) = h2_client(tcp, &f.ca).await;
            let request = http::Request::builder()
                .uri("https://proxy.example.test/")
                .body(())
                .unwrap();
            let (response, _) = client.send_request(request, true).unwrap();
            assert_eq!(response.await.unwrap().status(), 200);
            clients.push(client);
            drivers.push(driver);
        } else {
            let mut client = QClient::new(udp, &f.ca).await;
            let id = client.request("GET", "proxy.example.test", Some("/"), None, false, true);
            assert_eq!(client.response(id).await.status, 200);
            quic.push(client);
        }
    }
    assert_eq!(
        app.resources.receive.available_permits(),
        f.config.limits.max_total_receive_bytes - 5 * window as usize
    );
    drop(clients);
    drop(quic);
    for driver in drivers {
        driver.abort();
    }
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(
        app.resources.receive.available_permits(),
        f.config.limits.max_total_receive_bytes
    );
}

#[tokio::test]
async fn expired_outer_gates_new_handshakes_but_does_not_stall_inner_loading() {
    let mut f = fixture();
    Arc::get_mut(&mut f.config)
        .unwrap()
        .limits
        .idle_timeout_secs = 30;
    let stored = DiskStore::open(&f.config.state_dir.join("certificates"))
        .unwrap()
        .read_current()
        .unwrap()
        .unwrap();
    let root = f._root.path();
    let cert = root.join("outer.pem");
    let private = root.join("outer.key");
    let keys = root.join("ech-expiry.toml");
    let outer_key = key();
    let mut expired = X509::builder().unwrap();
    expired.set_version(2).unwrap();
    expired
        .set_serial_number(&BigNum::from_u32(42).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "public.example.test")
        .unwrap();
    expired.set_subject_name(&name.build()).unwrap();
    expired
        .append_extension(&BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    expired
        .append_extension(&ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    expired.set_issuer_name(f.ca_cert.subject_name()).unwrap();
    expired.set_pubkey(&outer_key).unwrap();
    let now = crate::acme::now() as i64;
    expired
        .set_not_before(&Asn1Time::from_unix(now - 3600).unwrap())
        .unwrap();
    expired
        .set_not_after(&Asn1Time::from_unix(now + 10).unwrap())
        .unwrap();
    expired
        .append_extension(
            &SubjectAlternativeName::new()
                .dns("public.example.test")
                .build(&expired.x509v3_context(Some(&f.ca_cert), None))
                .unwrap(),
        )
        .unwrap();
    expired.sign(&f.ca_key, MessageDigest::sha256()).unwrap();
    std::fs::write(&cert, expired.build().to_pem().unwrap()).unwrap();
    std::fs::write(&private, outer_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o600)).unwrap();
    Arc::get_mut(&mut f.config).unwrap().ech = Some(moon_naive_core::config::Ech {
        public_name: "public.example.test".into(),
        certificate_file: cert.clone(),
        private_key_file: private.clone(),
        keys_file: keys,
    });
    tls::ech_command("init", &f.config).unwrap();
    let server = network(&f, None).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let slot = server.tls.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut existing, driver) = h2_client(tcp, &f.ca).await;
    assert_eq!(peer_serial(tcp, &f.ca).await, vec![2]);
    let until = (now + 11).saturating_sub(crate::acme::now() as i64) as u64;
    tokio::time::sleep(Duration::from_secs(until)).await;
    assert!(slot.current().is_err());
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(&f.ca).unwrap();
    connector.set_alpn_protos(b"\x02h2").unwrap();
    let socket = TcpStream::connect(tcp).await.unwrap();
    let rejected = tokio::time::timeout(
        Duration::from_secs(2),
        tokio_boring::connect(
            connector.build().configure().unwrap(),
            "proxy.example.test",
            socket,
        ),
    )
    .await
    .unwrap();
    assert!(
        rejected.is_err(),
        "outer expiry must gate new handshakes even with unchanged files"
    );
    rotate(&f);
    assert!(slot.refresh(&f.config).unwrap());
    assert!(slot.current().is_err());
    // Repair only outer; the new inner already loaded above must become active.
    std::fs::write(&cert, stored.candidate.chain_pem).unwrap();
    std::fs::write(&private, stored.candidate.key_pem).unwrap();
    assert!(slot.refresh(&f.config).unwrap());
    let request = http::Request::builder()
        .uri("https://proxy.example.test/")
        .body(())
        .unwrap();
    let (response, _) = existing.send_request(request, true).unwrap();
    assert_eq!(response.await.unwrap().status(), 200);
    assert_eq!(peer_serial(tcp, &f.ca).await, vec![3]);
    let client = QClient::new(udp, &f.ca).await;
    assert_eq!(
        serial(&X509::from_der(client.conn.peer_cert().unwrap()).unwrap()),
        vec![3]
    );
    drop(client);
    drop(existing);
    driver.abort();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

pub(crate) fn test_origin_tls_material() -> (boring::ssl::SslAcceptor, Vec<u8>) {
    let mut f = fixture();
    Arc::get_mut(&mut f.config).unwrap().listener.h1 = true;
    let generation = tls::Slot::load(&f.config).unwrap().current().unwrap();
    (generation.h2.clone(), std::fs::read(&f.ca).unwrap())
}

#[tokio::test]
async fn h3_partial_headers_have_absolute_deadline_while_other_requests_progress() {
    let mut f = fixture();
    Arc::get_mut(&mut f.config).unwrap().limits.max_streams = 100;
    Arc::get_mut(&mut f.config)
        .unwrap()
        .limits
        .idle_timeout_secs = 30;
    let server = network(&f, None).await;
    let udp = server.udp_addr().unwrap();
    let app = server.app.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let mut q = QClient::new(udp, &f.ca).await;
    // Reserve a distinct client request ID. HEADERS length=100, only QPACK
    // prefix supplied. No complete Headers event can be emitted for this stream.
    q.conn
        .stream_send(396, &[1, 0x40, 100, 0, 0], false)
        .unwrap();
    let start = std::time::Instant::now();
    let mut normal = 0;
    while start.elapsed() < Duration::from_secs(13) && q.conn.peer_error().is_none() {
        if start.elapsed() < Duration::from_secs(9) && normal < 40 {
            let id = q.request("GET", "proxy.example.test", Some("/"), None, false, true);
            assert_eq!(q.response(id).await.status, 200);
            normal += 1;
            tokio::time::sleep(Duration::from_millis(230)).await;
        } else {
            q.step().await;
        }
    }
    assert!(normal >= 20, "unrelated website requests must progress");
    assert_eq!(q.conn.peer_error().map(|e| e.error_code), Some(0x107));
    assert!(start.elapsed() < Duration::from_secs(12));
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(app.resources.requests.active(), 0);
    assert_eq!(app.resources.connections.active(), 0);
}

#[tokio::test]
async fn h3_fragmented_headers_and_reset_release_pending_deadlines() {
    let mut f = fixture();
    Arc::get_mut(&mut f.config).unwrap().limits.max_streams = 100;
    Arc::get_mut(&mut f.config)
        .unwrap()
        .limits
        .idle_timeout_secs = 30;
    let server = network(&f, None).await;
    let udp = server.udp_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let mut q = QClient::new(udp, &f.ca).await;
    let fields = [
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"proxy.example.test"),
        quiche::h3::Header::new(b":path", b"/"),
    ];
    let mut block = [0; 512];
    let n = quiche::h3::qpack::Encoder::new()
        .encode(&fields, &mut block)
        .unwrap();
    assert!(n < 64);
    let mut wire = vec![1, n as u8];
    wire.extend_from_slice(&block[..n]);
    for (i, b) in wire.iter().enumerate() {
        q.conn.stream_send(392, &[*b], i + 1 == wire.len()).unwrap();
        q.step().await;
    }
    assert_eq!(q.response(392).await.status, 200);
    q.conn.stream_send(396, &[1, 0x40, 100, 0], false).unwrap();
    for _ in 0..10 {
        q.step().await;
    }
    q.conn
        .stream_shutdown(396, quiche::Shutdown::Write, 0x10c)
        .unwrap();
    let start = std::time::Instant::now();
    while start.elapsed() < super::HEADER_TIMEOUT + Duration::from_millis(200) {
        q.step().await;
    }
    assert!(
        q.conn.peer_error().is_none(),
        "reset/complete headers must clear deadlines"
    );
    let id = q.request("GET", "proxy.example.test", Some("/"), None, false, true);
    assert_eq!(q.response(id).await.status, 200);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

mod performance;
