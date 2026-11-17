//! TLS observations use public handshake state only. Resumption tickets are
//! confined to an automatically removed private temporary directory.
use super::*;
use boring::ssl::SslVersion;
use std::net::SocketAddr;

async fn handshake(
    address: SocketAddr,
    ca: &Path,
    version: SslVersion,
    alpn: Option<&[u8]>,
) -> std::result::Result<tokio_boring::SslStream<TcpStream>, String> {
    let mut connector = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
    connector.set_ca_file(ca).map_err(|e| e.to_string())?;
    connector
        .set_min_proto_version(Some(version))
        .map_err(|e| e.to_string())?;
    connector
        .set_max_proto_version(Some(version))
        .map_err(|e| e.to_string())?;
    if let Some(protocols) = alpn {
        connector
            .set_alpn_protos(protocols)
            .map_err(|e| e.to_string())?;
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        let socket = TcpStream::connect(address)
            .await
            .map_err(|e| e.to_string())?;
        tokio_boring::connect(
            connector.build().configure().map_err(|e| e.to_string())?,
            "proxy.example.test",
            socket,
        )
        .await
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "handshake_timeout".to_owned())?
}
fn public_handshake(stream: &tokio_boring::SslStream<TcpStream>) -> Value {
    let mut info = tls_info(stream.ssl());
    info["certificate_chain_sha256"] = json!(stream.ssl().peer_cert_chain().map(|chain| {
        chain
            .iter()
            .map(|cert| hash(&cert.to_der().unwrap()))
            .collect::<Vec<_>>()
    }));
    info["handshake"] = json!("accepted");
    info
}

fn openssl_attempt(
    address: SocketAddr,
    ca: &Path,
    session: &Path,
    version: &str,
    resume: bool,
) -> Value {
    use std::io::{Read, Write};
    let mut command = Command::new("openssl");
    command
        .args([
            "s_client",
            "-connect",
            &address.to_string(),
            "-servername",
            "proxy.example.test",
            "-verify_return_error",
            "-verify_hostname",
            "proxy.example.test",
            "-alpn",
            "http/1.1",
            "-ign_eof",
            version,
        ])
        .arg("-CAfile")
        .arg(ca)
        .arg(if resume { "-sess_in" } else { "-sess_out" })
        .arg(session)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => Process(child),
        Err(_) => return json!({"available":false,"outcome":"optional_openssl_client_unavailable"}),
    };
    if let Some(mut input) = child.0.stdin.take() {
        let _ = input
            .write_all(b"GET / HTTP/1.1\r\nHost: proxy.example.test\r\nConnection: close\r\n\r\n");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let exit = loop {
        match child.0.try_wait() {
            Ok(Some(status)) => break Some(status.code()),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.0.kill();
                let _ = child.0.wait();
                break None;
            }
        }
    };
    // OpenSSL's ordinary diagnostic output can contain session secrets. Parse
    // it only in memory; persist exclusively these explicit public predicates.
    let mut output = Vec::new();
    if let Some(mut pipe) = child.0.stdout.take() {
        let _ = pipe.read_to_end(&mut output);
    }
    let text = String::from_utf8_lossy(&output);
    let reused = text.lines().any(|line| line.starts_with("Reused, "));
    let handshake = reused || text.lines().any(|line| line.starts_with("New, TLS"));
    json!({"available":true,"handshake_completed":handshake,"resumed":reused,
        "session_offered":resume,"session_file_created":session.is_file(),"exit_code":exit,
        "outcome":if exit.is_none() {"timeout"} else {"completed"}})
}
async fn resumption(address: SocketAddr, ca: &Path, version: &'static str) -> Value {
    let ca = ca.to_owned();
    tokio::task::spawn_blocking(move || {
        let client_version = Command::new("openssl").arg("version").output().ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());
        let secret = tempfile::tempdir().unwrap();
        let session = secret.path().join("session.pem");
        let first = openssl_attempt(address, &ca, &session, version, false);
        let second = if session.is_file() {
            openssl_attempt(address, &ca, &session, version, true)
        } else {
            json!({"outcome":"not_attempted_no_session_issued"})
        };
        // Session path and bytes never enter the report; TempDir removes both.
        json!({"implementation":"openssl_s_client","client_version":client_version,"initial":first,"reconnect":second})
    })
    .await
    .unwrap()
}

pub(super) async fn observe(
    tcp: SocketAddr,
    _udp: SocketAddr,
    ca: &Path,
) -> Vec<(&'static str, &'static str, Value)> {
    let mut observations = Vec::new();
    for (name, version, alpn) in [
        (
            "tls12_h1_negotiation",
            SslVersion::TLS1_2,
            Some(b"\x08http/1.1".as_slice()),
        ),
        (
            "tls13_h1_negotiation",
            SslVersion::TLS1_3,
            Some(b"\x08http/1.1".as_slice()),
        ),
        (
            "tls13_h2_negotiation",
            SslVersion::TLS1_3,
            Some(b"\x02h2".as_slice()),
        ),
        (
            "tls13_unsupported_alpn",
            SslVersion::TLS1_3,
            Some(b"\x0cmona-invalid".as_slice()),
        ),
        ("tls13_absent_alpn", SslVersion::TLS1_3, None),
    ] {
        let observation = match handshake(tcp, ca, version, alpn).await {
            Ok(stream) => public_handshake(&stream),
            Err(error) => json!({"handshake":"rejected","error":error}),
        };
        observations.push(("tls", name, observation));
    }
    // Read actual server-driven connection termination after Connection: close;
    // distinguish a clean TLS EOF, truncation/error, and a stalled connection.
    let shutdown = match handshake(tcp, ca, SslVersion::TLS1_3, Some(b"\x08http/1.1")).await {
        Ok(mut stream) => {
            let write = stream
                .write_all(
                    b"GET / HTTP/1.1\r\nHost: proxy.example.test\r\nConnection: close\r\n\r\n",
                )
                .await;
            if write.is_err() {
                json!({"outcome":"request_write_failed"})
            } else {
                let mut wire = Vec::new();
                let read = tokio::time::timeout(
                    Duration::from_secs(4),
                    (&mut stream).take(65536).read_to_end(&mut wire),
                )
                .await;
                json!({"outcome":match read { Ok(Ok(_))=>"tls_eof",Ok(Err(_))=>"tls_read_error",Err(_)=>"timeout" },
                    "response_received":wire.starts_with(b"HTTP/1.1 "),"response_bytes":wire.len(),
                    "bounded_read":wire.len()==65536})
            }
        }
        Err(_) => json!({"outcome":"handshake_rejected"}),
    };
    observations.push(("tls", "connection_close", shutdown));
    observations.push((
        "tls",
        "tls12_session_resumption",
        resumption(tcp, ca, "-tls1_2").await,
    ));
    observations.push((
        "tls",
        "tls13_session_resumption",
        resumption(tcp, ca, "-tls1_3").await,
    ));
    observations
}
