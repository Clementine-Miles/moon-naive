//! Optional cross-stack wire observations. Secrets live only in a temporary fixture.
use super::*;
mod malformed;
mod tls;
mod transport;
use serde_json::{Value, json};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Instant,
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn hash(bytes: &[u8]) -> String {
    boring::sha::sha256(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn validate_alt_svc<'a>(fields: impl Iterator<Item = (&'a str, &'a [u8])>, udp_port: u16) {
    for (_, value) in fields.filter(|(name, _)| name.eq_ignore_ascii_case("alt-svc")) {
        let value = std::str::from_utf8(value).expect("Alt-Svc must be ASCII");
        for alternative in value.split(',') {
            if let Some((protocol, authority)) = alternative.trim().split_once('=')
                && protocol == "h3"
            {
                assert_eq!(
                    authority.split(';').next().unwrap().trim(),
                    format!("\":{udp_port}\""),
                    "Alt-Svc must advertise the actual bound UDP endpoint"
                );
            }
        }
    }
}
fn headers<'a>(fields: impl Iterator<Item = (&'a str, &'a [u8])>) -> Value {
    // Preserve duplicate fields and observed order. Dynamic values are marked,
    // not silently discarded; response auth proofs are never persisted.
    json!(
        fields
            .map(|(name, value)| (
                name.to_ascii_lowercase(),
                if name.eq_ignore_ascii_case("date") {
                    "<dynamic-date>".to_owned()
                } else if name.eq_ignore_ascii_case("alt-svc") {
                    {
                        let text = String::from_utf8_lossy(value);
                        if let Some(start) = text.find("\":") {
                            let tail = &text[start + 2..];
                            if let Some(end) = tail.find('"') {
                                if tail[..end].bytes().all(|b| b.is_ascii_digit()) {
                                    format!("{}<bound-port>{}", &text[..start + 2], &tail[end..])
                                } else {
                                    text.into_owned()
                                }
                            } else {
                                text.into_owned()
                            }
                        } else {
                            text.into_owned()
                        }
                    }
                } else if name.eq_ignore_ascii_case("proxy-authentication-info") {
                    "<redacted-auth-proof>".to_owned()
                } else {
                    String::from_utf8_lossy(value).into_owned()
                }
            ))
            .collect::<Vec<_>>()
    )
}
fn body_shape(bytes: &[u8]) -> Value {
    json!({"length":bytes.len(),"sha256":hash(bytes)})
}
fn tls_info(ssl: &boring::ssl::SslRef) -> Value {
    json!({"version":ssl.version_str(),"alpn":ssl.selected_alpn_protocol().map(|v|String::from_utf8_lossy(v).into_owned()),"cipher":ssl.current_cipher().map(|v|v.name()),"certificate_sha256":ssl.peer_certificate().map(|c|hash(&c.to_der().unwrap())),"chain_length":ssl.peer_cert_chain().map(|c|c.len()),"session_reused":ssl.session_reused()})
}
async fn tls_stream(
    address: std::net::SocketAddr,
    ca: &Path,
    alpn: &[u8],
) -> tokio_boring::SslStream<TcpStream> {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(ca).unwrap();
    connector.set_alpn_protos(alpn).unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        tokio_boring::connect(
            connector.build().configure().unwrap(),
            "proxy.example.test",
            TcpStream::connect(address).await.unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap()
}
#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    method: &'static str,
    path: Option<&'static str>,
    auth: Option<&'static str>,
    duplicate: bool,
    host: Option<&'static str>,
}
const CASES: &[Case] = &[
    Case {
        name: "normal",
        method: "GET",
        path: Some("/"),
        auth: None,
        duplicate: false,
        host: None,
    },
    Case {
        name: "head",
        method: "HEAD",
        path: Some("/"),
        auth: None,
        duplicate: false,
        host: None,
    },
    Case {
        name: "not_found",
        method: "GET",
        path: Some("/missing"),
        auth: None,
        duplicate: false,
        host: None,
    },
    Case {
        name: "wrong_authentication",
        method: "GET",
        path: Some("/"),
        auth: Some("Basic wrong"),
        duplicate: false,
        host: None,
    },
    Case {
        name: "malformed_authentication",
        method: "GET",
        path: Some("/"),
        auth: Some("MoonNaive broken"),
        duplicate: false,
        host: None,
    },
    Case {
        name: "duplicate_authentication",
        method: "GET",
        path: Some("/"),
        auth: Some("Basic wrong"),
        duplicate: true,
        host: None,
    },
    Case {
        name: "connect_missing_authentication",
        method: "CONNECT",
        path: None,
        auth: None,
        duplicate: false,
        host: None,
    },
    Case {
        name: "connect_wrong_authentication",
        method: "CONNECT",
        path: None,
        auth: Some("Basic wrong"),
        duplicate: false,
        host: None,
    },
    Case {
        name: "invalid_connect_authority",
        method: "CONNECT",
        path: None,
        auth: None,
        duplicate: false,
        host: None,
    },
    Case {
        name: "conflicting_authority",
        method: "GET",
        path: Some("/"),
        auth: None,
        duplicate: false,
        host: Some("other.example.test"),
    },
];
fn authority(case: Case) -> &'static str {
    if case.name == "invalid_connect_authority" {
        "example.org"
    } else if case.method == "CONNECT" {
        "example.org:443"
    } else {
        "proxy.example.test"
    }
}
async fn h1_case(address: std::net::SocketAddr, ca: &Path, case: Case, udp_port: u16) -> Value {
    let mut io = tls_stream(address, ca, b"\x08http/1.1").await;
    let tls = tls_info(io.ssl());
    let target = if case.method == "CONNECT" {
        authority(case)
    } else {
        case.path.unwrap()
    };
    let host = case.host.unwrap_or("proxy.example.test");
    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n",
        case.method, target
    );
    if let Some(auth) = case.auth {
        request.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
        if case.duplicate {
            request.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
        }
    }
    request.push_str("\r\n");
    io.write_all(request.as_bytes()).await.unwrap();
    let mut data = Vec::new();
    let outcome =
        match tokio::time::timeout(Duration::from_secs(4), io.read_to_end(&mut data)).await {
            Ok(Ok(_)) => "eof",
            Ok(Err(_)) => "io_error",
            Err(_) => "timeout",
        };
    let split = data
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(data.len());
    let head = String::from_utf8_lossy(&data[..split]);
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok());
    let fields = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n, v.trim_start().as_bytes()))
        .collect::<Vec<_>>();
    validate_alt_svc(fields.iter().map(|(name, value)| (*name, *value)), udp_port);
    json!({"outcome":outcome,"status":status,"headers":headers(fields.into_iter()),"body":body_shape(&data[split..]),"tls":tls,"connection":"request explicitly asked for close"})
}
async fn h2_case(address: std::net::SocketAddr, ca: &Path, case: Case, udp_port: u16) -> Value {
    let io = tls_stream(address, ca, b"\x02h2").await;
    let tls = tls_info(io.ssl());
    let (mut sender, driver) = ::h2::client::Builder::new()
        .handshake::<_, Bytes>(io)
        .await
        .unwrap();
    let driver = tokio::spawn(driver);
    let uri = if case.method == "CONNECT" {
        authority(case).to_owned()
    } else {
        format!(
            "https://{}{}/",
            authority(case),
            case.path.unwrap().trim_end_matches('/')
        )
    };
    // Normal URI construction below preserves the exact test path.
    let uri = if case.method == "CONNECT" {
        uri
    } else {
        format!("https://{}{}", authority(case), case.path.unwrap())
    };
    let mut request = http::Request::builder().method(case.method).uri(uri);
    if let Some(auth) = case.auth {
        request = request.header("proxy-authorization", auth);
        if case.duplicate {
            request = request.header("proxy-authorization", auth);
        }
    }
    if let Some(host) = case.host {
        request = request.header("host", host);
    }
    let sent = sender.send_request(request.body(()).unwrap(), true);
    let mut observation = json!({"tls":tls});
    match sent {
        Err(error) => {
            observation["outcome"] = json!(format!("local_client_rejection:{:?}", error.reason()))
        }
        Ok((response, _)) => match tokio::time::timeout(Duration::from_secs(4), response).await {
            Ok(Ok(response)) => {
                let status = response.status().as_u16();
                validate_alt_svc(
                    response
                        .headers()
                        .iter()
                        .map(|(name, value)| (name.as_str(), value.as_bytes())),
                    udp_port,
                );
                let fields = headers(
                    response
                        .headers()
                        .iter()
                        .map(|(n, v)| (n.as_str(), v.as_bytes())),
                );
                let body = body(response.into_body()).await;
                observation["status"] = json!(status);
                observation["headers"] = fields;
                observation["body"] = body_shape(&body);
                observation["outcome"] = json!("finished");
            }
            Ok(Err(error)) => {
                observation["outcome"] = json!("transport_rejection");
                observation["error_code"] = json!(error.reason().map(u32::from));
            }
            Err(_) => observation["outcome"] = json!("timeout"),
        },
    }
    // A second request distinguishes a stream rejection from connection loss.
    observation["reuse"] = json!(
        match tokio::time::timeout(Duration::from_secs(1), sender.ready()).await {
            Ok(Ok(mut sender)) => match sender.send_request(
                http::Request::builder()
                    .uri("https://proxy.example.test/")
                    .body(())
                    .unwrap(),
                true
            ) {
                Ok((response, _)) => matches!(
                    tokio::time::timeout(Duration::from_secs(1), response).await,
                    Ok(Ok(_))
                ),
                Err(_) => false,
            },
            _ => false,
        }
    );
    driver.abort();
    observation
}
async fn h2_wire(address: std::net::SocketAddr, ca: &Path) -> Value {
    let mut io = tls_stream(address, ca, b"\x02h2").await;
    let mut frames = Vec::new();
    io.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0")
        .await
        .unwrap();
    // Read startup frames, acknowledge SETTINGS, then a zero-length PING
    // (a deliberate FRAME_SIZE_ERROR). No authenticated bytes are captured.
    let mut injected = false;
    for _ in 0..12 {
        let mut head = [0; 9];
        if !matches!(
            tokio::time::timeout(Duration::from_millis(300), io.read_exact(&mut head)).await,
            Ok(Ok(_))
        ) {
            break;
        }
        let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
        if len > 65536 {
            break;
        }
        let mut payload = vec![0; len];
        if io.read_exact(&mut payload).await.is_err() {
            break;
        }
        let id = u32::from_be_bytes(head[5..9].try_into().unwrap()) & 0x7fff_ffff;
        let mut item = json!({"type":head[3],"flags":head[4],"stream":id,"length":len});
        if head[3] == 4 && head[4] & 1 == 0 {
            item["settings"] = json!(
                payload
                    .as_chunks::<6>()
                    .0
                    .iter()
                    .map(|v| (
                        u16::from_be_bytes(v[..2].try_into().unwrap()),
                        u32::from_be_bytes(v[2..].try_into().unwrap())
                    ))
                    .collect::<Vec<_>>()
            );
        }
        if head[3] == 8 && len == 4 {
            item["increment"] =
                json!(u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff);
        }
        if head[3] == 7 && len >= 8 {
            item["last_stream"] =
                json!(u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff);
            item["error_code"] = json!(u32::from_be_bytes(payload[4..8].try_into().unwrap()));
        }
        frames.push(item);
        if head[3] == 4 && head[4] & 1 == 0 && !injected {
            io.write_all(b"\0\0\0\x04\x01\0\0\0\0\0\0\0\x06\0\0\0\0\0")
                .await
                .unwrap();
            injected = true;
        }
        if head[3] == 7 {
            break;
        }
    }
    json!({"frames":frames,"outcome":"raw_settings_ack_and_invalid_ping_probe"})
}
async fn close_quic(client: &mut QClient) {
    let _ = client.conn.close(true, 0x100, b"");
    let mut packet = [0; 1350];
    for _ in 0..32 {
        match client.conn.send(&mut packet) {
            Ok((n, info)) => {
                let _ = client.socket.send_to(&packet[..n], info.to).await;
            }
            Err(_) => break,
        }
    }
    tokio::task::yield_now().await;
}
fn quic_parameters(c: &QClient) -> Value {
    let p = c.conn.peer_transport_params().unwrap();
    let settings = c.h3.as_ref().unwrap().peer_settings_raw().map(|values| {
        values
            .iter()
            .map(|&(id, value)| {
                if id >= 0x21 && (id - 0x21).is_multiple_of(0x1f) {
                    json!(["<dynamic-reserved-grease-id>", "<dynamic-grease-value>"])
                } else {
                    json!([id, value])
                }
            })
            .collect::<Vec<_>>()
    });
    json!({"max_idle_timeout_ms":p.max_idle_timeout,"max_udp_payload_size":p.max_udp_payload_size,"initial_max_data":p.initial_max_data,"initial_max_stream_data_bidi_local":p.initial_max_stream_data_bidi_local,"initial_max_stream_data_bidi_remote":p.initial_max_stream_data_bidi_remote,"initial_max_stream_data_uni":p.initial_max_stream_data_uni,"initial_max_streams_bidi":p.initial_max_streams_bidi,"initial_max_streams_uni":p.initial_max_streams_uni,"ack_delay_exponent":p.ack_delay_exponent,"max_ack_delay_ms":p.max_ack_delay,"disable_active_migration":p.disable_active_migration,"active_connection_id_limit":p.active_conn_id_limit,"retry_observed":p.retry_source_connection_id.is_some(),"h3_settings":settings})
}
async fn h3_case(address: std::net::SocketAddr, ca: &Path, case: Case) -> Value {
    let mut client = QClient::new(address, ca).await;
    let tls = json!({"version":client.conn.as_mut().version_str(),"alpn":String::from_utf8_lossy(client.conn.application_proto()),"cipher":client.conn.as_mut().current_cipher().map(|v|v.name()),"certificate_sha256":client.conn.peer_cert().map(hash),"chain_length":client.conn.peer_cert_chain().map(|v|v.len()),"session_reused":client.conn.as_mut().session_reused()});
    let mut fields = vec![
        quiche::h3::Header::new(b":method", case.method.as_bytes()),
        quiche::h3::Header::new(b":authority", authority(case).as_bytes()),
    ];
    if let Some(path) = case.path {
        fields.push(quiche::h3::Header::new(b":scheme", b"https"));
        fields.push(quiche::h3::Header::new(b":path", path.as_bytes()));
    }
    if let Some(auth) = case.auth {
        fields.push(quiche::h3::Header::new(
            b"proxy-authorization",
            auth.as_bytes(),
        ));
        if case.duplicate {
            fields.push(quiche::h3::Header::new(
                b"proxy-authorization",
                auth.as_bytes(),
            ));
        }
    }
    if let Some(host) = case.host {
        fields.push(quiche::h3::Header::new(b"host", host.as_bytes()));
    }
    let mut result = json!({"tls":tls});
    let id = match client.send_headers(&fields, true) {
        Ok(id) => id,
        Err(_) => {
            result["outcome"] = json!("local_client_rejection");
            result["wire_sent"] = json!(false);
            close_quic(&mut client).await;
            return result;
        }
    };
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut response_headers = Vec::new();
    let mut response_body = Vec::new();
    let mut status = None;
    let mut injected_packets = 0;
    'drive: loop {
        let mut out = [0; 1350];
        while let Ok((n, info)) = client.conn.send(&mut out) {
            if case.name == "single_datagram_loss" && injected_packets == 0 {
                injected_packets += 1;
                continue;
            }
            if case.name == "delayed_delivery" && injected_packets == 0 {
                injected_packets += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            client.socket.send_to(&out[..n], info.to).await.unwrap();
            if case.name == "duplicate_datagrams" {
                client.socket.send_to(&out[..n], info.to).await.unwrap();
                injected_packets += 1;
            }
        }
        let mut input = [0; 65535];
        if let Ok(Ok((n, from))) = tokio::time::timeout(
            Duration::from_millis(2),
            client.socket.recv_from(&mut input),
        )
        .await
        {
            let _ = client.conn.recv(
                &mut input[..n],
                quiche::RecvInfo {
                    from,
                    to: client.socket.local_addr().unwrap(),
                },
            );
        }
        if client
            .conn
            .timeout_instant()
            .is_some_and(|t| t <= Instant::now())
        {
            client.conn.on_timeout();
        }
        use quiche::h3::{Event, NameValue};
        loop {
            match client.h3.as_mut().unwrap().poll(&mut client.conn) {
                Ok((stream, Event::Headers { list, .. })) if stream == id => {
                    for h in list {
                        if h.name() == b":status" {
                            status = std::str::from_utf8(h.value())
                                .ok()
                                .and_then(|v| v.parse::<u16>().ok());
                        } else {
                            response_headers.push((
                                String::from_utf8_lossy(h.name()).into_owned(),
                                h.value().to_vec(),
                            ));
                        }
                    }
                }
                Ok((stream, Event::Data)) if stream == id => {
                    let mut chunk = [0; 16384];
                    while let Ok(n) =
                        client
                            .h3
                            .as_mut()
                            .unwrap()
                            .recv_body(&mut client.conn, id, &mut chunk)
                    {
                        if n == 0 {
                            break;
                        }
                        response_body.extend_from_slice(&chunk[..n]);
                    }
                }
                Ok((stream, Event::Finished)) if stream == id => {
                    result["outcome"] = json!("finished");
                    break 'drive;
                }
                Ok((stream, Event::Reset(code))) if stream == id => {
                    result["outcome"] = json!("stream_reset");
                    result["error_code"] = json!(code);
                    break 'drive;
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(error) => {
                    result["outcome"] = json!(format!("h3_error:{error:?}"));
                    break 'drive;
                }
            }
        }
        if client.conn.is_closed() || client.conn.is_draining() {
            result["outcome"] = json!("connection_closed");
            result["error_code"] = json!(client.conn.peer_error().map(|e| e.error_code));
            break;
        }
        if Instant::now() > deadline {
            result["outcome"] = json!("timeout");
            break;
        }
    }
    result["status"] = json!(status);
    validate_alt_svc(
        response_headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice())),
        address.port(),
    );
    result["headers"] = headers(
        response_headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_slice())),
    );
    result["body"] = body_shape(&response_body);
    result["transport"] = quic_parameters(&client);
    if [
        "single_datagram_loss",
        "delayed_delivery",
        "duplicate_datagrams",
    ]
    .contains(&case.name)
    {
        let stats = client.conn.stats();
        result["experiment"] = json!({"injected_datagrams":injected_packets,"delay_ms":if case.name=="delayed_delivery" {50}else{0},"network_model":"bounded client UDP write perturbation after handshake; not kernel path emulation"});
        result["client_packet_statistics"] = json!({"sent":stats.sent,"received":stats.recv,"lost":stats.lost,"retransmitted":stats.retrans,"paths":stats.paths_count});
    }
    close_quic(&mut client).await;
    result
}
async fn authenticated_h2(address: std::net::SocketAddr, ca: &Path) -> Vec<(&'static str, Value)> {
    let (mut client, driver) = h2_client(address, ca).await;
    let request = http::Request::builder()
        .method("CONNECT")
        .uri("example.org:443")
        .header("proxy-authorization", auth())
        .body(())
        .unwrap();
    let (response, mut upload) = client.send_request(request, false).unwrap();
    v2_send(&mut upload, frame(b"differential-test"), true).await;
    let response = tokio::time::timeout(Duration::from_secs(4), response)
        .await
        .unwrap();
    let mut result = Vec::new();
    if let Ok(response) = response {
        let status = response.status().as_u16();
        let fields = headers(
            response
                .headers()
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_bytes())),
        );
        let bytes = body(response.into_body()).await;
        let echo = status == 200 && unframe(&bytes) == b"differential-test";
        result.push(("valid_connect",json!({"status":status,"headers":fields,"body":body_shape(&bytes),"framed_echo_verified":echo,"outcome":"finished"})));
    } else {
        result.push(("valid_connect", json!({"outcome":"transport_rejection"})));
    }
    let old = client.last_proof.clone().unwrap();
    let (response, _) = client
        .send_request(
            http::Request::builder()
                .method("CONNECT")
                .uri("example.org:443")
                .header("proxy-authorization", &old)
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    let value = match tokio::time::timeout(Duration::from_secs(4), response).await {
        Ok(Ok(response)) => {
            json!({"status":response.status().as_u16(),"outcome":"finished","body":body_shape(&body(response.into_body()).await)})
        }
        _ => json!({"outcome":"transport_rejection"}),
    };
    result.push(("proof_replayed_on_wrong_stream", value));
    driver.abort();
    let (mut other, driver) = h2_client(address, ca).await;
    let (response, _) = other
        .send_request(
            http::Request::builder()
                .method("CONNECT")
                .uri("example.org:443")
                .header("proxy-authorization", old)
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    let value = match tokio::time::timeout(Duration::from_secs(4), response).await {
        Ok(Ok(response)) => {
            json!({"status":response.status().as_u16(),"outcome":"finished","body":body_shape(&body(response.into_body()).await)})
        }
        _ => json!({"outcome":"transport_rejection"}),
    };
    result.push(("proof_bound_to_wrong_connection", value));
    driver.abort();
    result
}
async fn authenticated_h3(address: std::net::SocketAddr, ca: &Path) -> Vec<(&'static str, Value)> {
    let mut client = QClient::new(address, ca).await;
    let old = proof(
        &moon_naive_core::auth::Binding {
            exporter: super::super::exporter(client.conn.as_mut()).unwrap(),
            stream_id: 0,
        },
        "CONNECT",
        "example.org:443",
        None,
        None,
        None,
    );
    let id = client.request(
        "CONNECT",
        "example.org:443",
        None,
        Some(&auth()),
        false,
        false,
    );
    client.send(id, &frame(b"differential-test")).await;
    let response = client.response(id).await;
    let echo = response.status == 200 && unframe(&response.body) == b"differential-test";
    let mut result = vec![(
        "valid_connect",
        json!({"status":response.status,"headers":headers(response.headers.iter().map(|(n,v)|(n.as_str(),v.as_bytes()))),"body":body_shape(&response.body),"framed_echo_verified":echo,"outcome":if response.reset {"stream_reset"} else {"finished"}}),
    )];
    let id = client.request("CONNECT", "example.org:443", None, Some(&old), false, true);
    let response = client.response(id).await;
    result.push(("proof_replayed_on_wrong_stream",json!({"status":response.status,"outcome":if response.reset {"stream_reset"} else {"finished"},"body":body_shape(&response.body)})));
    let mut other = QClient::new(address, ca).await;
    let id = other.request("CONNECT", "example.org:443", None, Some(&old), false, true);
    let response = other.response(id).await;
    result.push(("proof_bound_to_wrong_connection",json!({"status":response.status,"outcome":if response.reset {"stream_reset"} else {"finished"},"body":body_shape(&response.body)})));
    close_quic(&mut client).await;
    close_quic(&mut other).await;
    result
}
async fn append(
    records: &mut Vec<Value>,
    server: &str,
    protocol: &str,
    case: &str,
    repetition: usize,
    mut value: Value,
    elapsed: Duration,
) {
    value["server"] = json!(server);
    value["protocol"] = json!(protocol);
    value["case"] = json!(case);
    value["repetition"] = json!(repetition);
    value["elapsed_micros"] = if elapsed.is_zero() {
        Value::Null
    } else {
        json!(elapsed.as_micros() as u64)
    };
    records.push(value);
}
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
#[tokio::test]
#[ignore = "optional independent Caddy differential experiment; use cargo xtask differential"]
async fn independent_reference_matrix() {
    let executable = std::env::var_os("MOON_DIFF_CADDY").expect("MOON_DIFF_CADDY required");
    let report = PathBuf::from(std::env::var_os("MOON_DIFF_RUN").expect("MOON_DIFF_RUN required"));
    let mut f = fixture();
    Arc::get_mut(&mut f.config).unwrap().listener.h1 = true;
    let stored = DiskStore::open(&f.config.state_dir.join("certificates"))
        .unwrap()
        .read_current()
        .unwrap()
        .unwrap();
    let private = tempfile::tempdir().unwrap();
    let cert = private.path().join("certificate.pem");
    let key = private.path().join("private.pem");
    std::fs::write(&cert, &stored.candidate.chain_pem).unwrap();
    std::fs::write(&key, &stored.candidate.key_pem).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let upstream = &f.config.website.upstreams[0].origins[0];
    let dial = upstream.strip_prefix("http://").unwrap();
    let port = free_port();
    let reference: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let config = json!({"admin":{"disabled":true},"logging":{"logs":{"default":{"level":"ERROR"}}},"apps":{"tls":{"certificates":{"load_files":[{"certificate":cert,"key":key}]}},"http":{"servers":{"differential":{"listen":[reference.to_string()],"protocols":["h1","h2","h3"],"tls_connection_policies":[{"protocol_min":"tls1.2","protocol_max":"tls1.3"}],"automatic_https":{"disable":true},"routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":dial}]}]}]}}}}});
    let config_file = private.path().join("caddy.json");
    std::fs::write(&config_file, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut caddy = Process(
        Command::new(executable)
            .args(["run", "--config"])
            .arg(&config_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    loop {
        assert!(
            caddy.0.try_wait().unwrap().is_none(),
            "reference process exited during startup"
        );
        if TcpStream::connect(reference).await.is_ok() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "reference did not become ready"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_address = echo_listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        loop {
            let (mut socket, _) = echo_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                if socket.read_to_end(&mut bytes).await.is_ok() {
                    let _ = socket.write_all(&bytes).await;
                    let _ = socket.shutdown().await;
                }
            });
        }
    });
    // Bind before loading App: website Alt-Svc and self-destination policy must
    // observe the actual ephemeral endpoints, rather than fixture defaults.
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let configuration = Arc::get_mut(&mut f.config).unwrap();
    configuration.listener.tcp = tcp.local_addr().unwrap();
    configuration.listener.udp = udp.local_addr().unwrap();
    let mut app = App::load(&f.config).unwrap();
    app.egress.test_target = Some(echo_address);
    let server = Network {
        redirect: None,
        stats: app.stats.clone(),
        app: Arc::new(app),
        tls: super::super::tls::Slot::load(&f.config).unwrap(),
        tcp: Some(tcp),
        udp: Some(udp),
        additional: Vec::new(),
        connections: Budget::new(8).unwrap(),
        config: f.config.clone(),
    };

    let moon_tcp = server.tcp_addr().unwrap();
    let moon_udp = server.udp_addr().unwrap();
    let stats = server.stats.clone();
    let connection_budget = server.connections.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let mut capture = None;
    if let Some(tcpdump) = std::env::var_os("MOON_DIFF_TCPDUMP") {
        let filter = format!(
            "(tcp port {} or udp port {} or port {}) and host 127.0.0.1",
            moon_tcp.port(),
            moon_udp.port(),
            port
        );
        let child = Command::new(tcpdump)
            .args(["-i", "lo", "-U", "-s", "0", "-w"])
            .arg(report.join("encrypted-transport.pcap"))
            .arg(filter)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("optional tcpdump could not start");
        capture = Some(Process(child));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            capture.as_mut().unwrap().0.try_wait().unwrap().is_none(),
            "optional tcpdump failed"
        );
    }
    let mut records = Vec::new();
    for repetition in 0..3 {
        for (name, tcp, udp) in [
            ("moon", moon_tcp, moon_udp),
            ("reference", reference, reference),
        ] {
            for case in CASES {
                for protocol in ["h1", "h2", "h3"] {
                    let started = Instant::now();
                    let result = match protocol {
                        "h1" => h1_case(tcp, &f.ca, *case, udp.port()).await,
                        "h2" => h2_case(tcp, &f.ca, *case, udp.port()).await,
                        _ => h3_case(udp, &f.ca, *case).await,
                    };
                    append(
                        &mut records,
                        name,
                        protocol,
                        case.name,
                        repetition,
                        result,
                        started.elapsed(),
                    )
                    .await;
                }
            }
            for name_case in [
                "single_datagram_loss",
                "delayed_delivery",
                "duplicate_datagrams",
            ] {
                let case = Case {
                    name: name_case,
                    method: "GET",
                    path: Some("/"),
                    auth: None,
                    duplicate: false,
                    host: None,
                };
                let started = Instant::now();
                let value = h3_case(udp, &f.ca, case).await;
                assert_eq!(
                    value["status"], 200,
                    "bounded QUIC perturbation must still serve website"
                );
                append(
                    &mut records,
                    name,
                    "h3",
                    name_case,
                    repetition,
                    value,
                    started.elapsed(),
                )
                .await;
            }
            for (protocol, case, value) in malformed::observe(tcp, udp, &f.ca).await {
                append(
                    &mut records,
                    name,
                    protocol,
                    case,
                    repetition,
                    value,
                    Duration::ZERO,
                )
                .await;
            }
            for (protocol, case, value) in transport::observe(tcp, udp, &f.ca).await {
                append(
                    &mut records,
                    name,
                    protocol,
                    case,
                    repetition,
                    value,
                    Duration::ZERO,
                )
                .await;
            }
            for (protocol, case, value) in tls::observe(tcp, udp, &f.ca).await {
                append(
                    &mut records,
                    name,
                    protocol,
                    case,
                    repetition,
                    value,
                    Duration::ZERO,
                )
                .await;
            }
            let started = Instant::now();
            let wire = h2_wire(tcp, &f.ca).await;
            append(
                &mut records,
                name,
                "h2",
                "settings_ack_invalid_ping",
                repetition,
                wire,
                started.elapsed(),
            )
            .await;
        }
    }
    assert_eq!(
        stats.dials.load(Ordering::Relaxed),
        0,
        "unauthenticated differential cases must never dial proxy destinations"
    );
    for record in records
        .iter()
        .filter(|r| r["server"] == "moon" && r["protocol"] == "h3" && r.get("transport").is_some())
    {
        assert_eq!(record["transport"]["disable_active_migration"], true);
    }
    for repetition in 0..3 {
        for (name, tcp, udp) in [
            ("moon", moon_tcp, moon_udp),
            ("reference", reference, reference),
        ] {
            let before = stats.dials.load(Ordering::Relaxed);
            for (case, value) in authenticated_h2(tcp, &f.ca).await {
                if name == "moon" {
                    if case == "valid_connect" {
                        assert_eq!(value["status"], 200);
                        assert_eq!(value["framed_echo_verified"], true);
                    } else {
                        assert_ne!(value["status"], 200);
                    }
                }
                append(
                    &mut records,
                    name,
                    "h2",
                    case,
                    repetition,
                    value,
                    Duration::ZERO,
                )
                .await;
            }
            for (case, value) in authenticated_h3(udp, &f.ca).await {
                if name == "moon" {
                    if case == "valid_connect" {
                        assert_eq!(value["status"], 200);
                        assert_eq!(value["framed_echo_verified"], true);
                    } else {
                        assert_ne!(value["status"], 200);
                    }
                }
                append(
                    &mut records,
                    name,
                    "h3",
                    case,
                    repetition,
                    value,
                    Duration::ZERO,
                )
                .await;
            }
            if name == "moon" {
                assert_eq!(
                    stats.dials.load(Ordering::Relaxed) - before,
                    2,
                    "only two fresh valid authenticated tunnels may dial"
                );
            }
        }
    }
    echo.abort();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(
        connection_budget.active(),
        0,
        "differential connections must be cleaned up on shutdown"
    );
    assert_eq!(stats.streams.load(Ordering::Relaxed), 0);
    drop(caddy);
    drop(capture);
    let mut capture_metadata = Value::Null;
    if let Some(tshark) = std::env::var_os("MOON_DIFF_TSHARK") {
        assert!(
            report.join("encrypted-transport.pcap").exists(),
            "--tshark requires --tcpdump"
        );
        let output = Command::new(tshark)
            .args(["-r"])
            .arg(report.join("encrypted-transport.pcap"))
            .args(["-T", "fields", "-e", "frame.number"])
            .output()
            .unwrap();
        assert!(output.status.success(), "optional tshark failed");
        capture_metadata = json!({"encrypted_packet_count":String::from_utf8_lossy(&output.stdout).lines().count(),"tls_keys_recorded":false,"application_decryption":false});
    }
    for record in records.iter().filter(|r| r["case"] == "normal") {
        assert_eq!(
            record["status"], 200,
            "both ordinary website stacks must actually serve content"
        );
        assert_ne!(record["outcome"], "timeout");
    }
    // Replace ephemeral ports and private paths in the persisted configuration
    // identity; never serialize the TLS private key or authentication proofs.
    let public_config = json!({"reference":"Caddy v2.10.2","handler":"reverse_proxy","origin":"shared loopback fixture","protocols":["h1","h2","h3"],"certificate":"same ephemeral chain/key as Moon","admin":false,"public_ca_requests":false,"moon_flow_profile":{"h2_stream_window":TransportProfile::from_config(&f.config).unwrap().stream_window(),"h2_connection_window":TransportProfile::from_config(&f.config).unwrap().connection_window(),"h3_stream_window":TransportProfile::from_config(&f.config).unwrap().h3_stream_window(),"h3_connection_window":TransportProfile::from_config(&f.config).unwrap().h3_connection_window()}});
    let invalid=records.iter().filter(|r|r["observation_valid"]==false).map(|r|json!({"server":r["server"],"protocol":r["protocol"],"case":r["case"],"outcome":r["outcome"]})).collect::<Vec<_>>();
    let result = json!({"schema":1,"success":invalid.is_empty(),"invalid_observations":invalid,"observation_count":records.len(),"executed_test":"independent_reference_matrix","configuration_identity_sha256":hash(&serde_json::to_vec(&public_config).unwrap()),"configuration":public_config,"environment":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"network":"loopback","repetitions":3,"protocol":"mona","protocol_profile":"Rupin","moon_version":env!("CARGO_PKG_VERSION"),"test_executable_sha256":hash(&std::fs::read(std::env::current_exe().unwrap()).unwrap()),"header_order":"H1/H3 preserve wire order; H2 application headers use decoded HeaderMap iteration; raw HPACK frame observations are separate","alt_svc_validation":"raw H1/H2/H3 announcements checked against actual bound UDP ports before normalization","normalizations":["Date marked dynamic","Alt-Svc bound port marked; ma preserved","reserved H3 GREASE id/value marked dynamic"],"rustc":Command::new("rustc").arg("--version").output().ok().map(|v|String::from_utf8_lossy(&v.stdout).trim().to_owned())},"records":records,"capture":capture_metadata,"unmeasured":["ordinary authenticated forward requests beyond CONNECT remain covered by Moon regressions; not yet compared here","HPACK/QPACK dynamic compression traces and extended malformed frame/fuzz corpus beyond deterministic pseudoheader and PING probes","SETTINGS timing and header/body timing distributions across network environments; elapsed times here are descriptive loopback samples","TLS extension and exhaustive cipher preference enumeration; resumption sampled with OpenSSL only where available","H3 slow-reader flow-control update timing and extensive reset storms, half-closed states and graceful GOAWAY ordering","kernel path QUIC loss/delay/NAT rebinding, migration attempts, CID rotation, congestion/pacing/retransmission benchmarks; three bounded post-handshake client UDP perturbations measured here","malformed TLS/QUIC handshake corpus and packet-level CONNECTION_CLOSE comparison"]});
    std::fs::write(
        report.join("observations.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    assert!(invalid.is_empty(), "observation setup failed: {invalid:?}");
}

#[test]
fn response_artifacts_redact_proofs_and_preserve_alt_svc_policy() {
    let value = headers(
        [
            (
                "proxy-authentication-info",
                b"do-not-save-this-proof".as_slice(),
            ),
            ("alt-svc", b"h3=\":8443\"; ma=86400".as_slice()),
        ]
        .into_iter(),
    );
    let text = value.to_string();
    assert!(!text.contains("do-not-save-this-proof"));
    assert!(!text.contains("8443"));
    assert!(text.contains("ma=86400"));
}

#[test]
#[should_panic(expected = "actual bound UDP endpoint")]
fn unreachable_alt_svc_is_rejected_before_normalization() {
    validate_alt_svc(
        [("alt-svc", b"h3=\":8443\"; ma=86400".as_slice())].into_iter(),
        9443,
    );
}
