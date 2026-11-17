//! Wire-level malformed headers: bypass friendly client validation, never authenticate.
use super::*;
use quiche::h3::NameValue;
use std::net::SocketAddr;

type Fields = Vec<(&'static str, &'static str)>;
fn cases() -> Vec<(&'static str, Fields)> {
    let regular = vec![
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "proxy.example.test"),
        (":path", "/"),
    ];
    let mut cases = Vec::new();
    for (name, header) in [
        ("missing_method", ":method"),
        ("missing_scheme", ":scheme"),
        ("missing_authority", ":authority"),
        ("missing_path", ":path"),
    ] {
        cases.push((
            name,
            regular
                .iter()
                .copied()
                .filter(|(n, _)| *n != header)
                .collect(),
        ));
    }
    for (name, header) in [
        ("duplicate_method", ":method"),
        ("duplicate_scheme", ":scheme"),
        ("duplicate_authority", ":authority"),
        ("duplicate_path", ":path"),
    ] {
        let mut fields = regular.clone();
        fields.push(*regular.iter().find(|(n, _)| *n == header).unwrap());
        cases.push((name, fields));
    }
    let mut fields = regular.clone();
    fields.insert(0, ("x-fixture", "ordinary"));
    cases.push(("pseudoheader_after_regular", fields));
    let mut fields = regular.clone();
    fields.push((":unknown", "invalid"));
    cases.push(("unknown_pseudoheader", fields));
    let mut fields = regular.clone();
    fields.push(("connection", "keep-alive"));
    cases.push(("prohibited_connection_header", fields));
    let mut fields = regular.clone();
    fields.push(("host", "other.example.test"));
    cases.push(("raw_conflicting_host_authority", fields));
    cases.push((
        "connect_with_scheme_and_path",
        vec![
            (":method", "CONNECT"),
            (":scheme", "https"),
            (":authority", "example.org:443"),
            (":path", "/"),
        ],
    ));
    for (name, field, invalid) in [
        ("invalid_method_token", ":method", "BAD METHOD"),
        ("non_origin_request_target", ":path", "relative-target"),
        (
            "authority_userinfo",
            ":authority",
            "user@proxy.example.test",
        ),
    ] {
        let mut fields = regular.clone();
        fields
            .iter_mut()
            .find(|(name, _)| *name == field)
            .unwrap()
            .1 = invalid;
        cases.push((name, fields));
    }
    let mut fields = regular.clone();
    fields.extend([
        ("host", "proxy.example.test"),
        ("host", "proxy.example.test"),
    ]);
    cases.push(("duplicate_host_header", fields));
    let mut fields = regular;
    fields.push(("proxy-connection", "keep-alive"));
    cases.push(("prohibited_proxy_connection_header", fields));
    cases
}

// HPACK literal-without-indexing and literal, non-Huffman strings. This small
// independent encoder deliberately preserves invalid pseudoheader order/duplicates.
pub(super) fn hpack(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, value) in fields {
        assert!(name.len() < 127 && value.len() < 127);
        bytes.extend([0, name.len() as u8]);
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(value.len() as u8);
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes
}
pub(super) fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < (1 << 24));
    let mut bytes = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    bytes.extend([kind, flags]);
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
async fn h2_probe(address: SocketAddr, ca: &Path, fields: &[(&str, &str)]) -> Value {
    let mut io = tls_stream(address, ca, b"\x02h2").await;
    let mut request = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    request.extend(frame(4, 0, 0, &[]));
    request.extend(frame(1, 5, 1, &hpack(fields)));
    if io.write_all(&request).await.is_err() {
        return json!({"outcome":"io_error_before_probe"});
    }
    let deadline = tokio::time::Instant::now() + Duration::from_millis(600);
    let mut frames = Vec::new();
    let mut outcome = "observation_bound";
    let mut reuse_sent = false;
    let mut reuse_response_headers = false;
    for _ in 0..32 {
        let mut header = [0; 9];
        match tokio::time::timeout_at(deadline, io.read_exact(&mut header)).await {
            Err(_) => {
                outcome = "observation_timeout";
                break;
            }
            Ok(Err(error)) => {
                outcome = if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    "eof"
                } else {
                    "io_error"
                };
                break;
            }
            Ok(Ok(_)) => {}
        }
        let length =
            ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
        if length > 65536 {
            outcome = "frame_exceeds_observation_bound";
            break;
        }
        let mut payload = vec![0; length];
        if !matches!(
            tokio::time::timeout_at(deadline, io.read_exact(&mut payload)).await,
            Ok(Ok(_))
        ) {
            outcome = "incomplete_frame";
            break;
        }
        let kind = header[3];
        let stream = u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff;
        let mut value = json!({"type":kind,"flags":header[4],"stream":stream,"length":length,"payload_sha256":hash(&payload)});
        if kind == 3 && length == 4 {
            value["error_code"] = json!(u32::from_be_bytes(payload[..4].try_into().unwrap()));
        }
        if kind == 7 && length >= 8 {
            value["last_stream"] =
                json!(u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff);
            value["error_code"] = json!(u32::from_be_bytes(payload[4..8].try_into().unwrap()));
        }
        if kind == 4 && header[4] & 1 == 0 {
            value["settings"] = json!(
                payload
                    .as_chunks::<6>()
                    .0
                    .iter()
                    .map(|v| (
                        u16::from_be_bytes(v[..2].try_into().unwrap()),
                        u32::from_be_bytes(v[2..].try_into().unwrap()),
                    ))
                    .collect::<Vec<_>>()
            );
            if io.write_all(&frame(4, 1, 0, &[])).await.is_err() {
                outcome = "ack_io_error";
                break;
            }
        }
        frames.push(value);
        if kind == 7 {
            outcome = "goaway";
            break;
        }
        if stream == 1 && matches!(kind, 1 | 3) && !reuse_sent {
            let ordinary = hpack(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "proxy.example.test"),
                (":path", "/"),
            ]);
            reuse_sent = io.write_all(&frame(1, 5, 3, &ordinary)).await.is_ok();
        }
        if stream == 3 && kind == 1 {
            reuse_response_headers = true;
        }
        if stream == 3 && (kind == 3 || matches!(kind, 0 | 1) && header[4] & 1 != 0) {
            outcome = "reuse_response_complete";
            break;
        }
    }
    json!({"outcome":outcome,"frames":frames,"reuse_probe_sent":reuse_sent,"reuse_response_headers":reuse_response_headers,"request_hpack":"literal_without_indexing_no_huffman","raw_header_hashes_include_dynamic_fields":true})
}

async fn h3_pump(
    client: &mut QClient,
    events: &mut Vec<Value>,
    bodies: &mut Vec<u8>,
    until: tokio::time::Instant,
    target: u64,
) -> bool {
    let mut terminal = false;
    while tokio::time::Instant::now() < until && events.len() < 128 {
        let mut packet = [0; 1350];
        for _ in 0..64 {
            match client.conn.send(&mut packet) {
                Ok((length, info)) => {
                    if client
                        .socket
                        .send_to(&packet[..length], info.to)
                        .await
                        .is_err()
                    {
                        events.push(json!({"event":"udp_send_error"}));
                        return true;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(error) => {
                    events.push(json!({"event":"quic_send_error","error":format!("{error:?}")}));
                    return true;
                }
            }
        }
        let mut packet = [0; 65535];
        if let Ok(Ok((length, from))) = tokio::time::timeout(
            Duration::from_millis(2),
            client.socket.recv_from(&mut packet),
        )
        .await
        {
            let to = client.socket.local_addr().unwrap();
            if let Err(error) = client
                .conn
                .recv(&mut packet[..length], quiche::RecvInfo { from, to })
            {
                events.push(json!({"event":"quic_receive_error","error":format!("{error:?}")}));
            }
        }
        if client
            .conn
            .timeout_instant()
            .is_some_and(|at| at <= std::time::Instant::now())
        {
            client.conn.on_timeout();
        }
        for _ in 0..64 {
            let Some(h3) = client.h3.as_mut() else {
                return true;
            };
            match h3.poll(&mut client.conn) {
                Ok((stream, quiche::h3::Event::Headers { list, .. })) => {
                    let status = list
                        .iter()
                        .find(|v| v.name() == b":status")
                        .and_then(|v| std::str::from_utf8(v.value()).ok())
                        .and_then(|v| v.parse::<u16>().ok());
                    events.push(json!({"event":"headers","stream":stream,"status":status,"fields":headers(list.iter().map(|v|(std::str::from_utf8(v.name()).unwrap_or("invalid"),v.value())))}));
                }
                Ok((stream, quiche::h3::Event::Data)) => {
                    let mut body = [0; 4096];
                    while let Ok(length) = h3.recv_body(&mut client.conn, stream, &mut body) {
                        if length == 0 {
                            break;
                        }
                        if bodies.len() + length > 65536 {
                            events.push(json!({"event":"body_observation_bound"}));
                            return true;
                        }
                        bodies.extend_from_slice(&body[..length]);
                    }
                }
                Ok((stream, quiche::h3::Event::Finished)) => {
                    events.push(json!({"event":"finished","stream":stream}));
                    terminal |= stream == target;
                }
                Ok((stream, quiche::h3::Event::Reset(code))) => {
                    events.push(json!({"event":"reset","stream":stream,"error_code":code}));
                    terminal |= stream == target;
                }
                Ok((id, quiche::h3::Event::GoAway)) => {
                    events.push(json!({"event":"goaway","id":id}));
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(error) => {
                    events.push(json!({"event":"h3_error","error":format!("{error:?}")}));
                    terminal = true;
                    break;
                }
            }
        }
        if terminal
            || client.conn.is_closed()
            || client.conn.is_draining()
            || client.conn.peer_error().is_some()
        {
            break;
        }
    }
    terminal
}
async fn h3_probe(address: SocketAddr, ca: &Path, fields: &[(&str, &str)]) -> Value {
    // Only the initial well-formed handshake uses QClient::step. Once malformed
    // headers are sent, errors are observations, never panic conditions.
    let mut client = QClient::new(address, ca).await;
    let fields = fields
        .iter()
        .map(|(name, value)| quiche::h3::Header::new(name.as_bytes(), value.as_bytes()))
        .collect::<Vec<_>>();
    let stream = match client
        .h3
        .as_mut()
        .unwrap()
        .send_request(&mut client.conn, &fields, true)
    {
        Ok(stream) => stream,
        Err(error) => {
            let result = json!({"outcome":"local_client_rejection","error":format!("{error:?}"),"wire_sent":false,"coverage":"client_rejected_before_wire;server_behavior_unmeasured"});
            close_quic(&mut client).await;
            return result;
        }
    };
    let mut events = Vec::new();
    let mut body = Vec::new();
    let terminal = h3_pump(
        &mut client,
        &mut events,
        &mut body,
        tokio::time::Instant::now() + Duration::from_millis(400),
        stream,
    )
    .await;
    let fields = [
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "proxy.example.test"),
        (":path", "/"),
    ]
    .iter()
    .map(|(name, value)| quiche::h3::Header::new(name.as_bytes(), value.as_bytes()))
    .collect::<Vec<_>>();
    let reuse = if !client.conn.is_closed() && !client.conn.is_draining() {
        client
            .h3
            .as_mut()
            .unwrap()
            .send_request(&mut client.conn, &fields, true)
            .ok()
    } else {
        None
    };
    if let Some(stream) = reuse {
        h3_pump(
            &mut client,
            &mut events,
            &mut body,
            tokio::time::Instant::now() + Duration::from_millis(200),
            stream,
        )
        .await;
    }
    let peer_error = client.conn.peer_error().map(|e|json!({"application":e.is_app,"error_code":e.error_code,"reason_length":e.reason.len()}));
    let local_error = client.conn.local_error().map(|e|json!({"application":e.is_app,"error_code":e.error_code,"reason_length":e.reason.len()}));
    let result = json!({"outcome":if terminal {"terminal_event"} else {"bounded_observation"},"events":events,"body":body_shape(&body),"closed":client.conn.is_closed(),"draining":client.conn.is_draining(),"peer_error":peer_error,"local_error":local_error,"reuse_probe_sent":reuse.is_some(),"reuse_response_headers":reuse.is_some_and(|id|events.iter().any(|e|e["event"]=="headers"&&e["stream"]==id)),"request_encoding":"quiche_qpack_preserving_field_order","wire_sent":true});
    close_quic(&mut client).await;
    result
}

pub(super) async fn observe(
    tcp: SocketAddr,
    udp: SocketAddr,
    ca: &Path,
) -> Vec<(&'static str, &'static str, Value)> {
    let mut result = Vec::new();
    for (name, fields) in cases() {
        for protocol in ["h2", "h3"] {
            let ca = ca.to_path_buf();
            let fields = fields.clone();
            let mut task = tokio::spawn(async move {
                if protocol == "h2" {
                    h2_probe(tcp, &ca, &fields).await
                } else {
                    h3_probe(udp, &ca, &fields).await
                }
            });
            let value = match tokio::time::timeout(Duration::from_secs(7), &mut task).await {
                Ok(Ok(value)) => value,
                Ok(Err(_)) => json!({"outcome":"observer_setup_failure","observation_valid":false}),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    json!({"outcome":"probe_deadline_exceeded","observation_valid":false})
                }
            };
            result.push((protocol, name, value));
        }
    }
    result
}

#[test]
fn literal_hpack_retains_invalid_duplicates_and_order() {
    let cases = cases();
    assert_eq!(cases.len(), 18);
    let (_, fields) = cases
        .iter()
        .find(|(name, _)| *name == "duplicate_method")
        .unwrap();
    let encoded = hpack(fields);
    assert_eq!(encoded.windows(7).filter(|v| *v == b":method").count(), 2);
    assert_eq!(frame(1, 5, 1, &encoded)[3..9], [1, 5, 0, 0, 0, 1]);
    let (_, fields) = cases
        .iter()
        .find(|(name, _)| *name == "pseudoheader_after_regular")
        .unwrap();
    assert_eq!(fields[0].0, "x-fixture");
    let (_, fields) = cases
        .iter()
        .find(|(name, _)| *name == "invalid_method_token")
        .unwrap();
    assert!(hpack(fields).windows(10).any(|v| v == b"BAD METHOD"));
    let (_, fields) = cases
        .iter()
        .find(|(name, _)| *name == "duplicate_host_header")
        .unwrap();
    assert_eq!(fields.iter().filter(|(name, _)| *name == "host").count(), 2);
}
