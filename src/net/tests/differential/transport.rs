//! Small bounded H2 backpressure/cancellation experiment, separate from benchmarks.
use super::malformed::{frame, hpack};
use super::*;
use std::{collections::BTreeMap, net::SocketAddr};

async fn experiment(address: SocketAddr, ca: &Path) -> Value {
    let mut io = tls_stream(address, ca, b"\x02h2").await;
    let fields = hpack(&[
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "proxy.example.test"),
        (":path", "/"),
    ]);
    io.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    // Eight bytes of response DATA credit exposes a real per-stream flow stop,
    // independently of request admission or any bandwidth policy.
    io.write_all(&frame(4, 0, 0, &[0, 4, 0, 0, 0, 8]))
        .await
        .unwrap();
    let fragmented = frame(1, 5, 1, &fields);
    for part in fragmented.chunks(3) {
        io.write_all(part).await.unwrap();
        tokio::task::yield_now().await;
    }
    io.write_all(&frame(1, 5, 3, &fields)).await.unwrap();
    io.write_all(&frame(1, 5, 5, &fields)).await.unwrap();
    io.write_all(&frame(3, 0, 1, &8u32.to_be_bytes()))
        .await
        .unwrap();
    // Bounded cancellation burst followed by a fresh request on the connection.
    for stream in [7, 9, 11, 13] {
        io.write_all(&frame(1, 5, stream, &fields)).await.unwrap();
        io.write_all(&frame(3, 0, stream, &8u32.to_be_bytes()))
            .await
            .unwrap();
    }
    io.write_all(&frame(1, 5, 15, &fields)).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut frames = Vec::new();
    let mut bodies: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut complete = std::collections::BTreeSet::new();
    let mut update_sent = false;
    let mut outcome = "observation_bound";
    for _ in 0..128 {
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
        let mut record = json!({"type":kind,"flags":header[4],"stream":stream,"length":length,"payload_sha256":hash(&payload)});
        if kind == 4 && header[4] & 1 == 0 {
            record["settings"] = json!(
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
            io.write_all(&frame(4, 1, 0, &[])).await.unwrap();
        }
        if kind == 8 && length == 4 {
            record["increment"] =
                json!(u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff);
        }
        if kind == 3 && length == 4 {
            record["error_code"] = json!(u32::from_be_bytes(payload[..4].try_into().unwrap()));
        }
        if kind == 7 && length >= 8 {
            record["last_stream"] =
                json!(u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff);
            record["error_code"] = json!(u32::from_be_bytes(payload[4..8].try_into().unwrap()));
        }
        if kind == 0 {
            let body = bodies.entry(stream).or_default();
            // DATA padding is transport overhead, not response body bytes.
            let data = if header[4] & 8 != 0 {
                payload
                    .first()
                    .and_then(|padding| {
                        payload.get(1..payload.len().checked_sub(*padding as usize)?)
                    })
                    .unwrap_or_default()
            } else {
                &payload
            };
            if body.len() + data.len() > 65536 {
                outcome = "body_exceeds_observation_bound";
                break;
            }
            body.extend_from_slice(data);
            record["data_bytes"] = json!(data.len());
            if !update_sent && matches!(stream, 3 | 5 | 15) {
                // A deliberately slow reader releases credit after a fixed small
                // delay. Timing samples are descriptive, not a performance claim.
                tokio::time::sleep(Duration::from_millis(20)).await;
                for id in [3, 5, 15] {
                    io.write_all(&frame(8, 0, id, &4096u32.to_be_bytes()))
                        .await
                        .unwrap();
                }
                io.write_all(&frame(8, 0, 0, &4096u32.to_be_bytes()))
                    .await
                    .unwrap();
                update_sent = true;
            }
        }
        frames.push(record);
        if kind == 7 {
            outcome = "goaway";
            break;
        }
        if matches!(kind, 0 | 1) && header[4] & 1 != 0 {
            complete.insert(stream);
        }
        if [3, 5, 15].iter().all(|id| complete.contains(id)) {
            outcome = "multiplex_responses_complete";
            break;
        }
    }
    let body_shapes = bodies
        .into_iter()
        .map(|(id, body)| (id.to_string(), body_shape(&body)))
        .collect::<serde_json::Map<_, _>>();
    json!({"outcome":outcome,"frames":frames,"response_bodies":body_shapes,"completed_streams":complete,"client_stream_window_bytes":8,"client_window_update_increment":4096,"window_updates_sent":update_sent,"cancelled_streams":[1,7,9,11,13],"fragmented_write_bytes":3,"write_fragmentation_is_not_packet_segmentation_guarantee":true,"slow_reader_delay_ms":20,"raw_header_hashes_include_dynamic_fields":true})
}

pub(super) async fn observe(
    tcp: SocketAddr,
    _udp: SocketAddr,
    ca: &Path,
) -> Vec<(&'static str, &'static str, Value)> {
    let ca = ca.to_path_buf();
    let mut task = tokio::spawn(async move { experiment(tcp, &ca).await });
    let value = match tokio::time::timeout(Duration::from_secs(7), &mut task).await {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => json!({"outcome":"observer_setup_failure","observation_valid":false}),
        Err(_) => {
            task.abort();
            let _ = task.await;
            json!({"outcome":"probe_deadline_exceeded","observation_valid":false})
        }
    };
    vec![("h2", "fragmented_multiplex_cancel_and_flow_control", value)]
}
