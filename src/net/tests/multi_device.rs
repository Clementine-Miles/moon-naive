//! Real loopback next-hop tests: policy still checks the public destination;
//! multiple devices intentionally share one username and one source address.
use super::*;
use std::net::SocketAddr;

struct NextHop {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for NextHop {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn echo_next_hop() -> NextHop {
    // Administrative next hops can be private; their final CONNECT target must
    // remain an allowed concrete public IP. This address differs from frontend.
    let listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = children.join_next(), if !children.is_empty() => {},
                accepted = listener.accept() => {
                    let (mut socket, _) = accepted.unwrap();
                    children.spawn(async move {
                        let mut head = Vec::new();
                        while !head.ends_with(b"\r\n\r\n") {
                            assert!(head.len() < 32768);
                            head.push(socket.read_u8().await.unwrap());
                        }
                        assert!(head.starts_with(b"CONNECT 1.1.1.1:443 HTTP/1.1\r\n"));
                        socket.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.unwrap();
                        let mut payload = Vec::new();
                        if socket.read_to_end(&mut payload).await.is_ok() {
                            let _ = socket.write_all(&payload).await;
                            let _ = socket.shutdown().await;
                        }
                    });
                }
            }
        }
    });
    NextHop { address, task }
}

fn endpoint_pair(config: &mut Config, first_streams: usize, second_streams: usize) {
    // Reserve all four endpoints together so neither test endpoint can receive
    // another endpoint's allocated port; production validation rejects port 0.
    let tcp_a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let udp_a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let tcp_b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let udp_b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    config.listeners = [
        ("device-a", tcp_a.local_addr().unwrap(), udp_a.local_addr().unwrap(), first_streams),
        ("device-b", tcp_b.local_addr().unwrap(), udp_b.local_addr().unwrap(), second_streams),
    ].into_iter().map(|(name,tcp,udp,streams)| {
        toml::from_str(&format!(
            "name='{name}'\ntcp='{tcp}'\nudp='{udp}'\nh1=false\n[limits]\nmax_streams={streams}\nmax_connections=4\nmax_pending_requests=8\nmax_tunnels_per_user=8\nidle_timeout_secs=30\ngraceful_timeout_secs=1\n"
        )).unwrap()
    }).collect();
    config.limits.max_connections = 8;
    config.limits.max_streams = 8;
    config.limits.max_tunnels_per_user = 8;
    config.limits.idle_timeout_secs = 30;
    config.limits.graceful_timeout_secs = 1;
}
fn tunnel_request() -> http::Request<()> {
    http::Request::builder()
        .method("CONNECT")
        .uri("1.1.1.1:443")
        .header("proxy-authorization", auth())
        .body(())
        .unwrap()
}
async fn h2_site(client: &mut H2Client) {
    let (response, _) = client
        .send_request(
            http::Request::builder()
                .uri("https://proxy.example.test/")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    assert!(
        body(response.into_body())
            .await
            .starts_with(b"<!doctype html>")
    );
}

#[tokio::test]
async fn same_user_devices_isolate_ports_and_preserve_half_close() {
    let next_hop = echo_next_hop().await;
    let mut fixture = fixture();
    let config = Arc::get_mut(&mut fixture.config).unwrap();
    endpoint_pair(config, 1, 2);
    config.proxy.upstream =
        Some(toml::from_str(&format!("kind='http'\naddress='{}'", next_hop.address)).unwrap());
    let server = Prepared::load(fixture.config.clone())
        .await
        .unwrap()
        .bind()
        .await
        .unwrap();
    let endpoints = server.listener_addrs().unwrap();
    assert_eq!(endpoints.len(), 2);
    let a = endpoints[0].1.unwrap();
    let b = endpoints[1].1.unwrap();
    let b_udp = endpoints[1].2.unwrap();
    let budget = server.connections.clone();
    let stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let server_task = tokio::spawn(server.run(rx));

    let (mut device_a, driver_a) = h2_client(a, &fixture.ca).await;
    let (response_a, mut upload_a) = device_a.send_request(tunnel_request(), false).unwrap();
    let response_a = response_a.await.unwrap();
    assert_eq!(response_a.status(), 200);

    // Same user/source IP, separate device/connection. The local port ceiling
    // rejects the new tunnel while preserving ordinary website requests.
    let (mut crowded_device, crowded_driver) = h2_client(a, &fixture.ca).await;
    let (rejected, _) = crowded_device.send_request(tunnel_request(), true).unwrap();
    assert_eq!(rejected.await.unwrap().status(), 503);
    h2_site(&mut crowded_device).await;

    let mut device_b_quic = QClient::new(b_udp, &fixture.ca).await;
    let quic_id =
        device_b_quic.request("CONNECT", "1.1.1.1:443", None, Some(&auth()), false, false);
    tokio::time::timeout(Duration::from_secs(3), async {
        while device_b_quic
            .responses
            .get(&quic_id)
            .is_none_or(|r| r.status == 0)
        {
            device_b_quic.step().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        device_b_quic.responses[&quic_id].status, 200,
        "unexpected H3 admission status"
    );
    let (mut device_b_tcp, driver_b) = h2_client(b, &fixture.ca).await;
    let (response_b, mut upload_b) = device_b_tcp.send_request(tunnel_request(), false).unwrap();
    let response_b = response_b.await.unwrap();
    assert_eq!(response_b.status(), 200);

    // Application frames and FIN remain correct across concurrent transports.
    v2_send(&mut upload_a, frame(b"port-a device"), true).await;
    v2_send(&mut upload_b, frame(b"port-b device"), true).await;
    device_b_quic
        .send(quic_id, &frame(b"port-b quic device"))
        .await;
    assert_eq!(
        unframe(&body(response_a.into_body()).await),
        b"port-a device"
    );
    assert_eq!(
        unframe(&body(response_b.into_body()).await),
        b"port-b device"
    );
    let quic_response = device_b_quic.response(quic_id).await;
    assert_eq!(quic_response.status, 200);
    assert!(!quic_response.reset);
    assert_eq!(unframe(&quic_response.body), b"port-b quic device");

    // Reconnect after the crowded listener's permit was released.
    let (response, mut upload) = crowded_device
        .send_request(tunnel_request(), false)
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    v2_send(&mut upload, frame(b"reconnected"), true).await;
    assert_eq!(unframe(&body(response.into_body()).await), b"reconnected");
    driver_a.abort();
    driver_b.abort();
    crowded_driver.abort();
    let _ = device_b_quic.conn.close(true, 0x100, b"");
    device_b_quic.step().await;
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(4), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(budget.active(), 0);
    assert_eq!(stats.streams.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn certificate_rotation_is_atomic_across_ports_and_old_devices_survive() {
    let mut fixture = fixture();
    endpoint_pair(Arc::get_mut(&mut fixture.config).unwrap(), 4, 4);
    let server = Prepared::load(fixture.config.clone())
        .await
        .unwrap()
        .bind()
        .await
        .unwrap();
    let endpoints = server.listener_addrs().unwrap();
    let slot = server.tls.clone();
    let old = slot.current().unwrap().id.clone();
    let budget = server.connections.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let mut h2_devices = Vec::new();
    let mut h3_devices = Vec::new();
    for (_, tcp, udp) in &endpoints {
        assert_eq!(peer_serial(tcp.unwrap(), &fixture.ca).await, vec![2]);
        h2_devices.push(h2_client(tcp.unwrap(), &fixture.ca).await);
        let quic = QClient::new(udp.unwrap(), &fixture.ca).await;
        assert_eq!(
            serial(&X509::from_der(quic.conn.peer_cert().unwrap()).unwrap()),
            vec![2]
        );
        h3_devices.push(quic);
    }
    rotate(&fixture);
    assert!(slot.refresh(&fixture.config).unwrap());
    assert_ne!(slot.current().unwrap().id, old);
    for ((_, tcp, udp), ((h2, _), h3)) in endpoints
        .iter()
        .zip(h2_devices.iter_mut().zip(h3_devices.iter_mut()))
    {
        assert_eq!(peer_serial(tcp.unwrap(), &fixture.ca).await, vec![3]);
        let mut fresh = QClient::new(udp.unwrap(), &fixture.ca).await;
        assert_eq!(
            serial(&X509::from_der(fresh.conn.peer_cert().unwrap()).unwrap()),
            vec![3]
        );
        h2_site(h2).await;
        let id = h3.request("GET", "proxy.example.test", Some("/"), None, false, true);
        assert_eq!(h3.response(id).await.status, 200);
        let _ = fresh.conn.close(true, 0x100, b"");
        fresh.step().await;
    }
    for (_, driver) in h2_devices {
        driver.abort();
    }
    for mut client in h3_devices {
        let _ = client.conn.close(true, 0x100, b"");
        client.step().await;
    }
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(4), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(budget.active(), 0);
}

#[tokio::test]
async fn global_stream_ceiling_spans_ports_and_reset_returns_credit() {
    let next_hop = echo_next_hop().await;
    let mut fixture = fixture();
    let config = Arc::get_mut(&mut fixture.config).unwrap();
    endpoint_pair(config, 2, 2);
    // Each endpoint can admit two, but the process may admit only three.
    config.limits.max_streams = 3;
    config.proxy.upstream =
        Some(toml::from_str(&format!("kind='http'\naddress='{}'", next_hop.address)).unwrap());
    let server = Prepared::load(fixture.config.clone())
        .await
        .unwrap()
        .bind()
        .await
        .unwrap();
    let endpoints = server.listener_addrs().unwrap();
    let stats = server.stats.clone();
    let connections = server.connections.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut a, driver_a) = h2_client(endpoints[0].1.unwrap(), &fixture.ca).await;
    let (first, mut first_upload) = a.send_request(tunnel_request(), false).unwrap();
    let first = first.await.unwrap();
    assert_eq!(first.status(), 200);
    let (second, mut cancelled_upload) = a.send_request(tunnel_request(), false).unwrap();
    let second = second.await.unwrap();
    assert_eq!(second.status(), 200);
    let (mut b, driver_b) = h2_client(endpoints[1].1.unwrap(), &fixture.ca).await;
    let (third, mut third_upload) = b.send_request(tunnel_request(), false).unwrap();
    let third = third.await.unwrap();
    assert_eq!(third.status(), 200);
    let (denied, _) = b.send_request(tunnel_request(), true).unwrap();
    assert_eq!(denied.await.unwrap().status(), 503);
    tokio::time::timeout(Duration::from_secs(3), async {
        while stats.streams.load(Ordering::Relaxed) != 3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();

    // Cancel one half-open tunnel while another connection remains multiplexed.
    // The second endpoint must acquire the returned global credit.
    cancelled_upload.send_reset(::h2::Reason::CANCEL);
    drop(second);
    tokio::time::timeout(Duration::from_secs(3), async {
        while stats.streams.load(Ordering::Relaxed) != 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let (replacement, mut replacement_upload) = b.send_request(tunnel_request(), false).unwrap();
    let replacement = replacement.await.unwrap();
    assert_eq!(replacement.status(), 200);
    v2_send(&mut first_upload, frame(b"first"), true).await;
    v2_send(&mut third_upload, frame(b"third"), true).await;
    v2_send(&mut replacement_upload, frame(b"replacement"), true).await;
    assert_eq!(unframe(&body(first.into_body()).await), b"first");
    assert_eq!(unframe(&body(third.into_body()).await), b"third");
    assert_eq!(
        unframe(&body(replacement.into_body()).await),
        b"replacement"
    );
    driver_a.abort();
    driver_b.abort();
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(4), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(stats.streams.load(Ordering::Relaxed), 0);
    assert_eq!(connections.active(), 0);
}

#[tokio::test]
async fn aggregate_receive_credit_is_bounded_across_ports_and_reusable_after_disconnect() {
    let mut fixture = fixture();
    let config = Arc::get_mut(&mut fixture.config).unwrap();
    endpoint_pair(config, 2, 2);
    const CREDIT: usize = 128 * 1024;
    config.limits.max_total_receive_bytes = 2 * CREDIT;
    for endpoint in &mut config.listeners {
        endpoint.limits.as_mut().unwrap().max_total_receive_bytes = 2 * CREDIT;
        endpoint.flow.h2_stream_window = Some(64 * 1024);
        endpoint.flow.h2_connection_window = Some(CREDIT as u32);
        endpoint.flow.h3_stream_window = Some(32 * 1024);
        endpoint.flow.h3_connection_window = Some(CREDIT as u32);
    }
    let server = Prepared::load(fixture.config.clone())
        .await
        .unwrap()
        .bind()
        .await
        .unwrap();
    let endpoints = server.listener_addrs().unwrap();
    let receive = server.app.resources.receive.clone();
    let connections = server.connections.clone();
    let stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut a, driver_a) = h2_client(endpoints[0].1.unwrap(), &fixture.ca).await;
    h2_site(&mut a).await;
    let (mut b, driver_b) = h2_client(endpoints[1].1.unwrap(), &fixture.ca).await;
    h2_site(&mut b).await;
    assert_eq!(receive.available_permits(), 0);
    assert_eq!(stats.h2_connections.load(Ordering::Relaxed), 2);

    // TCP/TLS alone does not reserve receive credit. The third HTTP/2
    // connection is rejected before it can receive its advertised window.
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(&fixture.ca).unwrap();
    connector.set_alpn_protos(b"\x02h2").unwrap();
    let tls = tokio_boring::connect(
        connector.build().configure().unwrap(),
        "proxy.example.test",
        TcpStream::connect(endpoints[1].1.unwrap()).await.unwrap(),
    )
    .await
    .unwrap();
    if let Ok((mut sender, connection)) = ::h2::client::handshake(tls).await {
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        if let Ok((response, _)) = sender.send_request(
            http::Request::builder()
                .uri("https://proxy.example.test/")
                .body(())
                .unwrap(),
            true,
        ) {
            assert!(
                tokio::time::timeout(Duration::from_secs(3), response)
                    .await
                    .unwrap()
                    .is_err()
            );
        }
        driver.abort();
    }
    assert_eq!(receive.available_permits(), 0);
    assert_eq!(stats.h2_connections.load(Ordering::Relaxed), 2);
    drop(a);
    driver_a.abort();
    tokio::time::timeout(Duration::from_secs(3), async {
        while receive.available_permits() != CREDIT {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let (mut reconnected, replacement_driver) =
        h2_client(endpoints[1].1.unwrap(), &fixture.ca).await;
    h2_site(&mut reconnected).await;
    assert_eq!(receive.available_permits(), 0);
    drop((b, reconnected));
    driver_b.abort();
    replacement_driver.abort();
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(4), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(receive.available_permits(), 2 * CREDIT);
    assert_eq!(connections.active(), 0);
}

#[tokio::test]
async fn client_marker_cannot_select_another_ports_alt_svc_or_reach_origin() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        for _ in 0..6 {
            let (mut socket, _) = origin.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                assert!(head.len() < 32768);
                head.push(socket.read_u8().await.unwrap());
            }
            let text = String::from_utf8(head).unwrap().to_ascii_lowercase();
            assert!(
                !text.contains("x-moon-internal-listener"),
                "internal marker leaked to origin"
            );
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        }
    });
    let mut fixture = fixture();
    let config = Arc::get_mut(&mut fixture.config).unwrap();
    endpoint_pair(config, 4, 4);
    for endpoint in &mut config.listeners {
        endpoint.listener.h1 = true;
    }
    config.website.upstreams[0].origins = vec![format!("http://{address}")];
    let server = Prepared::load(fixture.config.clone())
        .await
        .unwrap()
        .bind()
        .await
        .unwrap();
    let endpoints = server.listener_addrs().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    for (index, (_, tcp, udp)) in endpoints.iter().enumerate() {
        let other = &endpoints[1 - index].0;
        let expected = format!("h3=\":{}\"; ma=86400", udp.unwrap().port());
        let (mut h2, driver) = h2_client(tcp.unwrap(), &fixture.ca).await;
        let (response, _) = h2
            .send_request(
                http::Request::builder()
                    .uri("https://proxy.example.test/")
                    .header("x-moon-internal-listener", other)
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["alt-svc"], expected);
        assert!(!response.headers().contains_key("x-moon-internal-listener"));
        assert_eq!(body(response.into_body()).await, b"ok");
        driver.abort();

        let mut h3 = QClient::new(udp.unwrap(), &fixture.ca).await;
        let id = h3
            .send_headers(
                &[
                    quiche::h3::Header::new(b":method", b"GET"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", b"proxy.example.test"),
                    quiche::h3::Header::new(b":path", b"/"),
                    quiche::h3::Header::new(b"x-moon-internal-listener", other.as_bytes()),
                ],
                true,
            )
            .unwrap();
        let response = h3.response(id).await;
        assert_eq!(response.status, 200);
        assert_eq!(response.headers["alt-svc"], expected);
        assert!(!response.headers.contains_key("x-moon-internal-listener"));
        assert_eq!(response.body, b"ok");
        let _ = h3.conn.close(true, 0x100, b"");
        h3.step().await;

        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_ca_file(&fixture.ca).unwrap();
        connector.set_alpn_protos(b"\x08http/1.1").unwrap();
        let mut h1 = tokio_boring::connect(
            connector.build().configure().unwrap(),
            "proxy.example.test",
            TcpStream::connect(tcp.unwrap()).await.unwrap(),
        )
        .await
        .unwrap();
        h1.write_all(format!("GET / HTTP/1.1\r\nHost: proxy.example.test\r\nConnection: close\r\nx-moon-internal-listener: {other}\r\n\r\n").as_bytes()).await.unwrap();
        let mut wire = Vec::new();
        tokio::time::timeout(Duration::from_secs(4), h1.read_to_end(&mut wire))
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8(wire).unwrap().to_ascii_lowercase();
        assert!(text.starts_with("http/1.1 200"));
        assert!(text.contains(&format!("\r\nalt-svc: {expected}\r\n")));
        assert!(!text.contains("x-moon-internal-listener"));
    }
    tokio::time::timeout(Duration::from_secs(3), origin_task)
        .await
        .unwrap()
        .unwrap();
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(4), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn bind_conflict_rolls_back_every_previously_bound_endpoint() {
    let mut fixture = fixture();
    endpoint_pair(Arc::get_mut(&mut fixture.config).unwrap(), 2, 2);
    let a = &fixture.config.listeners[0].listener;
    let b = &fixture.config.listeners[1].listener;
    let (a_tcp, a_udp, b_tcp, b_udp) = (a.tcp, a.udp, b.tcp, b.udp);
    // Fail the final UDP bind after the preceding endpoint sockets were bound.
    let conflict = UdpSocket::bind(b_udp).await.unwrap();
    let prepared = Prepared::load(fixture.config.clone()).await.unwrap();
    let connections = prepared.app.resources.connections.clone();
    let receive = prepared.app.resources.receive.clone();
    assert!(prepared.bind().await.is_err());
    assert_eq!(connections.active(), 0);
    assert_eq!(
        receive.available_permits(),
        fixture.config.limits.max_total_receive_bytes
    );
    let restored_a_tcp = TcpListener::bind(a_tcp).await.unwrap();
    let restored_a_udp = UdpSocket::bind(a_udp).await.unwrap();
    let restored_b_tcp = TcpListener::bind(b_tcp).await.unwrap();
    drop(conflict);
    let restored_b_udp = UdpSocket::bind(b_udp).await.unwrap();
    drop((
        restored_a_tcp,
        restored_a_udp,
        restored_b_tcp,
        restored_b_udp,
    ));
}
