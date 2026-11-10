use super::*;
use moon_naive_core::config::{ProxyKind, ProxyUpstream};

async fn h1_request(
    f: &Fixture,
    address: std::net::SocketAddr,
    request: &str,
    alpn: bool,
) -> String {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(&f.ca).unwrap();
    if alpn {
        connector.set_alpn_protos(b"\x08http/1.1").unwrap();
    }
    let mut stream = tokio_boring::connect(
        connector.build().configure().unwrap(),
        "proxy.example.test",
        TcpStream::connect(address).await.unwrap(),
    )
    .await
    .unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(response).unwrap()
}
#[tokio::test]
async fn h1_website_alpn_fallback_connect_cover_and_no_proxy_dial() {
    let mut f = fixture();
    Arc::get_mut(&mut f.config).unwrap().listener.h1 = true;
    let server = network(&f, None).await;
    let addr = server.tcp_addr().unwrap();
    let stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    for alpn in [true, false] {
        let response = h1_request(
            &f,
            addr,
            "GET / HTTP/1.1\r\nHost: proxy.example.test\r\nConnection: close\r\n\r\n",
            alpn,
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("moon-naive test site"));
        assert!(response.to_ascii_lowercase().contains("alt-svc: h3="));
        for (target, host) in [
            ("https://proxy.example.test/", "proxy.example.test"),
            ("https://PROXY.EXAMPLE.TEST:443/", "PROXY.EXAMPLE.TEST:443"),
        ] {
            let response = h1_request(
                &f,
                addr,
                &format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
                alpn,
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        }
        for auth in [
            "".to_owned(),
            format!("Proxy-Authorization: {}\r\n", auth()),
        ] {
            let response=h1_request(&f,addr,&format!("CONNECT proxy.example.test:443 HTTP/1.1\r\nHost: proxy.example.test\r\n{auth}Connection: close\r\n\r\n"),alpn).await;
            assert!(!response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(
                response
                    .split("\r\n\r\n")
                    .nth(1)
                    .is_some_and(|s| !s.is_empty())
            );
            assert!(
                !response
                    .to_ascii_lowercase()
                    .contains("proxy-authenticate:")
            );
        }
    }
    assert_eq!(stats.dials.load(Ordering::Relaxed), 0);
    assert_eq!(stats.resolutions.load(Ordering::Relaxed), 0);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}
fn hop(kind: ProxyKind, address: String) -> ProxyUpstream {
    ProxyUpstream {
        kind,
        address,
        username: Some("user".into()),
        password: Some("secret".into()),
        tls_server_name: None,
        ca_file: None,
    }
}
#[tokio::test]
async fn http_upstream_auth_and_coalesced_tunnel_bytes_are_preserved() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(stream.read_u8().await.unwrap());
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("CONNECT 1.1.1.1:443 HTTP/1.1\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpzZWNyZXQ="));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nbanner")
            .await
            .unwrap();
        let mut input = [0; 4];
        stream.read_exact(&mut input).await.unwrap();
        assert_eq!(&input, b"ping");
        stream.shutdown().await.unwrap();
    });
    let upstream = egress::NextHop::new(hop(ProxyKind::Http, addr.to_string())).unwrap();
    let mut stream = upstream
        .handshake(
            TcpStream::connect(addr).await.unwrap(),
            "1.1.1.1:443".parse().unwrap(),
        )
        .await
        .unwrap();
    let mut banner = [0; 6];
    stream.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"banner");
    stream.write_all(b"ping").await.unwrap();
    stream.shutdown().await.unwrap();
    server.await.unwrap();
}
#[tokio::test]
async fn socks5_auth_ipv6_and_reply_boundary() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        s.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 2]);
        s.write_all(&[5, 2]).await.unwrap();
        assert_eq!(s.read_u8().await.unwrap(), 1);
        let n = s.read_u8().await.unwrap();
        let mut user = vec![0; n as usize];
        s.read_exact(&mut user).await.unwrap();
        assert_eq!(&user, b"user");
        let n = s.read_u8().await.unwrap();
        let mut pass = vec![0; n as usize];
        s.read_exact(&mut pass).await.unwrap();
        assert_eq!(&pass, b"secret");
        s.write_all(&[1, 0]).await.unwrap();
        let mut request = [0; 22];
        s.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..4], &[5, 1, 0, 4]);
        assert_eq!(&request[20..], &443u16.to_be_bytes());
        s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1, b'x'])
            .await
            .unwrap();
    });
    let upstream = egress::NextHop::new(hop(ProxyKind::Socks5, addr.to_string())).unwrap();
    let mut stream = upstream
        .handshake(
            TcpStream::connect(addr).await.unwrap(),
            "[2606:4700:4700::1111]:443".parse().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), b'x');
    server.await.unwrap();
}
#[tokio::test]
async fn rejected_websocket_requests_do_not_reveal_tunnel_quota() {
    let mut f = fixture();
    Arc::get_mut(&mut f.config).unwrap().website.routes[0].path_prefix = "/ws".into();
    let server = network(&f, None).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let app = server.app.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut h2, driver) = h2_client(tcp, &f.ca).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while !h2.sender.is_extended_connect_protocol_enabled() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut q = QClient::new(udp, &f.ca).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while !q.h3.as_ref().unwrap().extended_connect_enabled_by_peer() {
            q.step().await;
        }
    })
    .await
    .unwrap();
    let mut baseline = Vec::new();
    for full in [false, true] {
        let mut held = Vec::new();
        if full {
            while let Some(permit) = app.resources.tunnels.acquire() {
                held.push(permit);
            }
            assert!(!held.is_empty());
        }
        let mut observed = Vec::new();
        for (host, path, version, status) in [
            ("unknown.example.test", "/ws", "13", 404),
            ("proxy.example.test", "/missing", "13", 404),
            ("proxy.example.test", "/ws", "12", 400),
        ] {
            for auth in [None, Some("Basic invalid")] {
                let mut request = http::Request::builder()
                    .method("CONNECT")
                    .uri(format!("https://{host}{path}"))
                    .header("sec-websocket-version", version);
                if let Some(auth) = auth {
                    request = request.header("proxy-authorization", auth);
                }
                let mut request = request.body(()).unwrap();
                request
                    .extensions_mut()
                    .insert(::h2::ext::Protocol::from_static("websocket"));
                let (reply, _) = h2.send_request(request, true).unwrap();
                let reply = tokio::time::timeout(Duration::from_secs(5), reply)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    reply.status(),
                    status,
                    "H2 full={full} host={host} path={path}"
                );
                for name in ["proxy-authenticate", "proxy-authentication-info", "padding"] {
                    assert!(!reply.headers().contains_key(name));
                }
                observed.push((reply.status().as_u16(), body(reply.into_body()).await));
                let mut headers = vec![
                    quiche::h3::Header::new(b":method", b"CONNECT"),
                    quiche::h3::Header::new(b":authority", host.as_bytes()),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":path", path.as_bytes()),
                    quiche::h3::Header::new(b":protocol", b"websocket"),
                    quiche::h3::Header::new(b"sec-websocket-version", version.as_bytes()),
                ];
                if let Some(auth) = auth {
                    headers.push(quiche::h3::Header::new(
                        b"proxy-authorization",
                        auth.as_bytes(),
                    ));
                }
                let id = q.send_headers(&headers, true).unwrap();
                let reply = q.response(id).await;
                assert_eq!(
                    reply.status, status,
                    "H3 full={full} host={host} path={path}"
                );
                for name in ["proxy-authenticate", "proxy-authentication-info", "padding"] {
                    assert!(!reply.headers.contains_key(name));
                }
                observed.push((reply.status, reply.body));
            }
        }
        if full {
            assert_eq!(observed, baseline);
        } else {
            baseline = observed;
        }
        drop(held);
        assert_eq!(app.resources.tunnels.active(), 0);
    }
    assert_eq!(app.stats.dials.load(Ordering::Relaxed), 0);
    assert_eq!(app.stats.resolutions.load(Ordering::Relaxed), 0);
    driver.abort();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn h1_h2_h3_websocket_routes_only_fixed_origins_and_preserves_first_bytes() {
    let mut f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = listener.local_addr().unwrap();
    let cfg = Arc::get_mut(&mut f.config).unwrap();
    cfg.listener.h1 = true;
    cfg.website.max_request_body_bytes = 4;
    cfg.website
        .upstreams
        .push(moon_naive_core::website::Upstream {
            name: "ws".into(),
            origins: vec![format!("http://{origin_addr}")],
            tls_server_name: None,
            host_header: None,
            ca_file: None,
            http2: false,
        });
    cfg.website.routes.push(moon_naive_core::website::Route {
        path_prefix: "/ws".into(),
        upstream: "ws".into(),
        strip_prefix: false,
    });
    let origin = tokio::spawn(async move {
        use base64::Engine;
        for _ in 0..4 {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(s.read_u8().await.unwrap());
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /ws HTTP/1."));
            for forbidden in [
                "proxy-authorization",
                "proxy-connection",
                "padding-type-request",
                "x-forwarded-port",
                "spoofed-client",
            ] {
                assert!(
                    !request.to_ascii_lowercase().contains(forbidden),
                    "{request}"
                );
            }
            if !request.to_ascii_lowercase().contains("upgrade: websocket") {
                s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                )
                .await
                .unwrap();
                continue;
            }
            let key = request
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-key"))
                        .map(|(_, v)| v.trim())
                })
                .unwrap();
            let accept = base64::engine::general_purpose::STANDARD.encode(boring::sha::sha1(
                format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
            ));
            s.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\nhello").as_bytes()).await.unwrap();
            let mut input = Vec::new();
            s.read_to_end(&mut input).await.unwrap();
            assert_eq!(input, b"raw-websocket-data");
            s.shutdown().await.unwrap();
        }
    });
    let server = network(&f, None).await;
    let addr = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let legacy = h1_request(&f, addr,
        "GET /ws HTTP/1.0\r\nHost: proxy.example.test\r\nX-Forwarded-For: spoofed-client\r\nX-Forwarded-Port: 12345\r\nProxy-Authorization: Basic private\r\nConnection: close\r\n\r\n", true).await;
    assert!(legacy.ends_with("hello"), "{legacy}");
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(&f.ca).unwrap();
    connector.set_alpn_protos(b"\x08http/1.1").unwrap();
    let mut ws = tokio_boring::connect(
        connector.build().configure().unwrap(),
        "proxy.example.test",
        TcpStream::connect(addr).await.unwrap(),
    )
    .await
    .unwrap();
    ws.write_all(b"GET /ws HTTP/1.1\r\nHost: proxy.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Forwarded-Port: 12345\r\nX-Forwarded-For: spoofed-client\r\nProxy-Authorization: Basic private\r\nPadding-Type-Request: 1\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(ws.read_u8().await.unwrap());
    }
    assert!(
        header.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&header)
    );
    let mut hello = [0; 5];
    ws.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"hello");
    ws.write_all(b"raw-websocket-data").await.unwrap();
    ws.shutdown().await.unwrap();
    drop(ws);
    let (mut client, connection) = h2_client(addr, &f.ca).await;
    for _ in 0..100 {
        if client.sender.is_extended_connect_protocol_enabled() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(client.sender.is_extended_connect_protocol_enabled());
    let mut req = http::Request::builder()
        .method("CONNECT")
        .uri("https://proxy.example.test/ws")
        .header("sec-websocket-version", "13")
        .header("x-forwarded-port", "12345")
        .header("x-forwarded-for", "spoofed-client")
        .header("proxy-authorization", "Basic private")
        .header("padding-type-request", "1")
        .body(())
        .unwrap();
    req.extensions_mut()
        .insert(::h2::ext::Protocol::from_static("websocket"));
    let (response, mut send) = client.send_request(req, false).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("padding"));
    send.send_data(Bytes::from_static(b"raw-websocket-data"), true)
        .unwrap();
    assert_eq!(body(response.into_body()).await, b"hello");
    let mut q = QClient::new(udp, &f.ca).await;
    for _ in 0..100 {
        if q.h3.as_ref().unwrap().extended_connect_enabled_by_peer() {
            break;
        }
        q.step().await;
    }
    assert!(q.h3.as_ref().unwrap().extended_connect_enabled_by_peer());
    let headers = [
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":authority", b"proxy.example.test"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":path", b"/ws"),
        quiche::h3::Header::new(b":protocol", b"websocket"),
        quiche::h3::Header::new(b"sec-websocket-version", b"13"),
        quiche::h3::Header::new(b"x-forwarded-port", b"12345"),
        quiche::h3::Header::new(b"x-forwarded-for", b"spoofed-client"),
        quiche::h3::Header::new(b"proxy-authorization", b"Basic private"),
        quiche::h3::Header::new(b"padding-type-request", b"1"),
    ];
    let id = q.send_headers(&headers, false).unwrap();
    q.send(id, b"raw-websocket-data").await;
    let reply = q.response(id).await;
    assert_eq!(reply.status, 200);
    assert!(!reply.padding);
    assert_eq!(reply.body, b"hello");
    origin.await.unwrap();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    connection.abort();
}

#[tokio::test]
async fn authenticated_h2_h3_forward_http_uses_checked_egress_and_strips_credentials() {
    let f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                bytes.push(s.read_u8().await.unwrap());
            }
            let header = String::from_utf8(bytes).unwrap();
            assert!(header.starts_with("POST /echo?q=1 HTTP/1.1"), "{header}");
            assert!(!header.to_ascii_lowercase().contains("proxy-authorization"));
            for name in [
                "x-forwarded-",
                "forwarded:",
                "x-real-ip:",
                "via:",
                "x_forwarded_for:",
            ] {
                assert!(
                    !header.to_ascii_lowercase().contains(name),
                    "forward identity leaked: {header}"
                );
            }
            assert!(
                header
                    .to_ascii_lowercase()
                    .contains("x-application: keep-me")
            );
            assert!(header.to_ascii_lowercase().contains("host: 1.1.1.1"));
            assert!(
                header
                    .to_ascii_lowercase()
                    .contains("transfer-encoding: chunked")
            );
            let mut framed = Vec::new();
            while !framed.ends_with(b"0\r\n\r\n") {
                framed.push(s.read_u8().await.unwrap());
            }
            assert_eq!(&framed, b"4\r\ndata\r\n0\r\n\r\n");
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata")
                .await
                .unwrap();
        }
    });
    let server = network(&f, Some(addr)).await;
    let address = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut h2, driver) = h2_client(address, &f.ca).await;
    let (reply, _) = h2
        .send_request(
            http::Request::builder()
                .uri("http://1.1.1.1/echo?q=1")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    assert_eq!(reply.await.unwrap().status(), 404);
    assert_eq!(stats.dials.load(Ordering::Relaxed), 0);
    let (req, mut body_send) = h2
        .send_request(
            http::Request::builder()
                .method("POST")
                .uri("http://1.1.1.1/echo?q=1")
                .header("proxy-authorization", auth())
                .header("content-length", "4")
                .header("via", "1.1 private-proxy")
                .header("x_forwarded_for", "spoofed-client")
                .header("x-application", "keep-me")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    body_send
        .send_data(Bytes::from_static(b"data"), true)
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), req)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("alt-svc"));
    assert!(!response.headers().contains_key("padding"));
    assert_eq!(body(response.into_body()).await, b"data");
    let mut q = QClient::new(udp, &f.ca).await;
    let auth = auth();
    let headers = [
        quiche::h3::Header::new(b":method", b"POST"),
        quiche::h3::Header::new(b":scheme", b"http"),
        quiche::h3::Header::new(b":authority", b"1.1.1.1"),
        quiche::h3::Header::new(b":path", b"/echo?q=1"),
        quiche::h3::Header::new(b"proxy-authorization", auth.as_bytes()),
        quiche::h3::Header::new(b"via", b"1.1 private-proxy"),
        quiche::h3::Header::new(b"x_forwarded_for", b"spoofed-client"),
        quiche::h3::Header::new(b"x-application", b"keep-me"),
    ];
    let id = q.send_headers(&headers, false).unwrap();
    q.send(id, b"data").await;
    let response = q.response(id).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"data");
    assert!(!response.padding);
    assert!(!response.headers.contains_key("alt-svc"));
    origin.await.unwrap();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    driver.abort();
}

#[tokio::test]
async fn https_upstream_reuses_context_but_verifies_each_peer_and_new_generation() {
    let mut f = fixture();
    Arc::get_mut(&mut f.config).unwrap().listener.h1 = true;
    let generation = tls::Slot::load(&f.config).unwrap().current().unwrap();
    let mut other = fixture();
    Arc::get_mut(&mut other.config).unwrap().listener.h1 = true;
    let untrusted = tls::Slot::load(&other.config).unwrap().current().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for attempt in 0..5 {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = if attempt == 2 {
                &untrusted.h2
            } else {
                &generation.h2
            };
            let Ok(mut stream) = tokio_boring::accept(tls, socket).await else {
                assert!(attempt >= 2);
                continue;
            };
            assert!(!stream.ssl().session_reused());
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                match stream.read_u8().await {
                    Ok(byte) => request.push(byte),
                    Err(_) => {
                        assert!(attempt >= 2);
                        break;
                    }
                }
            }
            if attempt >= 2 {
                continue;
            }
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nsecure")
                .await
                .unwrap();
        }
    });
    let mut config = hop(ProxyKind::Https, address.to_string());
    config.tls_server_name = Some("proxy.example.test".into());
    let roots = f._root.path().join("next-hop-roots.crt");
    std::fs::copy(&f.ca, &roots).unwrap();
    config.ca_file = Some(roots.clone());
    let upstream = Arc::new(egress::NextHop::new(config.clone()).unwrap());
    for _ in 0..2 {
        let clone = upstream.clone();
        let mut stream = clone
            .handshake(
                TcpStream::connect(address).await.unwrap(),
                "1.1.1.1:443".parse().unwrap(),
            )
            .await
            .unwrap();
        let mut bytes = [0; 6];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"secure");
        if roots.exists() {
            std::fs::remove_file(&roots).unwrap();
            assert!(egress::NextHop::new(config.clone()).is_err());
        }
    }
    // The already-used context must still reject a new peer with an untrusted CA.
    assert!(
        upstream
            .handshake(
                TcpStream::connect(address).await.unwrap(),
                "1.1.1.1:443".parse().unwrap(),
            )
            .await
            .is_err()
    );
    // A new configuration must rebuild trust; it cannot inherit the old context.
    config.ca_file = Some(f.ca.clone());
    config.tls_server_name = Some("wrong.example.test".into());
    assert!(
        egress::NextHop::new(config.clone())
            .unwrap()
            .handshake(
                TcpStream::connect(address).await.unwrap(),
                "1.1.1.1:443".parse().unwrap()
            )
            .await
            .is_err()
    );
    config.tls_server_name = Some("proxy.example.test".into());
    config.ca_file =
        Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/le-staging-roots.crt"));
    assert!(
        egress::NextHop::new(config)
            .unwrap()
            .handshake(
                TcpStream::connect(address).await.unwrap(),
                "1.1.1.1:443".parse().unwrap(),
            )
            .await
            .is_err()
    );
    server.await.unwrap();
}

/// Complete loopback TCP + verified TLS + HTTP CONNECT + first tunnel byte.
/// No session resumption, public network, or proxy destination DNS is involved.
#[tokio::test]
#[ignore = "release latency benchmark; run separately with --nocapture --test-threads=1"]
async fn benchmark_https_next_hop_connect() {
    const SAMPLES: usize = 64;
    let mut f = fixture();
    Arc::get_mut(&mut f.config).unwrap().listener.h1 = true;
    let generation = tls::Slot::load(&f.config).unwrap().current().unwrap();
    let roots = f._root.path().join("benchmark-roots.crt");
    let mut bundle = std::fs::read(crate::trust::system_ca_file().unwrap()).unwrap();
    bundle.extend(std::fs::read(&f.ca).unwrap());
    std::fs::write(&roots, bundle).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..=SAMPLES {
            let (socket, _) = listener.accept().await.unwrap();
            socket.set_nodelay(true).unwrap();
            let mut stream = tokio_boring::accept(&generation.h2, socket).await.unwrap();
            assert!(!stream.ssl().session_reused());
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            assert!(request.starts_with(b"CONNECT 1.1.1.1:443 HTTP/1.1\r\n"));
            stream.write_all(b"HTTP/1.1 200 OK\r\n\r\nx").await.unwrap();
        }
    });
    let mut config = hop(ProxyKind::Https, address.to_string());
    config.tls_server_name = Some("proxy.example.test".into());
    config.ca_file = Some(roots);
    let setup = std::time::Instant::now();
    let upstream = egress::NextHop::new(config).unwrap();
    let setup_us = setup.elapsed().as_secs_f64() * 1_000_000.;
    let mut samples = Vec::new();
    let mut cold = 0.;
    for index in 0..=SAMPLES {
        let start = std::time::Instant::now();
        let socket = TcpStream::connect(address).await.unwrap();
        socket.set_nodelay(true).unwrap();
        let mut stream = upstream
            .handshake(socket, "1.1.1.1:443".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), b'x');
        let micros = start.elapsed().as_secs_f64() * 1_000_000.;
        if index == 0 {
            cold = micros;
        } else {
            samples.push(micros);
        }
    }
    server.await.unwrap();
    samples.sort_by(f64::total_cmp);
    eprintln!(
        "PERF {{\"case\":\"https_next_hop_connect\",\"samples\":{SAMPLES},\"setup_us\":{setup_us},\"cold_us\":{cold},\"median_us\":{},\"p95_us\":{}}}",
        samples[SAMPLES / 2],
        samples[SAMPLES * 95 / 100]
    );
}

#[tokio::test]
async fn forward_https_reuses_roots_but_still_rejects_wrong_name_and_untrusted_ca() {
    let f = fixture();
    let leaf_key = key();
    let mut leaf = X509::builder().unwrap();
    leaf.set_version(2).unwrap();
    leaf.set_serial_number(&BigNum::from_u32(9).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    let mut subject = X509NameBuilder::new().unwrap();
    subject
        .append_entry_by_text("CN", "forward origin")
        .unwrap();
    leaf.set_subject_name(&subject.build()).unwrap();
    leaf.set_issuer_name(f.ca_cert.subject_name()).unwrap();
    leaf.set_pubkey(&leaf_key).unwrap();
    leaf.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    leaf.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    leaf.append_extension(&BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    leaf.append_extension(&ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    leaf.append_extension(
        &SubjectAlternativeName::new()
            .ip("1.1.1.1")
            .build(&leaf.x509v3_context(Some(&f.ca_cert), None))
            .unwrap(),
    )
    .unwrap();
    leaf.sign(&f.ca_key, MessageDigest::sha256()).unwrap();
    let mut tls = boring::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    tls.set_certificate(&leaf.build()).unwrap();
    tls.set_private_key(&leaf_key).unwrap();
    let tls = tls.build();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        for attempt in 0..4 {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = match tokio_boring::accept(&tls, socket).await {
                Ok(stream) => stream,
                Err(error) => {
                    assert!(attempt >= 2, "origin TLS handshake: {error}");
                    continue;
                }
            };
            let mut request = Vec::new();
            let read = async {
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await?);
                }
                std::io::Result::Ok(())
            }
            .await;
            if attempt >= 2 {
                assert!(read.is_err());
                continue;
            }
            read.unwrap();
            assert!(
                !String::from_utf8_lossy(&request)
                    .to_ascii_lowercase()
                    .contains("proxy-authorization")
            );
            let header = String::from_utf8_lossy(&request).to_ascii_lowercase();
            for name in ["x-forwarded-", "forwarded:", "x-real-ip:", "via:"] {
                assert!(
                    !header.contains(name),
                    "HTTPS forward identity leaked: {header}"
                );
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecure",
                )
                .await
                .unwrap();
        }
    });
    let roots_path = f._root.path().join("forward-roots.crt");
    std::fs::copy(&f.ca, &roots_path).unwrap();
    let mut server = network(&f, Some(upstream_address)).await;
    Arc::get_mut(&mut server.app).unwrap().egress.roots =
        crate::trust::Roots::new(Some(roots_path.clone()));
    let address = server.tcp_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut client, driver) = h2_client(address, &f.ca).await;
    for (attempt, host) in ["1.1.1.1", "1.1.1.1", "1.0.0.1"].iter().enumerate() {
        let (reply, _) = client
            .send_request(
                http::Request::builder()
                    .uri(format!("https://{host}/"))
                    .header("proxy-authorization", auth())
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), reply)
            .await
            .unwrap()
            .unwrap();
        if attempt < 2 {
            assert_eq!(reply.status(), 200);
            assert_eq!(body(reply.into_body()).await, b"secure");
        } else {
            assert_eq!(reply.status(), 502);
        }
        if attempt == 0 {
            std::fs::remove_file(&roots_path).unwrap();
        }
    }
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    driver.abort();

    // A separate configuration generation must not inherit another CA cache.
    let other = fixture();
    let mut server = network(&f, Some(upstream_address)).await;
    Arc::get_mut(&mut server.app).unwrap().egress.roots =
        crate::trust::Roots::new(Some(other.ca.clone()));
    let address = server.tcp_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut client, driver) = h2_client(address, &f.ca).await;
    let (reply, _) = client
        .send_request(
            http::Request::builder()
                .uri("https://1.1.1.1/")
                .header("proxy-authorization", auth())
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), reply)
            .await
            .unwrap()
            .unwrap()
            .status(),
        502
    );
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    driver.abort();
    tokio::time::timeout(Duration::from_secs(5), origin)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn h1_origin_trailers_round_trip_across_h1_h2_h3() {
    let mut f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = Arc::get_mut(&mut f.config).unwrap();
    cfg.listener.h1 = true;
    cfg.website
        .upstreams
        .push(moon_naive_core::website::Upstream {
            name: "trailers".into(),
            origins: vec![format!("http://{addr}")],
            tls_server_name: None,
            host_header: None,
            ca_file: None,
            http2: false,
        });
    cfg.website.routes.push(moon_naive_core::website::Route {
        path_prefix: "/echo".into(),
        upstream: "trailers".into(),
        strip_prefix: false,
    });
    let origin = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(s.read_u8().await.unwrap());
            }
            assert!(
                String::from_utf8_lossy(&head)
                    .to_ascii_lowercase()
                    .contains("transfer-encoding: chunked")
            );
            let mut wire = Vec::new();
            while !wire.ends_with(b"\r\n\r\n") {
                wire.push(s.read_u8().await.unwrap());
            }
            let wire = String::from_utf8(wire).unwrap();
            assert!(wire.starts_with("4\r\ndata\r\n0\r\n"), "{wire}");
            assert!(wire.contains("x-request-sum: complete\r\n"), "{wire}");
            assert!(!wire.contains("proxy-authorization"), "{wire}");
            assert!(!wire.contains("proxy_authorization"), "{wire}");
            assert!(!wire.contains("proxy:"), "{wire}");
            s.write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: x-response-sum\r\nConnection: close\r\n\r\n4\r\ndata\r\n0\r\nx-response-sum: ").await.unwrap();
            // Split a trailer field across actual reads; preserve the earlier DATA.
            tokio::time::sleep(Duration::from_millis(20)).await;
            s.write_all(b"complete\r\nProxy-Authorization: never-forward\r\nProxy_Authorization: never-forward\r\nProxy: http://attacker.example\r\n\r\n")
                .await
                .unwrap();
        }
    });
    let server = network(&f, None).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let reply = h1_request(&f, tcp, "POST /echo HTTP/1.1\r\nHost: proxy.example.test\r\nTransfer-Encoding: chunked\r\nTE: trailers\r\nConnection: close\r\n\r\n4\r\ndata\r\n0\r\nx-request-sum: complete\r\nProxy-Authorization: never-forward\r\nProxy_Authorization: never-forward\r\nProxy: http://attacker.example\r\n\r\n", true).await;
    assert!(reply.starts_with("HTTP/1.1 103"), "{reply}");
    assert!(reply.contains("HTTP/1.1 200"), "{reply}");
    assert!(
        reply.contains("4\r\ndata\r\n0\r\nx-response-sum: complete\r\n\r\n"),
        "{reply}"
    );
    assert!(!reply.to_ascii_lowercase().contains("proxy-authorization"));
    assert!(!reply.to_ascii_lowercase().contains("proxy_authorization"));
    assert!(!reply.to_ascii_lowercase().contains("attacker.example"));
    let (mut client, driver) = h2_client(tcp, &f.ca).await;
    let (mut response, mut send) = client
        .send_request(
            http::Request::builder()
                .method("POST")
                .uri("https://proxy.example.test/echo")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    send.send_data(Bytes::from_static(b"data"), false).unwrap();
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-request-sum", "complete".parse().unwrap());
    trailers.insert("proxy_authorization", "never-forward".parse().unwrap());
    trailers.insert("proxy", "http://attacker.example".parse().unwrap());
    send.send_trailers(trailers).unwrap();
    let info = std::future::poll_fn(|cx| response.poll_informational(cx))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(info.status(), 103);
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut recv = response.into_body();
    let mut bytes = Vec::new();
    while let Some(part) = recv.data().await {
        let part = part.unwrap();
        recv.flow_control().release_capacity(part.len()).unwrap();
        bytes.extend_from_slice(&part);
    }
    assert_eq!(bytes, b"data");
    assert_eq!(
        recv.trailers().await.unwrap().unwrap()["x-response-sum"],
        "complete"
    );
    let mut q = QClient::new(udp, &f.ca).await;
    let id = q.request(
        "POST",
        "proxy.example.test",
        Some("/echo"),
        None,
        false,
        false,
    );
    q.h3.as_mut()
        .unwrap()
        .send_body(&mut q.conn, id, b"data", false)
        .unwrap();
    q.h3.as_mut()
        .unwrap()
        .send_additional_headers(
            &mut q.conn,
            id,
            &[quiche::h3::Header::new(b"x-request-sum", b"complete")],
            true,
            true,
        )
        .unwrap();
    let response = q.response(id).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"data");
    assert_eq!(response.headers["x-response-sum"], "complete");
    origin.await.unwrap();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    driver.abort();
}

#[tokio::test]
async fn http_redirect_uses_canonical_host_and_rejects_proxy_requests() {
    let f = fixture();
    let server = network(&f, None).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = Network {
        redirect: Some(listener),
        ..server
    };
    let stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    for (request, status, location) in [
        (
            "GET /a?q=1 HTTP/1.1\r\nHost: proxy.example.test\r\n\r\n",
            308,
            true,
        ),
        (
            "GET / HTTP/1.1\r\nHost: attacker.example\r\n\r\n",
            404,
            false,
        ),
        (
            "CONNECT proxy.example.test:443 HTTP/1.1\r\nHost: proxy.example.test\r\n\r\n",
            405,
            false,
        ),
        (
            "GET http://other.example/ HTTP/1.1\r\nHost: proxy.example.test\r\n\r\n",
            400,
            false,
        ),
    ] {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        assert!(reply.starts_with(&format!("HTTP/1.1 {status}")), "{reply}");
        if location {
            assert!(
                reply.contains(&format!(
                    "location: https://proxy.example.test:{}/a?q=1",
                    f.config.listener.tcp.port()
                )),
                "{reply}"
            );
        } else {
            assert!(!reply.contains("location:"));
        }
    }
    assert_eq!(stats.dials.load(Ordering::Relaxed), 0);
    assert_eq!(stats.resolutions.load(Ordering::Relaxed), 0);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn upstream_failure_never_sends_early_connect_success_or_falls_back_direct() {
    let mut f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let cfg = Arc::get_mut(&mut f.config).unwrap();
    cfg.listener.tcp = "0.0.0.0:8443".parse().unwrap();
    cfg.listener.udp = cfg.listener.tcp;
    cfg.proxy.upstream = Some(hop(ProxyKind::Http, address.to_string()));
    let (seen, received) = tokio::sync::oneshot::channel();
    let (release, wait) = tokio::sync::oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
        }
        assert!(header.starts_with(b"CONNECT 1.1.1.1:443 HTTP/1.1\r\n"));
        seen.send(()).unwrap();
        wait.await.unwrap();
        stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let server = network(&f, None).await;
    let address = server.tcp_addr().unwrap();
    let stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut client, driver) = h2_client(address, &f.ca).await;
    let (mut response, _send) = client
        .send_request(
            http::Request::builder()
                .method("CONNECT")
                .uri("1.1.1.1:443")
                .header("proxy-authorization", auth())
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), received)
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut response)
            .await
            .is_err()
    );
    release.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .unwrap()
            .unwrap()
            .status(),
        502
    );
    assert_eq!(
        stats.dials.load(Ordering::Relaxed),
        1,
        "no direct fallback dial"
    );
    upstream.await.unwrap();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    driver.abort();
}

#[tokio::test]
async fn h1_ambiguous_framing_never_reaches_origin_and_site_metadata_is_clean() {
    let mut f = fixture();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cfg = Arc::get_mut(&mut f.config).unwrap();
    cfg.listener.h1 = true;
    cfg.website
        .upstreams
        .push(moon_naive_core::website::Upstream {
            name: "mirror".into(),
            origins: vec![format!("http://{}", origin.local_addr().unwrap())],
            tls_server_name: None,
            host_header: None,
            ca_file: None,
            http2: false,
        });
    cfg.website.routes.clear();
    cfg.website.routes.push(moon_naive_core::website::Route {
        path_prefix: "/".into(),
        upstream: "mirror".into(),
        strip_prefix: false,
    });
    let server = network(&f, None).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let mut attacks = vec![
        "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n".to_owned(),
        "Content-Length: 0\r\nContent-Length: 0\r\n".to_owned(),
        "Content-Length: 0, 0\r\n".to_owned(),
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n".to_owned(),
        "Transfer-Encoding: gzip, chunked\r\n".to_owned(),
        "Transfer-Encoding : chunked\r\n".to_owned(),
        "X-Fold: value\r\n other\r\n".to_owned(),
        "X-Bare: value\n".to_owned(),
        "Host: attacker.example\r\n".to_owned(),
        "Connection: Host\r\n".to_owned(),
        "Connection: Content-Length\r\nContent-Length: 0\r\n".to_owned(),
        "Connection: X-Forwarded-For\r\nX-Forwarded-For: attacker.example\r\n".to_owned(),
        "Connection: Proxy_Authorization\r\n".to_owned(),
        "X-Large: ".to_owned() + &"a".repeat(32768) + "\r\n",
        "X-Field: a\r\n".repeat(128),
    ];
    attacks.push("Content-Length: 18446744073709551616\r\n".into());
    for fields in attacks {
        let request = format!(
            "POST / HTTP/1.1\r\nHost: proxy.example.test\r\n{fields}\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: proxy.example.test\r\n\r\n"
        );
        let response = h1_request(&f, tcp, &request, true).await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        assert_eq!(response.matches("HTTP/1.1 ").count(), 1);
        assert!(
            !response.to_ascii_lowercase().contains("server: pingora"),
            "{response}"
        );
        assert!(
            !response
                .to_ascii_lowercase()
                .contains("proxy-authenticate:")
        );
    }
    for request in [
        "GET https://attacker.example/ HTTP/1.1\r\nHost: proxy.example.test\r\nConnection: close\r\n\r\n",
        "GET https://proxy.example.test:8443/ HTTP/1.1\r\nHost: proxy.example.test\r\nConnection: close\r\n\r\n",
        "GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: user@proxy.example.test\r\nConnection: close\r\n\r\n",
    ] {
        let response = h1_request(&f, tcp, request, true).await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), origin.accept())
            .await
            .is_err()
    );
    let backend = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut socket, _) = origin.accept().await.unwrap();
            let mut raw = Vec::new();
            while !raw.ends_with(b"\r\n\r\n") {
                raw.push(socket.read_u8().await.unwrap());
            }
            let head = String::from_utf8(raw).unwrap().to_ascii_lowercase();
            for forbidden in [
                "proxy:",
                "proxy-authorization:",
                "fastopen:",
                "proxy_authorization:",
                "padding",
                "x_forwarded_for:",
                "attacker.example",
            ] {
                assert!(!head.contains(forbidden), "{head}");
            }
            assert!(head.contains("x_app_value: retained"), "{head}");
            assert!(
                head.contains("authorization: bearer website-token"),
                "{head}"
            );
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nServer: PHP-test\r\nX-Powered-By: backend-version\r\nCache-Control: public, max-age=60\r\nETag: \"mirror\"\r\nConnection: close\r\n\r\nmirror").await.unwrap();
        }
    });
    let metadata = [
        ("fastopen", "1"),
        ("proxy", "http://attacker.example"),
        ("proxy_authorization", "secret"),
        ("padding_type_request", "1"),
        ("x_forwarded_for", "attacker.example"),
        ("x_app_value", "retained"),
        ("authorization", "Bearer website-token"),
    ];
    let fields = metadata
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect::<String>();
    let response = h1_request(&f, tcp, &format!("GET / HTTP/1.1\r\nHost: proxy.example.test\r\nProxy-Authorization: {}\r\n{fields}Connection: close\r\n\r\n", auth()), true).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("mirror"));
    assert!(!response.to_ascii_lowercase().contains("server:"));
    assert!(!response.to_ascii_lowercase().contains("x-powered-by:"));
    let (mut h2, driver) = h2_client(tcp, &f.ca).await;
    let mut request = http::Request::builder().uri("https://proxy.example.test/");
    for (k, v) in metadata {
        request = request.header(k, v);
    }
    let (reply, _) = h2.send_request(request.body(()).unwrap(), true).unwrap();
    let reply = reply.await.unwrap();
    assert_eq!(reply.status(), 200);
    assert!(!reply.headers().contains_key("server"));
    assert!(!reply.headers().contains_key("x-powered-by"));
    assert_eq!(reply.headers()["etag"], "\"mirror\"");
    assert_eq!(body(reply.into_body()).await, b"mirror");
    let mut q = QClient::new(udp, &f.ca).await;
    let mut fields = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"proxy.example.test"),
        quiche::h3::Header::new(b":path", b"/"),
    ];
    fields.extend(
        metadata
            .iter()
            .map(|(k, v)| quiche::h3::Header::new(k.as_bytes(), v.as_bytes())),
    );
    let id = q.send_headers(&fields, true).unwrap();
    let response = q.response(id).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"mirror");
    assert!(!response.headers.contains_key("server"));
    assert!(!response.headers.contains_key("x-powered-by"));
    assert_eq!(response.headers["cache-control"], "public, max-age=60");
    backend.await.unwrap();
    assert_eq!(stats.dials.load(Ordering::Relaxed), 0);
    assert_eq!(stats.resolutions.load(Ordering::Relaxed), 0);
    driver.abort();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn h1_header_deadline_is_not_extended_by_dripping_bytes() {
    let mut f = fixture();
    Arc::get_mut(&mut f.config).unwrap().listener.h1 = true;
    let server = network(&f, None).await;
    let address = server.tcp_addr().unwrap();
    let connections = server.connections.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(&f.ca).unwrap();
    connector.set_alpn_protos(b"\x08http/1.1").unwrap();
    let mut stream = tokio_boring::connect(
        connector.build().configure().unwrap(),
        "proxy.example.test",
        TcpStream::connect(address).await.unwrap(),
    )
    .await
    .unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: proxy.example.test\r\nX-Slow: ")
        .await
        .unwrap();
    let began = std::time::Instant::now();
    let (mut read, mut write) = tokio::io::split(stream);
    let writer = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if write.write_all(b"a").await.is_err() {
                break;
            }
        }
    });
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(12), read.read_to_end(&mut response))
        .await
        .expect("dripping header retained its connection");
    assert!(began.elapsed() >= Duration::from_secs(9));
    assert!(response.is_empty());
    writer.abort();
    assert_eq!(connections.active(), 0);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn reused_h2_h3_connections_never_inherit_auth_and_quic_replay_does_not_redial() {
    let f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"accepted").await.unwrap();
            socket.shutdown().await.unwrap();
        }
    });
    let server = network(&f, Some(address)).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut h2, driver) = h2_client(tcp, &f.ca).await;
    let credential = auth();
    let sequences = [
        vec![("proxy-authorization", credential.as_str())],
        vec![],
        vec![("proxy-authorization", "Basic invalid")],
        // Correct revision/offer/encoding, but no valid stream-bound MAC.
        vec![(
            "proxy-authorization",
            "moon-naive 02.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )],
        vec![
            ("proxy-authorization", credential.as_str()),
            ("proxy-authorization", credential.as_str()),
        ],
        vec![("proxy_authorization", credential.as_str())],
    ];
    let mut h2_fallback = None;
    for (index, fields) in sequences.iter().enumerate() {
        let mut request = http::Request::builder()
            .method("CONNECT")
            .uri("1.1.1.1:443");
        for (name, value) in fields {
            request = request.header(*name, *value);
        }
        let (reply, _) = h2.send_request(request.body(()).unwrap(), true).unwrap();
        let reply = reply.await.unwrap();
        assert_eq!(reply.status(), if index == 0 { 200 } else { 404 });
        assert!(!reply.headers().contains_key("proxy-authenticate"));
        let mut headers = reply.headers().clone();
        headers.remove("date");
        let bytes = body(reply.into_body()).await;
        if index == 0 {
            assert!(headers.contains_key("proxy-authentication-info"));
            assert_eq!(unframe(&bytes), b"accepted");
        } else {
            assert!(!bytes.is_empty());
            for name in ["proxy-authentication-info", "padding"] {
                assert!(!headers.contains_key(name));
            }
            let observed = (headers, bytes);
            if let Some(expected) = &h2_fallback {
                assert_eq!(&observed, expected);
            } else {
                h2_fallback = Some(observed);
            }
        }
    }
    assert_eq!(stats.dials.load(Ordering::Relaxed), 1);
    let mut q = QClient::new(udp, &f.ca).await;
    q.replay_packets = true;
    let mut h3_fallback = None;
    for (index, fields) in sequences.iter().enumerate() {
        let mut headers = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":authority", b"1.1.1.1:443"),
        ];
        headers.extend(
            fields
                .iter()
                .map(|(n, v)| quiche::h3::Header::new(n.as_bytes(), v.as_bytes())),
        );
        let id = q.send_headers(&headers, true).unwrap();
        let mut reply = q.response(id).await;
        assert_eq!(reply.status, if index == 0 { 200 } else { 404 });
        assert!(!reply.headers.contains_key("proxy-authenticate"));
        if index == 0 {
            assert!(reply.headers.contains_key("proxy-authentication-info"));
            assert_eq!(unframe(&reply.body), b"accepted");
        } else {
            assert!(!reply.body.is_empty());
            for name in ["proxy-authentication-info", "padding"] {
                assert!(!reply.headers.contains_key(name));
            }
            reply.headers.remove("date");
            let observed = (reply.headers, reply.body);
            if let Some(expected) = &h3_fallback {
                assert_eq!(&observed, expected);
            } else {
                h3_fallback = Some(observed);
            }
        }
    }
    assert_eq!(stats.dials.load(Ordering::Relaxed), 2);
    origin.await.unwrap();
    driver.abort();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn incomplete_quic_handshake_releases_connection_and_receive_budget() {
    let mut f = fixture();
    Arc::get_mut(&mut f.config)
        .unwrap()
        .limits
        .idle_timeout_secs = 60;
    let server = network(&f, None).await;
    let udp = server.udp_addr().unwrap();
    let connections = server.connections.clone();
    let receive = server.app.resources.receive.clone();
    let available = receive.available_permits();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let mut half_open = QClient::initial(udp, &f.ca).await;
    let mut out = [0; 1350];
    while let Ok((n, info)) = half_open.conn.send(&mut out) {
        half_open.socket.send_to(&out[..n], info.to).await.unwrap();
    }
    // Process only the stateless Retry, then submit its token in a new Initial.
    // Do not process/acknowledge any server TLS flight after it allocates state.
    let mut packet = [0; 65535];
    let (n, from) = tokio::time::timeout(
        Duration::from_secs(2),
        half_open.socket.recv_from(&mut packet),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        quiche::Header::from_slice(&mut packet[..n], quiche::MAX_CONN_ID_LEN)
            .unwrap()
            .ty,
        quiche::Type::Retry
    );
    half_open
        .conn
        .recv(
            &mut packet[..n],
            quiche::RecvInfo {
                from,
                to: half_open.socket.local_addr().unwrap(),
            },
        )
        .unwrap();
    while let Ok((n, info)) = half_open.conn.send(&mut out) {
        half_open.socket.send_to(&out[..n], info.to).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while connections.active() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(receive.available_permits() < available);
    let began = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(12), async {
        while connections.active() != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("half-open QUIC retained quota until application idle timeout");
    assert!(began.elapsed() >= Duration::from_secs(9));
    assert_eq!(receive.available_permits(), available);
    let mut healthy = QClient::new(udp, &f.ca).await;
    let id = healthy.request("GET", "proxy.example.test", Some("/"), None, false, true);
    assert_eq!(healthy.response(id).await.status, 200);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn h2_protocol_error_reset_flood_is_closed_without_affecting_other_clients() {
    let f = fixture();
    let server = network(&f, None).await;
    let tcp = server.tcp_addr().unwrap();
    let app = server.app.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(&f.ca).unwrap();
    connector.set_alpn_protos(b"\x02h2").unwrap();
    let mut stream = tokio_boring::connect(
        connector.build().configure().unwrap(),
        "proxy.example.test",
        TcpStream::connect(tcp).await.unwrap(),
    )
    .await
    .unwrap();
    let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    wire.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]); // empty client SETTINGS
    // HPACK indexed GET/https/path, authority, and illegal response-only :status.
    // Each stream is syntactically framed but must be reset by the H2 library.
    let mut block = vec![0x82, 0x87, 0x84, 0x01, 18];
    block.extend_from_slice(b"proxy.example.test");
    block.push(0x88);
    for id in (1u32..260).step_by(2) {
        wire.extend_from_slice(&[0, 0, block.len() as u8, 1, 5]);
        wire.extend_from_slice(&id.to_be_bytes());
        wire.extend_from_slice(&block);
    }
    stream.write_all(&wire).await.unwrap();
    let code = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let mut frame = [0; 9];
            stream.read_exact(&mut frame).await.unwrap();
            let length = u32::from_be_bytes([0, frame[0], frame[1], frame[2]]) as usize;
            assert!(length <= 16384);
            let mut payload = vec![0; length];
            stream.read_exact(&mut payload).await.unwrap();
            if frame[3] == 7 {
                break u32::from_be_bytes(payload[4..8].try_into().unwrap());
            }
        }
    })
    .await
    .expect("protocol error flood was not bounded");
    assert_eq!(code, u32::from(::h2::Reason::ENHANCE_YOUR_CALM));
    assert_eq!(app.stats.dials.load(Ordering::Relaxed), 0);
    let (mut healthy, driver) = h2_client(tcp, &f.ca).await;
    let (reply, _) = healthy
        .send_request(
            http::Request::builder()
                .uri("https://proxy.example.test/")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    assert_eq!(reply.await.unwrap().status(), 200);
    driver.abort();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn tls_origin_reuse_preserves_sni_ca_isolation_and_san_precedence_over_cn() {
    let mut f = fixture();
    let other = fixture();
    let leaf_key = key();
    let mut subject = X509NameBuilder::new().unwrap();
    subject
        .append_entry_by_text("CN", "wrong.example.test")
        .unwrap();
    let mut leaf = X509::builder().unwrap();
    leaf.set_version(2).unwrap();
    leaf.set_serial_number(&BigNum::from_u32(42).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    leaf.set_subject_name(&subject.build()).unwrap();
    leaf.set_issuer_name(f.ca_cert.subject_name()).unwrap();
    leaf.set_pubkey(&leaf_key).unwrap();
    leaf.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    leaf.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    leaf.append_extension(&BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    leaf.append_extension(&ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    leaf.append_extension(
        &SubjectAlternativeName::new()
            .dns("correct.example.test")
            .build(&leaf.x509v3_context(Some(&f.ca_cert), None))
            .unwrap(),
    )
    .unwrap();
    leaf.sign(&f.ca_key, MessageDigest::sha256()).unwrap();
    let mut tls = boring::ssl::SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    tls.set_certificate(&leaf.build()).unwrap();
    tls.set_private_key(&leaf_key).unwrap();
    let tls = tls.build();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let origin = tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        let mut id = 0;
        loop {
            tokio::select! {
                Some(_) = children.join_next(), if !children.is_empty() => {},
                accepted = listener.accept() => {
                    let (socket,_) = accepted.unwrap();
                    id += 1;
                    let tls = tls.clone();
                    let count = count.clone();
                    children.spawn(async move {
                        let Ok(mut socket) = tokio_boring::accept(&tls, socket).await else { return };
                        loop {
                            let mut raw = Vec::new();
                            while !raw.ends_with(b"\r\n\r\n") {
                                let Ok(byte) = socket.read_u8().await else { return };
                                raw.push(byte);
                            }
                            count.fetch_add(1,Ordering::Relaxed);
                            let data = id.to_string();
                            if socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{data}",data.len()).as_bytes()).await.is_err() { return }
                        }
                    });
                }
            }
        }
    });
    let cfg = Arc::get_mut(&mut f.config).unwrap();
    for (name, sni, ca) in [
        ("good", "correct.example.test", f.ca.clone()),
        ("wrong-name", "wrong.example.test", f.ca.clone()),
        ("wrong-ca", "correct.example.test", other.ca.clone()),
    ] {
        cfg.website
            .upstreams
            .push(moon_naive_core::website::Upstream {
                name: name.into(),
                origins: vec![format!("https://{origin_address}")],
                tls_server_name: Some(sni.into()),
                host_header: None,
                ca_file: Some(ca),
                http2: false,
            });
        cfg.website.routes.push(moon_naive_core::website::Route {
            path_prefix: format!("/{name}"),
            upstream: name.into(),
            strip_prefix: false,
        });
    }
    let server = network(&f, None).await;
    let address = server.tcp_addr().unwrap();
    let stats = server.app.site.stats().clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut client, driver) = h2_client(address, &f.ca).await;
    let mut connection_id = Vec::new();
    for name in ["good", "good", "wrong-name", "wrong-ca", "good"] {
        let (reply, _) = client
            .send_request(
                http::Request::builder()
                    .uri(format!("https://proxy.example.test/{name}"))
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), reply)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply.status(), if name == "good" { 200 } else { 502 });
        let data = body(reply.into_body()).await;
        if name == "good" {
            if connection_id.is_empty() {
                connection_id = data;
            } else {
                assert_eq!(data, connection_id);
            }
        }
    }
    assert_eq!(requests.load(Ordering::Relaxed), 3);
    assert_eq!(stats.upstream_reuses.load(Ordering::Relaxed), 2);
    driver.abort();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    origin.abort();
}

#[tokio::test]
async fn h1_keepalive_serves_one_thousand_requests_then_closes() {
    use tokio::io::AsyncBufReadExt;
    let mut f = fixture();
    Arc::get_mut(&mut f.config).unwrap().listener.h1 = true;
    let server = network(&f, None).await;
    let address = server.tcp_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(&f.ca).unwrap();
    connector.set_alpn_protos(b"\x08http/1.1").unwrap();
    let stream = tokio_boring::connect(
        connector.build().configure().unwrap(),
        "proxy.example.test",
        TcpStream::connect(address).await.unwrap(),
    )
    .await
    .unwrap();
    let mut stream = tokio::io::BufReader::new(stream);
    tokio::time::timeout(Duration::from_secs(15), async {
        for index in 0..1000 {
            stream
                .write_all(b"HEAD / HTTP/1.1\r\nHost: proxy.example.test\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            while !response.ends_with(b"\r\n\r\n") {
                assert_ne!(stream.read_until(b'\n', &mut response).await.unwrap(), 0);
            }
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            if index == 999 {
                assert!(
                    response.to_ascii_lowercase().contains("connection: close"),
                    "{response}"
                );
            }
        }
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    })
    .await
    .unwrap();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn h1_website_remains_available_when_h2_receive_credit_is_exhausted() {
    let mut f = fixture();
    Arc::get_mut(&mut f.config).unwrap().listener.h1 = true;
    let server = network(&f, None).await;
    let address = server.tcp_addr().unwrap();
    let budget = server.app.resources.receive.clone();
    let held = budget
        .clone()
        .try_acquire_many_owned(budget.available_permits() as u32)
        .unwrap();
    let (stop, receive) = watch::channel(false);
    let task = tokio::spawn(server.run(receive));
    let response = h1_request(
        &f,
        address,
        "GET / HTTP/1.1\r\nHost: proxy.example.test\r\nConnection: close\r\n\r\n",
        true,
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert_eq!(budget.available_permits(), 0);
    drop(held);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn h3_nat_rebinding_consumes_path_events_and_preserves_session() {
    let mut f = fixture();
    Arc::get_mut(&mut f.config)
        .unwrap()
        .limits
        .idle_timeout_secs = 10;
    let server = network(&f, None).await;
    let address = server.udp_addr().unwrap();
    let stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    // NAT simulation: the client always talks to one relay socket. Only the
    // relay's source port toward the server changes, with real encrypted QUIC.
    let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_address = front.local_addr().unwrap();
    let (rotate, mut rotations) = tokio::sync::mpsc::channel::<tokio::sync::oneshot::Sender<()>>(1);
    let relay = tokio::spawn(async move {
        let mut upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut peer = None;
        let mut client_data = [0u8; 2048];
        let mut server_data = [0u8; 2048];
        loop {
            tokio::select! {
                Some(done)=rotations.recv()=>{
                    upstream=UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    let _=done.send(());
                },
                value=front.recv_from(&mut client_data)=>{
                    let (n,from)=value.unwrap();peer=Some(from);
                    upstream.send_to(&client_data[..n],address).await.unwrap();
                },
                value=upstream.recv_from(&mut server_data)=>{
                    let (n,from)=value.unwrap();assert_eq!(from,address);
                    if let Some(peer)=peer {front.send_to(&server_data[..n],peer).await.unwrap();}
                }
            }
        }
    });
    let mut client = QClient::new(relay_address, &f.ca).await;
    for index in 0..12 {
        // The current single-CID routing supports one rebinding. Repeated
        // changes need full CID/path retirement support, not a larger path cap.
        if index == 1 {
            let (done, wait) = tokio::sync::oneshot::channel();
            rotate.send(done).await.unwrap();
            wait.await.unwrap();
        }
        let id = client.request("GET", "proxy.example.test", Some("/"), None, false, true);
        let response = client.response(id).await;
        assert_eq!(response.status, 200);
        assert_eq!(
            response.body,
            b"<!doctype html><title>moon-naive test site</title>"
        );
        // Drive normal ACK/path-validation traffic, not a new connection.
        let until = std::time::Instant::now() + Duration::from_millis(30);
        while std::time::Instant::now() < until {
            client.step().await;
        }
    }
    assert_eq!(stats.h3_connections.load(Ordering::Relaxed), 1);
    assert_eq!(stats.dials.load(Ordering::Relaxed), 0);
    assert!(stats.h3_path_events.load(Ordering::Relaxed) >= 3);
    client.conn.close(true, 0, b"done").unwrap();
    client.step().await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    relay.abort();
}

#[tokio::test]
async fn websocket_backup_and_repeated_subprotocol_fields_preserve_raw_target() {
    let mut f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = listener.local_addr().unwrap();
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let cfg = Arc::get_mut(&mut f.config).unwrap();
    cfg.listener.h1 = true;
    cfg.website.max_request_body_bytes = 4;
    cfg.website
        .upstreams
        .push(moon_naive_core::website::Upstream {
            name: "ws".into(),
            origins: vec![
                format!("http://{dead_addr}"),
                format!("http://{origin_addr}"),
            ],
            tls_server_name: None,
            host_header: None,
            ca_file: None,
            http2: false,
        });
    cfg.website.routes.push(moon_naive_core::website::Route {
        path_prefix: "/ws".into(),
        upstream: "ws".into(),
        strip_prefix: true,
    });
    let origin = tokio::spawn(async move {
        use base64::Engine;
        for _ in 0..4 {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(s.read_u8().await.unwrap());
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET //a%2Fb?q=%2F HTTP/1."));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("x-forwarded-for: 127.0.0.1"),
                "{request}"
            );
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("x-forwarded-host: proxy.example.test"),
                "{request}"
            );
            for forbidden in [
                "proxy-authorization",
                "proxy-connection",
                "padding-type-request",
                "x-forwarded-port",
                "spoofed-client",
            ] {
                assert!(
                    !request.to_ascii_lowercase().contains(forbidden),
                    "{request}"
                );
            }
            if !request.to_ascii_lowercase().contains("upgrade: websocket") {
                s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                )
                .await
                .unwrap();
                continue;
            }
            let key = request
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-key"))
                        .map(|(_, v)| v.trim())
                })
                .unwrap();
            let accept = base64::engine::general_purpose::STANDARD.encode(boring::sha::sha1(
                format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
            ));
            let protocol = if request
                .to_ascii_lowercase()
                .contains("sec-websocket-protocol")
            {
                "Sec-WebSocket-Protocol: second\r\n"
            } else {
                ""
            };
            s.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n{protocol}\r\nhello").as_bytes()).await.unwrap();
            let mut input = Vec::new();
            s.read_to_end(&mut input).await.unwrap();
            assert_eq!(input, b"raw-websocket-data");
            s.shutdown().await.unwrap();
        }
    });
    let server = network(&f, None).await;
    let addr = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let legacy = h1_request(&f, addr,
        "GET /ws//a%2Fb?q=%2F HTTP/1.0\r\nHost: proxy.example.test\r\nX-Forwarded-For: spoofed-client\r\nX-Forwarded-Port: 12345\r\nProxy-Authorization: Basic private\r\nConnection: close\r\n\r\n", true).await;
    assert!(legacy.ends_with("hello"), "{legacy}");
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(&f.ca).unwrap();
    connector.set_alpn_protos(b"\x08http/1.1").unwrap();
    let mut ws = tokio_boring::connect(
        connector.build().configure().unwrap(),
        "proxy.example.test",
        TcpStream::connect(addr).await.unwrap(),
    )
    .await
    .unwrap();
    ws.write_all(b"GET /ws//a%2Fb?q=%2F HTTP/1.1\r\nHost: proxy.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Forwarded-Port: 12345\r\nX-Forwarded-For: spoofed-client\r\nProxy-Authorization: Basic private\r\nPadding-Type-Request: 1\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(ws.read_u8().await.unwrap());
    }
    assert!(
        header.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&header)
    );
    let mut hello = [0; 5];
    ws.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"hello");
    ws.write_all(b"raw-websocket-data").await.unwrap();
    ws.shutdown().await.unwrap();
    drop(ws);
    let (mut client, connection) = h2_client(addr, &f.ca).await;
    for _ in 0..100 {
        if client.sender.is_extended_connect_protocol_enabled() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(client.sender.is_extended_connect_protocol_enabled());
    let mut req = http::Request::builder()
        .method("CONNECT")
        .uri("https://proxy.example.test/ws//a%2Fb?q=%2F")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-protocol", "first")
        .header("sec-websocket-protocol", "second")
        .header("x-forwarded-port", "12345")
        .header("x-forwarded-for", "spoofed-client")
        .header("proxy-authorization", "Basic private")
        .header("padding-type-request", "1")
        .body(())
        .unwrap();
    req.extensions_mut()
        .insert(::h2::ext::Protocol::from_static("websocket"));
    let (response, mut send) = client.send_request(req, false).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("padding"));
    send.send_data(Bytes::from_static(b"raw-websocket-data"), true)
        .unwrap();
    assert_eq!(body(response.into_body()).await, b"hello");
    let mut q = QClient::new(udp, &f.ca).await;
    for _ in 0..100 {
        if q.h3.as_ref().unwrap().extended_connect_enabled_by_peer() {
            break;
        }
        q.step().await;
    }
    assert!(q.h3.as_ref().unwrap().extended_connect_enabled_by_peer());
    let headers = [
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":authority", b"proxy.example.test"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":path", b"/ws//a%2Fb?q=%2F"),
        quiche::h3::Header::new(b":protocol", b"websocket"),
        quiche::h3::Header::new(b"sec-websocket-version", b"13"),
        quiche::h3::Header::new(b"sec-websocket-protocol", b"first"),
        quiche::h3::Header::new(b"sec-websocket-protocol", b"second"),
        quiche::h3::Header::new(b"x-forwarded-port", b"12345"),
        quiche::h3::Header::new(b"x-forwarded-for", b"spoofed-client"),
        quiche::h3::Header::new(b"proxy-authorization", b"Basic private"),
        quiche::h3::Header::new(b"padding-type-request", b"1"),
    ];
    let id = q.send_headers(&headers, false).unwrap();
    q.send(id, b"raw-websocket-data").await;
    let reply = q.response(id).await;
    assert_eq!(reply.status, 200);
    assert!(!reply.padding);
    assert_eq!(reply.body, b"hello");
    origin.await.unwrap();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    connection.abort();
}

#[tokio::test]
async fn mixed_h1_h2_h3_websocket_admission_holds_through_half_close() {
    use base64::Engine;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let case = crate::acme::lab_support::Case::new("mixed-websocket-admission");
    let mut f = fixture();
    let opened = Arc::new(AtomicUsize::new(0));
    let reject = Arc::new(AtomicBool::new(false));
    let finish = Arc::new(tokio::sync::Semaphore::new(0));
    let (closed, mut half_closed) = tokio::sync::mpsc::channel(8);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = listener.local_addr().unwrap();
    let origin = tokio::spawn({
        let opened = opened.clone();
        let reject = reject.clone();
        let finish = finish.clone();
        async move {
            let mut jobs = tokio::task::JoinSet::new();
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                opened.fetch_add(1, Ordering::SeqCst);
                let reject = reject.clone();
                let finish = finish.clone();
                let closed = closed.clone();
                jobs.spawn(async move {
                let mut head=Vec::new();while !head.ends_with(b"\r\n\r\n"){head.push(socket.read_u8().await.unwrap());}
                if reject.swap(false,Ordering::SeqCst) {socket.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();return;}
                let head=String::from_utf8(head).unwrap();let key=head.lines().find_map(|line|line.split_once(':').filter(|(k,_)|k.eq_ignore_ascii_case("sec-websocket-key")).map(|(_,v)|v.trim())).unwrap();
                let accept=base64::engine::general_purpose::STANDARD.encode(boring::hash::hash(MessageDigest::sha1(),format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes()).unwrap());
                socket.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\nhello").as_bytes()).await.unwrap();
                let mut input=Vec::new();let _=socket.read_to_end(&mut input).await;
                closed.send(()).await.unwrap();
                finish.acquire().await.unwrap().forget();
                let _=socket.write_all(b"tail").await;let _=socket.shutdown().await;
            });
            }
        }
    });
    let config = Arc::get_mut(&mut f.config).unwrap();
    config.listener.h1 = true;
    config.limits.max_streams = 1;
    config.limits.max_connections = 16;
    config.limits.max_total_receive_bytes = 256 * 1024 * 1024;
    config.limits.idle_timeout_secs = 30;
    config.website.upstreams[0].origins = vec![format!("http://{origin_addr}")];
    let network = network(&f, None).await;
    let tcp = network.tcp_addr().unwrap();
    let udp = network.udp_addr().unwrap();
    let app = network.app.clone();
    let _capture = case.capture(&[tcp.port(), udp.port(), origin_addr.port()]);
    let (stop, rx) = watch::channel(false);
    let server = tokio::spawn(network.run(rx));
    async fn h1(
        f: &Fixture,
        tcp: std::net::SocketAddr,
    ) -> (tokio_boring::SslStream<TcpStream>, u16) {
        let mut tls = SslConnector::builder(SslMethod::tls()).unwrap();
        tls.set_ca_file(&f.ca).unwrap();
        tls.set_alpn_protos(b"\x08http/1.1").unwrap();
        let mut stream = tokio_boring::connect(
            tls.build().configure().unwrap(),
            "proxy.example.test",
            TcpStream::connect(tcp).await.unwrap(),
        )
        .await
        .unwrap();
        stream.write_all(b"GET /ws HTTP/1.1\r\nHost: proxy.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(
                tokio::time::timeout(Duration::from_secs(3), stream.read_u8())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        let status = std::str::from_utf8(&head)
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (stream, status)
    }
    fn h2ws() -> http::Request<()> {
        let mut req = http::Request::builder()
            .method("CONNECT")
            .uri("https://proxy.example.test/ws")
            .header("sec-websocket-version", "13")
            .body(())
            .unwrap();
        req.extensions_mut()
            .insert(::h2::ext::Protocol::from_static("websocket"));
        req
    }
    async fn h3ws(q: &mut QClient) -> u64 {
        let until = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            match q.send_headers(
                &[
                    quiche::h3::Header::new(b":method", b"CONNECT"),
                    quiche::h3::Header::new(b":authority", b"proxy.example.test"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":path", b"/ws"),
                    quiche::h3::Header::new(b":protocol", b"websocket"),
                    quiche::h3::Header::new(b"sec-websocket-version", b"13"),
                ],
                false,
            ) {
                Ok(id) => return id,
                Err(quiche::h3::Error::TransportError(quiche::Error::StreamLimit)) => {
                    assert!(
                        std::time::Instant::now() < until,
                        "QUIC stream credit deadline"
                    );
                    Box::pin(q.step()).await;
                }
                Err(error) => panic!("H3 headers failed: {error:?}"),
            }
        }
    }
    let (mut h2, driver) = h2_client(tcp, &f.ca).await;
    let mut q = Box::pin(QClient::new(udp, &f.ca)).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while !h2.sender.is_extended_connect_protocol_enabled() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !q.h3.as_ref().unwrap().extended_connect_enabled_by_peer() {
            Box::pin(q.step()).await;
        }
    })
    .await
    .unwrap();
    let (mut one, status) = h1(&f, tcp).await;
    assert_eq!(status, 101);
    let mut hello = [0; 5];
    one.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, b"hello");
    assert_eq!(app.resources.tunnels.active(), 1);
    let opened_before = opened.load(Ordering::SeqCst);
    let (response, _) = h2.send_request(h2ws(), false).unwrap();
    assert_eq!(response.await.unwrap().status(), 503);
    let id = h3ws(&mut q).await;
    assert_eq!(Box::pin(q.response(id)).await.status, 503);
    let _ = q.conn.stream_shutdown(id, quiche::Shutdown::Write, 0x100);
    Box::pin(q.step()).await;
    assert_eq!(
        opened.load(Ordering::SeqCst),
        opened_before,
        "full admission must prevent origin TCP opens"
    );
    one.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), half_closed.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        app.resources.tunnels.active(),
        1,
        "upload half-close must retain the duplex lease"
    );
    finish.add_permits(1);
    let mut tail = [0; 4];
    one.read_exact(&mut tail).await.unwrap();
    assert_eq!(&tail, b"tail");
    drop(one);
    tokio::time::timeout(Duration::from_secs(3), async {
        while app.resources.tunnels.active() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // H2 holds the same lease and also retains it after END_STREAM.
    let (response, mut send) = h2.send_request(h2ws(), false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    assert_eq!(body.data().await.unwrap().unwrap(), "hello");
    let opened_before = opened.load(Ordering::SeqCst);
    assert_eq!(h1(&f, tcp).await.1, 503);
    let id = h3ws(&mut q).await;
    assert_eq!(Box::pin(q.response(id)).await.status, 503);
    let _ = q.conn.stream_shutdown(id, quiche::Shutdown::Write, 0x100);
    Box::pin(q.step()).await;
    assert_eq!(opened.load(Ordering::SeqCst), opened_before);
    send.send_data(Bytes::new(), true).unwrap();
    tokio::time::timeout(Duration::from_secs(3), half_closed.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(app.resources.tunnels.active(), 1);
    finish.add_permits(1);
    assert_eq!(super::body(body).await, b"tail");
    tokio::time::timeout(Duration::from_secs(3), async {
        while app.resources.tunnels.active() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // A rejected origin handshake must roll back the H1 lease.
    reject.store(true, Ordering::SeqCst);
    assert_eq!(h1(&f, tcp).await.1, 403);
    tokio::time::timeout(Duration::from_secs(3), async {
        while app.resources.tunnels.active() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let id = h3ws(&mut q).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while q.responses.get(&id).is_none_or(|r| r.body.len() < 5) {
            Box::pin(q.step()).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(q.responses[&id].status, 200);
    assert_eq!(app.resources.tunnels.active(), 1);
    let opened_before = opened.load(Ordering::SeqCst);
    assert_eq!(h1(&f, tcp).await.1, 503);
    let (response, _) = h2.send_request(h2ws(), false).unwrap();
    assert_eq!(response.await.unwrap().status(), 503);
    assert_eq!(opened.load(Ordering::SeqCst), opened_before);
    q.conn
        .stream_shutdown(id, quiche::Shutdown::Read, 0x100)
        .unwrap();
    q.conn
        .stream_shutdown(id, quiche::Shutdown::Write, 0x100)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while app.resources.tunnels.active() != 0 {
            Box::pin(q.step()).await;
        }
    })
    .await
    .unwrap();
    finish.add_permits(8);
    driver.abort();
    stop.send(true).unwrap();
    server.await.unwrap().unwrap();
    origin.abort();
}
