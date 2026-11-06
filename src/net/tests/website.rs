use super::*;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use moon_naive_core::website::{Route, Upstream};
use std::{convert::Infallible, io::Read, sync::Mutex};

type TestBody = UnsyncBoxBody<Bytes, std::io::Error>;
fn full(bytes: impl Into<Bytes>) -> TestBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}
fn upstream(config: &mut Config, address: std::net::SocketAddr) {
    config.website.upstreams.insert(
        0,
        Upstream {
            name: "app".into(),
            origins: vec![format!("http://{address}")],
            tls_server_name: None,
            host_header: None,
            ca_file: None,
            http2: true,
        },
    );
    config.website.routes.push(Route {
        path_prefix: "/api/".into(),
        upstream: "app".into(),
        strip_prefix: true,
    });
}
fn request(method: &str, path: &str, headers: &[(&str, &str)]) -> http::Request<()> {
    let mut request = http::Request::builder()
        .method(method)
        .uri(format!("https://proxy.example.test{path}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(()).unwrap()
}
fn qrequest(q: &mut QClient, method: &str, path: &str, headers: &[(&str, &str)], fin: bool) -> u64 {
    let mut fields = vec![
        quiche::h3::Header::new(b":method", method.as_bytes()),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"proxy.example.test"),
        quiche::h3::Header::new(b":path", path.as_bytes()),
    ];
    fields.extend(
        headers
            .iter()
            .map(|(n, v)| quiche::h3::Header::new(n.as_bytes(), v.as_bytes())),
    );
    q.send_headers(&fields, fin).unwrap()
}
fn gunzip(bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .read_to_end(&mut result)
        .unwrap();
    result
}

#[tokio::test]
async fn single_origin_config_routes_h2_h3_with_origin_host_and_original_path() {
    let mut f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let parsed = Config::parse(
        &include_str!("../../../config.example.toml")
            .replace("http://127.0.0.1:8080", &format!("http://{address}")),
    )
    .unwrap();
    Arc::get_mut(&mut f.config).unwrap().website = parsed.website;
    let origin = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                assert!(head.len() < 32768);
                head.push(socket.read_u8().await.unwrap());
            }
            let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
            assert!(head.starts_with("get /a%2fb?q=%2f http/1.1\r\n"));
            assert!(head.contains(&format!("\r\nhost: {address}\r\n")), "{head}");
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin",
                )
                .await
                .unwrap();
        }
    });
    let server = network(&f, None).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut client, driver) = h2_client(tcp, &f.ca).await;
    let (reply, _) = client
        .send_request(request("GET", "/a%2Fb?q=%2F", &[]), true)
        .unwrap();
    let reply = reply.await.unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(body(reply.into_body()).await, b"origin".as_slice());
    let mut q = QClient::new(udp, &f.ca).await;
    let id = qrequest(&mut q, "GET", "/a%2Fb?q=%2F", &[], true);
    let reply = q.response(id).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, b"origin");
    origin.await.unwrap();
    drop(client);
    driver.abort();
    drop(q);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn website_pingora_streaming_proxy_reuses_pool_across_h2_h3_and_sanitizes_headers() {
    let mut f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    upstream(Arc::get_mut(&mut f.config).unwrap(), address);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let observed = seen.clone();
    let connections = Arc::new(AtomicUsize::new(0));
    let count = connections.clone();
    let origin = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            count.fetch_add(1, Ordering::Relaxed);
            let seen = observed.clone();
            tasks.spawn(async move {
                let service =
                    hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                        let seen = seen.clone();
                        async move {
                            let path = req.uri().to_string();
                            seen.lock()
                                .unwrap()
                                .push((path.clone(), req.headers().clone()));
                            let mut response = http::Response::builder()
                                .header("x-origin-path", &path)
                                .header(
                                    "content-type",
                                    if path == "/sse" {
                                        "text/event-stream"
                                    } else {
                                        "text/plain"
                                    },
                                )
                                .header("connection", "x-private")
                                .header("x-private", "remove-me")
                                .header("alt-svc", "h3=\":8443\"")
                                .header("padding", "remove-me")
                                .header("set-cookie", "a=1")
                                .header("set-cookie", "b=2");
                            let body = match path.as_str() {
                                "/large" => full("proxy compressible content\n".repeat(5000)),
                                "/sse" => full("data: normal event\n\n".repeat(500)),
                                "/no-transform" => {
                                    response =
                                        response.header("cache-control", "public, no-transform");
                                    full("unchanged representation\n".repeat(500))
                                }
                                _ => req
                                    .into_body()
                                    .map_err(std::io::Error::other)
                                    .boxed_unsync(),
                            };
                            Ok::<_, Infallible>(response.body(body).unwrap())
                        }
                    });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let server = network(&f, None).await;
    let stats = server.app.site.stats().clone();
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let naive_stats = server.stats.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut client, driver) = h2_client(tcp, &f.ca).await;
    let untrusted = [
        ("proxy-authorization", "Basic unrelated"),
        ("padding", "~"),
        ("x-forwarded-for", "1.2.3.4"),
        ("forwarded", "for=evil"),
        ("x-forwarded-proto", "http"),
        ("x-forwarded-port", "1"),
        ("x-real-ip", "evil"),
    ];
    let (reply, mut upload) = client
        .send_request(request("POST", "/api/a%2Fb?q=%2F", &untrusted), false)
        .unwrap();
    let bytes = Bytes::from(vec![b'p'; 512 * 1024]);
    let expected = bytes.clone();
    let upload = tokio::spawn(async move {
        v2_send(&mut upload, bytes, true).await;
    });
    let reply = reply.await.unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(reply.headers()["x-origin-path"], "/a%2Fb?q=%2F");
    assert_eq!(reply.headers().get_all("set-cookie").iter().count(), 2);
    for header in ["connection", "x-private", "padding"] {
        assert!(!reply.headers().contains_key(header), "{header}");
    }
    assert!(
        reply.headers()["alt-svc"]
            .to_str()
            .unwrap()
            .starts_with("h3=\":")
    );
    assert_eq!(body(reply.into_body()).await, expected);
    upload.await.unwrap();
    let mut q = QClient::new(udp, &f.ca).await;
    let id = qrequest(&mut q, "POST", "/api//echo", &untrusted, false);
    let bytes = vec![b'q'; 300_000];
    q.send(id, &bytes).await;
    let reply = q.response(id).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, bytes);
    assert_eq!(reply.headers["x-origin-path"], "//echo");
    assert!(
        stats.upstream_reuses.load(Ordering::Relaxed) >= 1,
        "the H3 request should reuse the H2 request's origin pool"
    );
    let id = qrequest(
        &mut q,
        "GET",
        "/api/large",
        &[("accept-encoding", "gzip")],
        true,
    );
    let reply = q.response(id).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.headers["content-encoding"], "gzip");
    assert_eq!(
        gunzip(&reply.body),
        "proxy compressible content\n".repeat(5000).as_bytes()
    );
    for (offer, compressed) in [
        ("br, zstd, gzip", true),
        ("gzip;q=0", false),
        ("br;q=1, gzip;q=0.5", true),
        ("identity;q=1, gzip;q=0.5", false),
        ("gzip;q=2", false),
    ] {
        let id = qrequest(
            &mut q,
            "GET",
            "/api/large",
            &[("accept-encoding", offer)],
            true,
        );
        let reply = q.response(id).await;
        assert_eq!(reply.status, 200);
        assert_eq!(
            reply.headers.contains_key("content-encoding"),
            compressed,
            "{offer}"
        );
        let data = if compressed {
            gunzip(&reply.body)
        } else {
            reply.body.to_vec()
        };
        assert_eq!(data, "proxy compressible content\n".repeat(5000).as_bytes());
    }
    // Honor request-side no-transform, including multiple fields and
    // case-insensitive tokens, as well as the origin response directive.
    let protected = [
        ("accept-encoding", "gzip"),
        ("cache-control", "max-age=0"),
        ("cache-control", "No-Transform, no-cache"),
    ];
    let (reply, _) = client
        .send_request(request("GET", "/api/large", &protected), true)
        .unwrap();
    let reply = reply.await.unwrap();
    assert_eq!(reply.status(), 200);
    assert!(
        !reply.headers().contains_key("content-encoding"),
        "request no-transform ignored on H2"
    );
    assert_eq!(
        body(reply.into_body()).await,
        "proxy compressible content\n".repeat(5000).as_bytes()
    );
    let id = qrequest(&mut q, "GET", "/api/large", &protected, true);
    let reply = q.response(id).await;
    assert_eq!(reply.status, 200);
    assert!(
        !reply.headers.contains_key("content-encoding"),
        "request no-transform ignored on H3"
    );
    assert_eq!(
        reply.body,
        "proxy compressible content\n".repeat(5000).as_bytes()
    );
    for path in ["/api/sse", "/api/no-transform"] {
        let id = qrequest(&mut q, "GET", path, &[("accept-encoding", "gzip")], true);
        let reply = q.response(id).await;
        assert_eq!(reply.status, 200);
        assert!(!reply.headers.contains_key("content-encoding"), "{path}");
    }
    for (_, headers) in seen.lock().unwrap().iter() {
        for header in [
            "proxy-authorization",
            "padding",
            "forwarded",
            "x-real-ip",
            "x-forwarded-port",
        ] {
            assert!(!headers.contains_key(header), "{header}");
        }
        assert_eq!(headers["x-forwarded-for"], "127.0.0.1");
        assert_eq!(headers["x-forwarded-proto"], "https");
        assert_eq!(headers["x-forwarded-host"], "proxy.example.test");
    }
    // Completion and idle-pool return can race with the next downstream request.
    assert!(connections.load(Ordering::Relaxed) <= 2);
    assert!(stats.upstream_reuses.load(Ordering::Relaxed) >= 3);
    assert_eq!(naive_stats.dials.load(Ordering::Relaxed), 0);
    driver.abort();
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
    origin.abort();
}

#[tokio::test]
async fn website_proxy_failover_body_limit_and_fixed_origin_routing() {
    let mut f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed = reservation.local_addr().unwrap();
    drop(reservation);
    let c = Arc::get_mut(&mut f.config).unwrap();
    upstream(c, closed);
    c.website.upstreams[0]
        .origins
        .push(format!("http://{address}"));
    c.website.routes.retain(|route| route.upstream != "fixture");
    c.website.max_request_body_bytes = 100;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let origin = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let count = count.clone();
            tasks.spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(stream),
                        hyper::service::service_fn(
                            move |req: http::Request<hyper::body::Incoming>| {
                                count.fetch_add(1, Ordering::Relaxed);
                                async move {
                                    let _ = req.into_body().collect().await;
                                    Ok::<_, Infallible>(http::Response::new(Full::new(
                                        Bytes::from_static(b"healthy"),
                                    )))
                                }
                            },
                        ),
                    )
                    .await;
            });
        }
    });
    let server = network(&f, None).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let stats = server.app.site.stats().clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut h2, driver) = h2_client(tcp, &f.ca).await;
    let (reply, _) = h2.send_request(request("GET", "/api/", &[]), true).unwrap();
    let reply = reply.await.unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(body(reply.into_body()).await, b"healthy");
    assert_eq!(stats.upstream_failures.load(Ordering::Relaxed), 1);
    let (reply, _) = h2
        .send_request(
            request("POST", "/api/", &[("content-length", "101")]),
            false,
        )
        .unwrap();
    assert_eq!(reply.await.unwrap().status(), 413);
    let mut q = QClient::new(udp, &f.ca).await;
    let id = qrequest(&mut q, "POST", "/api/", &[("content-length", "101")], false);
    assert_eq!(q.response(id).await.status, 413);
    let id = q.request("GET", "evil.example.test", Some("/api/"), None, false, true);
    assert_eq!(q.response(id).await.status, 404);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let (reply, mut upload) = h2
        .send_request(request("POST", "/api/", &[]), false)
        .unwrap();
    v2_send(&mut upload, Bytes::from(vec![b'x'; 101]), true).await;
    assert_eq!(reply.await.unwrap().status(), 413);
    let id = qrequest(&mut q, "POST", "/api/", &[], false);
    q.send(id, &[b'x'; 101]).await;
    assert_eq!(q.response(id).await.status, 413);
    let id = qrequest(&mut q, "GET", "/", &[], true);
    assert_eq!(q.response(id).await.status, 404);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        3,
        "POST bodies must not be replayed"
    );
    driver.abort();
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
    origin.abort();
}

#[tokio::test]
async fn website_https_h2_origin_verifies_identity_reuses_connections_and_forwards_trailers() {
    let mut f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let generation = tls::Slot::load(&f.config).unwrap().current().unwrap();
    let c = Arc::get_mut(&mut f.config).unwrap();
    upstream(c, address);
    c.website.upstreams[0].origins = vec![format!("https://{address}")];
    c.website.upstreams[0].tls_server_name = Some("proxy.example.test".into());
    c.website.upstreams[0].host_header = Some("origin.example.test".into());
    c.website.upstreams[0].ca_file = Some(f.ca.clone());
    let mut wrong = c.website.upstreams[0].clone();
    wrong.name = "wrong-name".into();
    wrong.tls_server_name = Some("wrong.example.test".into());
    c.website.upstreams.push(wrong);
    c.website.routes.push(Route {
        path_prefix: "/bad/".into(),
        upstream: "wrong-name".into(),
        strip_prefix: true,
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let origin = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let generation = generation.clone();
            let count = count.clone();
            tasks.spawn(async move {
                let Ok(stream) = pingora_core::protocols::tls::server::handshake(
                    &generation.h2,
                    pingora_core::protocols::l4::stream::Stream::from(socket),
                )
                .await
                else {
                    return;
                };
                let Ok(mut h2) = ::h2::server::handshake(stream).await else {
                    return;
                };
                let mut requests = tokio::task::JoinSet::new();
                while let Some(Ok((request, mut response))) = h2.accept().await {
                    let count = count.clone();
                    requests.spawn(async move {
                        count.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(request.version(), http::Version::HTTP_2);
                        assert_eq!(
                            request.uri().authority().unwrap().as_str(),
                            "origin.example.test"
                        );
                        if request.headers().contains_key("expect") {
                            response
                                .send_informational(
                                    http::Response::builder().status(100).body(()).unwrap(),
                                )
                                .unwrap();
                        }
                        response
                            .send_informational(
                                http::Response::builder()
                                    .status(103)
                                    .header("link", "</style.css>; rel=preload; as=style")
                                    .body(())
                                    .unwrap(),
                            )
                            .unwrap();
                        let grpc = request
                            .headers()
                            .get("content-type")
                            .is_some_and(|v| v.as_bytes().starts_with(b"application/grpc"));
                        let mut incoming = request.into_body();
                        let bytes = body_data_with_trailers(&mut incoming).await;
                        let request_trailers = incoming.trailers().await.unwrap();
                        let request_checksum = request_trailers
                            .as_ref()
                            .and_then(|h| h.get("x-upload-checksum"))
                            .cloned();
                        let mut header = http::Response::builder().header(
                            "content-type",
                            if grpc {
                                "application/grpc"
                            } else {
                                "application/octet-stream"
                            },
                        );
                        if let Some(value) = request_checksum {
                            header = header.header("x-upload-checksum", value);
                        }
                        let mut output = response
                            .send_response(header.body(()).unwrap(), false)
                            .unwrap();
                        v2_send(
                            &mut output,
                            if bytes.is_empty() {
                                Bytes::from_static(b"verified h2 origin")
                            } else {
                                Bytes::from(bytes)
                            },
                            false,
                        )
                        .await;
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("x-checksum", http::HeaderValue::from_static("complete"));
                        if grpc {
                            trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                        }
                        output.send_trailers(trailers).unwrap();
                    });
                }
            });
        }
    });
    let server = network(&f, None).await;
    let stats = server.app.site.stats().clone();
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut client, driver) = h2_client(tcp, &f.ca).await;
    let (mut reply, _) = client
        .send_request(request("GET", "/api/", &[]), true)
        .unwrap();
    let hint = std::future::poll_fn(|cx| reply.poll_informational(cx))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(hint.status(), 103);
    let reply = reply.await.unwrap();
    assert_eq!(reply.status(), 200);
    let mut data = reply.into_body();
    assert_eq!(
        body_data_with_trailers(&mut data).await,
        b"verified h2 origin"
    );
    assert_eq!(
        data.trailers().await.unwrap().unwrap()["x-checksum"],
        "complete"
    );
    // A client that waits for 100 must not deadlock before sending its body.
    let (mut response, mut send) = client
        .send_request(
            request(
                "POST",
                "/api/",
                &[
                    ("expect", "100-continue"),
                    ("content-type", "application/grpc"),
                    ("te", "trailers"),
                    ("accept-encoding", "gzip"),
                ],
            ),
            false,
        )
        .unwrap();
    for code in [100, 103] {
        let info = tokio::time::timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| response.poll_informational(cx)),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(info.status(), code);
    }
    let grpc_frame = Bytes::from_static(b"\0\0\0\0\x04ping");
    send.send_data(grpc_frame.clone(), true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.headers()["content-type"], "application/grpc");
    assert!(!response.headers().contains_key("content-encoding"));
    let mut data = response.into_body();
    assert_eq!(body_data_with_trailers(&mut data).await, grpc_frame);
    assert_eq!(data.trailers().await.unwrap().unwrap()["grpc-status"], "0");
    let mut q = QClient::new(udp, &f.ca).await;
    let id = qrequest(&mut q, "GET", "/api/", &[], true);
    let reply = q.response(id).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, b"verified h2 origin");
    assert_eq!(reply.headers["x-checksum"], "complete");
    assert!(reply.headers.contains_key("link"));
    let id = qrequest(&mut q, "POST", "/api/", &[], false);
    q.send(id, b"streamed upload").await;
    let reply = q.response(id).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, b"streamed upload");
    let id = qrequest(&mut q, "POST", "/api/", &[], false);
    let h3 = q.h3.as_mut().unwrap();
    assert_eq!(
        h3.send_body(&mut q.conn, id, b"with trailers", false)
            .unwrap(),
        13
    );
    h3.send_additional_headers(
        &mut q.conn,
        id,
        &[quiche::h3::Header::new(b"x-upload-checksum", b"present")],
        true,
        true,
    )
    .unwrap();
    let reply = q.response(id).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, b"with trailers");
    assert_eq!(reply.headers["x-upload-checksum"], "present");
    let before = calls.load(Ordering::Relaxed);
    let id = qrequest(&mut q, "GET", "/bad/", &[], true);
    assert_eq!(q.response(id).await.status, 502);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        before,
        "wrong certificate identity must fail before HTTP"
    );
    assert!(stats.upstream_reuses.load(Ordering::Relaxed) >= 2);
    driver.abort();
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
    origin.abort();
}
async fn body_data_with_trailers(body: &mut ::h2::RecvStream) -> Vec<u8> {
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
async fn website_resets_cancel_waiting_origins_and_release_request_quotas() {
    let mut f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    upstream(
        Arc::get_mut(&mut f.config).unwrap(),
        listener.local_addr().unwrap(),
    );
    let active = Arc::new(AtomicUsize::new(0));
    let count = active.clone();
    let origin = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let count = count.clone();
            tasks.spawn(async move {
                let mut header = Vec::new();
                let mut byte = [0];
                while !header.ends_with(b"\r\n\r\n") {
                    if socket.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    header.push(byte[0]);
                }
                count.fetch_add(1, Ordering::Relaxed);
                while socket.read(&mut byte).await.unwrap_or(0) > 0 {}
                count.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
    let server = network(&f, None).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let app = server.app.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let (mut h2, driver) = h2_client(tcp, &f.ca).await;
    let (reply, mut upload) = h2
        .send_request(request("GET", "/api/slow", &[]), true)
        .unwrap();
    let mut q = QClient::new(udp, &f.ca).await;
    let id = qrequest(&mut q, "GET", "/api/slow", &[], true);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while active.load(Ordering::Relaxed) < 2 {
        assert!(std::time::Instant::now() < deadline);
        q.step().await;
    }
    upload.send_reset(::h2::Reason::CANCEL);
    drop(reply);
    q.conn
        .stream_shutdown(id, quiche::Shutdown::Read, 0x10c)
        .unwrap();
    q.conn
        .stream_shutdown(id, quiche::Shutdown::Write, 0x10c)
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while active.load(Ordering::Relaxed) > 0 || app.resources.requests.active() > 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "cancelled website origin or request quota leaked"
        );
        q.step().await;
    }
    assert_eq!(app.stats.streams.load(Ordering::Relaxed), 0);
    driver.abort();
    let _ = stop.send(true);
    task.await.unwrap().unwrap();
    origin.abort();
}

/// Fixed mirror objects retain Content-Length; transforms and unknown-length
/// streams still use valid H1 framing on the same downstream/upstream connection.
#[tokio::test]
async fn h1_mirror_framing_compression_ranges_and_keepalive() {
    let mut f = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = Arc::get_mut(&mut f.config).unwrap();
    config.listener.h1 = true;
    upstream(config, listener.local_addr().unwrap());
    let payload = "mirror representation\n".repeat(4096);
    let expected = payload.clone();
    let origin = tokio::spawn(async move {
        let (mut io, _) = listener.accept().await.unwrap();
        for path in [
            "fixed", "gzip", "range", "stream", "head", "cached", "empty", "fixed",
        ] {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(io.read_u8().await.unwrap());
                assert!(request.len() < 8192);
            }
            assert!(
                std::str::from_utf8(&request)
                    .unwrap()
                    .contains(&format!(" /{path} HTTP/1.1"))
            );
            let response = match path {
                "range" => "HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 0-3/10\r\nContent-Type: text/plain\r\n\r\ndata".into(),
                "stream" => "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n".into(),
                "head" => "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n".into(),
                "cached" => "HTTP/1.1 304 Not Modified\r\nContent-Length: 1234\r\nETag: \"mirror-v1\"\r\n\r\n".into(),
                "empty" => "HTTP/1.1 204 No Content\r\n\r\n".into(),
                _ => format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nETag: \"mirror-v1\"\r\n\r\n{payload}", payload.len()),
            };
            io.write_all(response.as_bytes()).await.unwrap();
        }
        // A single accepted origin TCP connection served the entire sequence.
    });
    let server = network(&f, None).await;
    let address = server.tcp_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file(&f.ca).unwrap();
    connector.set_alpn_protos(b"\x08http/1.1").unwrap();
    let tls = tokio_boring::connect(
        connector.build().configure().unwrap(),
        "proxy.example.test",
        TcpStream::connect(address).await.unwrap(),
    )
    .await
    .unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .unwrap();
    let driver = tokio::spawn(connection);
    tokio::time::timeout(Duration::from_secs(10), async {
        for path in [
            "fixed", "gzip", "range", "stream", "head", "cached", "empty", "fixed",
        ] {
            let mut req = http::Request::builder()
                .method(if path == "head" { "HEAD" } else { "GET" })
                .uri(format!("/api/{path}"))
                .header("host", "proxy.example.test");
            if matches!(path, "gzip" | "range") {
                req = req.header("accept-encoding", "gzip");
            }
            if path == "range" {
                req = req.header("range", "bytes=0-3");
            }
            let reply = sender
                .send_request(req.body(Full::new(Bytes::new())).unwrap())
                .await
                .unwrap();
            let headers = reply.headers();
            if matches!(path, "gzip" | "stream") {
                assert!(
                    !headers.contains_key("content-length"),
                    "{path}: {headers:?}"
                );
                assert_eq!(headers["transfer-encoding"], "chunked");
            } else {
                assert!(
                    !headers.contains_key("transfer-encoding"),
                    "{path}: {headers:?}"
                );
                if path != "empty" {
                    assert!(headers.contains_key("content-length"), "{path}");
                }
            }
            assert_eq!(headers.contains_key("content-encoding"), path == "gzip");
            if path == "range" {
                assert_eq!(reply.status(), 206);
                assert_eq!(headers["content-range"], "bytes 0-3/10");
            }
            let body = reply.into_body().collect().await.unwrap().to_bytes();
            match path {
                "fixed" => assert_eq!(body, expected),
                "gzip" => assert_eq!(gunzip(&body), expected.as_bytes()),
                "range" => assert_eq!(body, "data"),
                "stream" => assert_eq!(body, "hello"),
                _ => assert!(body.is_empty()),
            }
        }
        origin.await.unwrap();
    })
    .await
    .unwrap();
    drop(sender);
    driver.abort();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}
