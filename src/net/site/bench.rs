//! Measurement of the H3→H2 website bridge, before deciding whether to replace
//! it. Run in release, alone:
//!
//! cargo test --release --locked -p moon-naive --lib site::bench -- --ignored --nocapture --test-threads=1
//!
//! - `bridge`: what an HTTP/3 website request does (`Site::start`: Exchange
//!   channels → in-memory H2 client → Pingora H2 session → proxy → origin).
//! - `h2_hop`: only the in-memory H2 client↔server hop with the bridge's
//!   settings, serving from memory: the part a direct H3 Pingora session
//!   (custom session) would remove.
//! - `origin`: an HTTP/1.1 keep-alive client straight to the same origin, the
//!   floor that every path pays.
use super::*;
use bytes::Bytes;
use std::time::Instant;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const BLOCK: usize = 64 * 1024;

fn cpu_seconds() -> f64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    let ticks = fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
    // CLK_TCK is 100 on Linux x86_64.
    ticks as f64 / 100.0
}

/// HTTP/1.1 keep-alive origin: `GET /<bytes>` answers with that many bytes.
async fn origin() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let block = Bytes::from(vec![b'x'; BLOCK]);
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.set_nodelay(true).unwrap();
            let block = block.clone();
            tokio::spawn(async move {
                let mut buffer = Vec::with_capacity(4096);
                loop {
                    let head_end = loop {
                        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                            break end + 4;
                        }
                        let mut chunk = [0; 4096];
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
                    buffer.drain(..head_end);
                    let path = head.split_whitespace().nth(1).unwrap_or("/0");
                    let size: usize = path
                        .rsplit('/')
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {size}\r\ncontent-type: application/octet-stream\r\n\r\n"
                    );
                    if socket.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                    let mut left = size;
                    while left > 0 {
                        let n = left.min(BLOCK);
                        if socket.write_all(&block[..n]).await.is_err() {
                            return;
                        }
                        left -= n;
                    }
                }
            });
        }
    });
    address
}

fn site(origin: std::net::SocketAddr) -> Arc<Site> {
    let config = Config::parse(
        &include_str!("../../../config.example.toml")
            .replace("http://127.0.0.1:8080", &format!("http://{origin}")),
    )
    .unwrap();
    let tunnels = moon_naive_core::policy::Budget::new(config.limits.max_streams).unwrap();
    Arc::new(Site::load(&config, tunnels).unwrap())
}

fn head(size: usize) -> Head {
    Head {
        binding: None,
        client_ip: Some("127.0.0.1".parse().unwrap()),
        method: "GET".into(),
        authority: "proxy.example.dev".into(),
        scheme: Some("https".into()),
        path: Some(format!("/bench/{size}")),
        protocol: None,
        headers: vec![("accept-encoding".into(), b"identity".to_vec())],
    }
}

/// One website request through the bridge, as `h3.rs` drives it.
async fn bridge_get(site: &Arc<Site>, size: usize) -> usize {
    let wake = Arc::new(Notify::new());
    let mut exchange = site.start(head(size), true, wake);
    drop(exchange.input);
    let mut received = 0;
    while let Some(task) = exchange.output.recv().await {
        match task {
            HttpTask::Header(header, end) => {
                assert_eq!(header.status.as_u16(), 200);
                if end {
                    break;
                }
            }
            HttpTask::Body(Some(bytes), _) => received += bytes.len(),
            HttpTask::Body(None, true) | HttpTask::Done | HttpTask::Trailer(_) => break,
            HttpTask::Failed(error) => panic!("{error}"),
            _ => {}
        }
    }
    exchange.completion.await.unwrap().unwrap();
    received
}

/// The bridge's in-memory H2 hop alone, serving from memory.
async fn h2_hop() -> h2::client::SendRequest<Bytes> {
    let (client, server) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut builder = h2::server::Builder::new();
        builder
            .max_concurrent_streams(1024)
            .initial_window_size(64 * 1024)
            .initial_connection_window_size(1024 * 1024)
            .max_send_buffer_size(crate::net::CHUNK * 2);
        let mut connection = builder.handshake(server).await.unwrap();
        let block = Bytes::from(vec![b'x'; BLOCK]);
        while let Some(Ok((request, mut respond))) = connection.accept().await {
            let size: usize = request
                .uri()
                .path()
                .rsplit('/')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            let block = block.clone();
            tokio::spawn(async move {
                let response = http::Response::builder().status(200).body(()).unwrap();
                let mut body = respond.send_response(response, size == 0).unwrap();
                let mut left = size;
                while left > 0 {
                    body.reserve_capacity(left.min(BLOCK));
                    let Some(Ok(capacity)) =
                        std::future::poll_fn(|cx| body.poll_capacity(cx)).await
                    else {
                        return;
                    };
                    let n = capacity.min(left);
                    left -= n;
                    body.send_data(block.slice(..n), left == 0).unwrap();
                }
            });
        }
    });
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(64 * 1024)
        .initial_connection_window_size(1024 * 1024)
        .max_send_buffer_size(crate::net::CHUNK * 2);
    let (sender, connection) = builder.handshake(client).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
}

async fn hop_get(sender: &h2::client::SendRequest<Bytes>, size: usize) -> usize {
    let request = http::Request::builder()
        .uri(format!("https://bench/{size}"))
        .body(())
        .unwrap();
    let mut sender = sender.clone().ready().await.unwrap();
    let (response, _) = sender.send_request(request, true).unwrap();
    let mut body = response.await.unwrap().into_body();
    let mut received = 0;
    while let Some(bytes) = body.data().await {
        let bytes = bytes.unwrap();
        received += bytes.len();
        body.flow_control().release_capacity(bytes.len()).unwrap();
    }
    received
}

async fn origin_get(stream: &mut TcpStream, size: usize) -> usize {
    stream
        .write_all(format!("GET /bench/{size} HTTP/1.1\r\nhost: o\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    let mut left = size;
    let mut buffer = vec![0; BLOCK];
    while left > 0 {
        let n = stream.read(&mut buffer[..left.min(BLOCK)]).await.unwrap();
        assert!(n > 0);
        left -= n;
    }
    size
}

#[derive(Clone, Copy)]
enum Path {
    Bridge,
    Hop,
    Origin,
}

async fn run(path: Path, concurrency: usize, requests: usize, size: usize) -> (f64, f64, Vec<f64>) {
    let address = origin().await;
    let site = site(address);
    let hop = h2_hop().await;
    // Warm up connections and pools.
    match path {
        Path::Bridge => {
            bridge_get(&site, 1024).await;
        }
        Path::Hop => {
            hop_get(&hop, 1024).await;
        }
        Path::Origin => {}
    }
    let cpu = cpu_seconds();
    let start = Instant::now();
    let mut jobs = tokio::task::JoinSet::new();
    for _ in 0..concurrency {
        let site = site.clone();
        let hop = hop.clone();
        jobs.spawn(async move {
            let mut latencies = Vec::new();
            let mut stream = match path {
                Path::Origin => {
                    let s = TcpStream::connect(address).await.unwrap();
                    s.set_nodelay(true).unwrap();
                    Some(s)
                }
                _ => None,
            };
            for _ in 0..requests {
                let began = Instant::now();
                let n = match path {
                    Path::Bridge => bridge_get(&site, size).await,
                    Path::Hop => hop_get(&hop, size).await,
                    Path::Origin => origin_get(stream.as_mut().unwrap(), size).await,
                };
                assert_eq!(n, size);
                latencies.push(began.elapsed().as_secs_f64() * 1e3);
            }
            latencies
        });
    }
    let mut latencies = Vec::new();
    while let Some(result) = jobs.join_next().await {
        latencies.extend(result.unwrap());
    }
    let elapsed = start.elapsed().as_secs_f64();
    let cpu = cpu_seconds() - cpu;
    site.stop_bridge();
    latencies.sort_by(f64::total_cmp);
    (elapsed, cpu, latencies)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "release benchmark of the H3→H2 website bridge; run with --ignored --nocapture --test-threads=1"]
async fn benchmark_h3_website_bridge() {
    for (label, path) in [
        ("origin", Path::Origin),
        ("h2_hop", Path::Hop),
        ("bridge", Path::Bridge),
    ] {
        for (concurrency, requests, size) in [
            (1, 8, 32 << 20),
            (8, 4, 16 << 20),
            (1, 2000, 1024),
            (32, 200, 1024),
        ] {
            let mut best: Option<(f64, f64, Vec<f64>)> = None;
            for _ in 0..3 {
                let result = run(path, concurrency, requests, size).await;
                if best.as_ref().is_none_or(|b| result.0 < b.0) {
                    best = Some(result);
                }
            }
            let (elapsed, cpu, latencies) = best.unwrap();
            let bytes = (concurrency * requests * size) as f64;
            let p = |q: f64| latencies[((latencies.len() - 1) as f64 * q) as usize];
            println!(
                "WEBSITE_BENCH path={label} concurrency={concurrency} requests={} size={size} seconds={elapsed:.3} mbit_s={:.0} req_s={:.0} cpu_ms_per_mib={:.2} cpu_us_per_req={:.1} p50_ms={:.3} p99_ms={:.3}",
                concurrency * requests,
                bytes * 8.0 / elapsed / 1e6,
                (concurrency * requests) as f64 / elapsed,
                cpu * 1e3 / (bytes / (1 << 20) as f64),
                cpu * 1e6 / (concurrency * requests) as f64,
                p(0.5),
                p(0.99),
            );
        }
    }
}
