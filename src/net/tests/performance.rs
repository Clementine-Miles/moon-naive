//! Explicit slow benchmark: real QUIC over a bounded deterministic UDP relay.
use super::*;
use std::collections::VecDeque;

async fn relay(
    server: std::net::SocketAddr,
    delay: Duration,
    loss_every: usize,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut client = None;
        let mut queue = VecDeque::new();
        let mut count = 0usize;
        let mut buf = [0; 65535];
        loop {
            let next = queue
                .front()
                .map(|(at, _, _): &(tokio::time::Instant, Vec<u8>, std::net::SocketAddr)| *at)
                .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(60));
            tokio::select! {
                result=socket.recv_from(&mut buf)=>{
                    let (n,from)=result.unwrap();let to=if from==server {client.unwrap()}else{client=Some(from);server};
                    count+=1;if loss_every!=0 && count.is_multiple_of(loss_every){continue;}
                    assert!(queue.len()<4096,"relay fixture queue bound exceeded");
                    queue.push_back((tokio::time::Instant::now()+delay,buf[..n].to_vec(),to));
                },
                _=tokio::time::sleep_until(next),if !queue.is_empty()=>{
                    let (_,data,to)=queue.pop_front().unwrap();socket.send_to(&data,to).await.unwrap();
                }
            }
        }
    });
    (address, task)
}
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let f: Vec<_> = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
}
#[tokio::test]
#[ignore = "explicit RTT/loss benchmark; run release with --ignored --nocapture --test-threads=1"]
async fn benchmark_h3_receive_windows() {
    let tick_hz: String = String::from_utf8(
        std::process::Command::new("getconf")
            .arg("CLK_TCK")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let tick_hz: f64 = tick_hz.trim().parse().unwrap();
    for cap in [100, 32] {
        for (rtt_ms, loss_every) in [(0, 0), (20, 0), (80, 100)] {
            for streams in [1, 8] {
                let mut f = fixture();
                let config = Arc::get_mut(&mut f.config).unwrap();
                config.limits.max_streams = cap;
                config.limits.idle_timeout_secs = 60;
                config.traffic.sparse_padding = false;
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let server = network(&f, Some(listener.local_addr().unwrap())).await;
                let app = server.app.clone();
                let original = app.resources.receive.available_permits();
                let window = app.profile.h3_stream_window();
                let (address, relay) = relay(
                    server.udp_addr().unwrap(),
                    Duration::from_millis(rtt_ms / 2),
                    loss_every,
                )
                .await;
                let (stop, rx) = watch::channel(false);
                let driver = tokio::spawn(server.run(rx));
                const SIZE: usize = 128 * 1024;
                let origin = tokio::spawn(async move {
                    let mut jobs = tokio::task::JoinSet::new();
                    for _ in 0..streams {
                        let (mut s, _) = listener.accept().await.unwrap();
                        jobs.spawn(async move {
                            let mut data = Vec::new();
                            s.read_to_end(&mut data).await.unwrap();
                            assert_eq!(data, vec![b'x'; SIZE]);
                            s.write_all(b"ok").await.unwrap();
                            s.shutdown().await.unwrap();
                        });
                    }
                    while let Some(r) = jobs.join_next().await {
                        r.unwrap();
                    }
                });
                let mut q = QClient::new(address, &f.ca).await;
                let ids: Vec<_> = (0..streams)
                    .map(|_| {
                        q.request(
                            "CONNECT",
                            "example.org:443",
                            None,
                            Some(&auth()),
                            false,
                            false,
                        )
                    })
                    .collect();
                let admission = std::time::Instant::now();
                while ids
                    .iter()
                    .any(|id| q.responses.get(id).is_none_or(|r| r.status != 200))
                {
                    assert!(admission.elapsed() < Duration::from_secs(10));
                    q.step().await;
                }
                let mut encoder = moon_naive_core::codec::Encoder::default();
                let mut wire = Vec::new();
                for part in vec![b'x'; SIZE].chunks(8192) {
                    wire.extend(encoder.encode(part, 0).unwrap());
                }
                let mut offsets = vec![0; streams];
                let mut finished = vec![false; streams];
                let cpu = cpu_ticks();
                let start = std::time::Instant::now();
                let iterations = app.stats.h3_driver_iterations.load(Ordering::Relaxed);
                while finished.iter().any(|v| !*v) {
                    assert!(
                        start.elapsed() < Duration::from_secs(45),
                        "benchmark transfer deadline"
                    );
                    for (i, id) in ids.iter().enumerate() {
                        if finished[i] {
                            continue;
                        }
                        match q.h3.as_mut().unwrap().send_body(
                            &mut q.conn,
                            *id,
                            &wire[offsets[i]..],
                            true,
                        ) {
                            Ok(n) => {
                                offsets[i] += n;
                                finished[i] = offsets[i] == wire.len();
                            }
                            Err(quiche::h3::Error::Done) => {}
                            Err(e) => panic!("{e:?}"),
                        }
                    }
                    q.step().await;
                }
                for id in ids {
                    q.io_timeout = Duration::from_secs(15);
                    let r = q.response(id).await;
                    assert_eq!(
                        moon_naive_core::codec::Decoder::default()
                            .feed(&r.body)
                            .unwrap(),
                        b"ok"
                    );
                }
                let elapsed = start.elapsed().as_secs_f64();
                origin.await.unwrap();
                let rss = std::fs::read_to_string("/proc/self/status")
                    .unwrap()
                    .lines()
                    .find(|l| l.starts_with("VmRSS:"))
                    .unwrap()
                    .to_owned();
                println!(
                    "H3_BENCH cap={cap} stream_window={window} active={streams} rtt_ms={rtt_ms} drop_every={loss_every} payload_bytes={} seconds={elapsed:.4} mbps={:.4} cpu_seconds={:.4} driver_iterations={} lost={} rss={rss}",
                    SIZE * streams,
                    (SIZE * streams * 8) as f64 / elapsed / 1e6,
                    (cpu_ticks() - cpu) as f64 / tick_hz,
                    app.stats.h3_driver_iterations.load(Ordering::Relaxed) - iterations,
                    q.conn.stats().lost
                );
                drop(q);
                relay.abort();
                stop.send(true).unwrap();
                driver.await.unwrap().unwrap();
                assert_eq!(app.resources.receive.available_permits(), original);
                assert_eq!(app.resources.tunnels.active(), 0);
                assert_eq!(app.resources.requests.active(), 0);
            }
        }
    }
}
