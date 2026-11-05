//! Downgrade rejection against an unmodified upstream release executable.
//! Only the origin dial address is substituted by the cfg(test) egress fixture.
use super::*;
use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn launch(
    binary: &std::path::Path,
    protocol: &str,
    port: u16,
    ca: &std::path::Path,
    password: &str,
) -> (Process, SocketAddr) {
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = reservation.local_addr().unwrap();
    drop(reservation);
    let mut command = Command::new(binary);
    command
        .arg(format!("--listen=socks://{listen}"))
        .arg(format!(
            "--proxy={protocol}://alice:{password}@proxy.example.test:{port}"
        ))
        .arg("--host-resolver-rules=MAP proxy.example.test 127.0.0.1")
        .env("SSL_CERT_FILE", ca)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = command
        .spawn()
        .expect("start unmodified official naive executable");
    let mut child = Process(child);
    let end = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "official client exited before listening"
        );
        if TcpStream::connect(listen).await.is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "official SOCKS listener deadline"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (child, listen)
}
async fn socks(listen: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(listen).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut connect = vec![5, 1, 0, 3, 11];
    connect.extend(b"example.org");
    connect.extend(443u16.to_be_bytes());
    stream.write_all(&connect).await.unwrap();
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    stream
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires NAIVE_BIN; verifies official legacy clients cannot downgrade moon-naive"]
async fn official_naive_h2_h3_legacy_authentication_never_opens_egress() {
    let binary = PathBuf::from(std::env::var_os("NAIVE_BIN").expect("set NAIVE_BIN"));
    assert!(binary.is_absolute() && binary.is_file());
    let fixture = fixture();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = network(&fixture, Some(origin.local_addr().unwrap())).await;
    let tcp = server.tcp_addr().unwrap();
    let udp = server.udp_addr().unwrap();
    let app = server.app.clone();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.run(rx));
    for (protocol, port) in [("https", tcp.port()), ("quic", udp.port())] {
        for password in [
            "long-loopback-test-password",
            "wrong-long-loopback-password",
        ] {
            let (client, listen) = launch(&binary, protocol, port, &fixture.ca, password).await;
            let mut stream = tokio::time::timeout(Duration::from_secs(10), socks(listen))
                .await
                .unwrap();
            let _ = stream.write_all(b"must-not-reach-origin").await;
            let mut byte = [0; 1];
            let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut byte))
                .await
                .unwrap();
            assert!(read.is_err() || read.unwrap() == 0);
            assert_eq!(app.stats.dials.load(Ordering::Relaxed), 0);
            assert_eq!(app.stats.resolutions.load(Ordering::Relaxed), 0);
            drop(client);
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), origin.accept())
            .await
            .is_err()
    );
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert_eq!(app.tunnels.active(), 0);
    assert_eq!(app.requests.active(), 0);
}
