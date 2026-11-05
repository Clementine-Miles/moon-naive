//! Explicit opt-in to an installed Chromium; only local fixture origins are used.
use super::*;
use std::process::{Command, Stdio};
#[tokio::test]
#[ignore = "requires CHROMIUM_BIN pointing to a real local browser"]
async fn chromium_discovers_h3_from_alt_svc_and_falls_back_to_h2() {
    use base64::Engine;
    let binary = std::env::var("CHROMIUM_BIN").expect("CHROMIUM_BIN required");
    for quic in [true, false] {
        let mut f = fixture();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(address).await.unwrap();
        let config = Arc::get_mut(&mut f.config).unwrap();
        config.listener.h1 = true;
        config.listener.tcp = address;
        config.listener.udp = address;
        config.limits.idle_timeout_secs = 30;
        std::fs::write(f.site_root.join("probe.txt"), b"browser probe").unwrap();
        std::fs::write(f.site_root.join("index.html"),br#"<!doctype html><title>waiting</title><body>waiting<script>
(async()=>{let seen=[performance.getEntriesByType('navigation')[0].nextHopProtocol];for(let i=0;i<30;i++){let u='/probe.txt?i='+i;await(await fetch(u,{cache:'no-store'})).text();let p=performance.getEntriesByName(location.origin+u).at(-1);seen.push(p?.nextHopProtocol||'?');await new Promise(r=>setTimeout(r,200));}document.body.textContent='protocols:'+seen.join(',');document.title='done:'+seen.join(',');})();
</script>"#).unwrap();
        let slot = tls::Slot::load(&f.config).unwrap();
        let certificate = DiskStore::open(&f.config.state_dir.join("certificates"))
            .unwrap()
            .read_current()
            .unwrap()
            .unwrap();
        let leaf = X509::stack_from_pem(&certificate.candidate.chain_pem)
            .unwrap()
            .remove(0);
        let spki = base64::engine::general_purpose::STANDARD.encode(boring::sha::sha256(
            &leaf.public_key().unwrap().public_key_to_der().unwrap(),
        ));
        let app = Arc::new(App::load(&f.config).unwrap());
        let stats = app.stats.clone();
        let (stop, rx) = watch::channel(false);
        let server = if quic {
            let network = Network {
                app,
                tls: slot,
                tcp,
                udp,
                redirect: None,
                connections: Budget::new(16).unwrap(),
                config: f.config.clone(),
                stats: stats.clone(),
            };
            tokio::spawn(network.run(rx))
        } else {
            drop(udp);
            tokio::spawn(async move {
                let mut stop = rx;
                let mut tasks = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {_=stop.changed()=>break,accepted=tcp.accept()=>{let(socket,_)=accepted?;let app=app.clone();let slot=slot.clone();let stop=stop.clone();tasks.spawn(async move {let _=super::super::h2::serve(socket,app,slot,stop).await;});}}
                }
                tasks.abort_all();
                Ok::<_, crate::acme::Error>(())
            })
        };
        let output = f._root.path().join("browser.html");
        let stderr = f._root.path().join("browser.stderr");
        let child = Command::new(&binary)
            .args([
                "--headless",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-background-networking",
                "--disable-component-update",
                "--no-first-run",
                "--no-default-browser-check",
                "--no-proxy-server",
                "--remote-debugging-port=0",
                "--disable-extensions",
                "--enable-quic",
            ])
            .arg(format!(
                "--user-data-dir={}",
                f._root.path().join("browser-profile").display()
            ))
            .arg(format!("--ignore-certificate-errors-spki-list={spki}"))
            .arg(format!(
                "--log-net-log={}",
                f._root.path().join("netlog.json").display()
            ))
            // Chromium independently rejects private roots for QUIC even with an SPKI pin.
            // Its allowlist uses the hostname, whereas forced QUIC uses the entire origin.
            // Port 1 is never contacted: the actual ephemeral origin still starts on H2
            // and discovers H3 through Alt-Svc. Assert that initial H2 below.
            .arg("--origin-to-force-quic-on=proxy.example.test:1")
            .arg("--host-resolver-rules=MAP proxy.example.test 127.0.0.1, MAP * ~NOTFOUND")
            .arg(format!("https://proxy.example.test:{}/", address.port()))
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&output).unwrap())
            .stderr(std::fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let mut child = Browser(child);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
        let protocols = loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "Chromium exited before page completion"
            );
            if tokio::time::Instant::now() >= deadline {
                let diagnostics = std::fs::read_to_string(&stderr).unwrap_or_default();
                panic!("Chromium page deadline: {diagnostics}");
            }
            if let Ok(active) =
                std::fs::read_to_string(f._root.path().join("browser-profile/DevToolsActivePort"))
                && let Some(port) = active.lines().next().and_then(|p| p.parse::<u16>().ok())
                && let Ok(Ok(title)) =
                    tokio::time::timeout(Duration::from_secs(1), page_title(port)).await
                && let Some(protocols) = title.strip_prefix("done:")
            {
                break protocols.to_owned();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        drop(child);
        if quic && !protocols.split(',').any(|p| p == "h3") {
            let _ = std::fs::copy(
                f._root.path().join("netlog.json"),
                "/tmp/moon-browser-netlog.json",
            );
        }
        eprintln!("Chromium QUIC enabled at server={quic}: {protocols}");
        assert_eq!(
            protocols.split(',').next(),
            Some("h2"),
            "initial navigation must not force QUIC"
        );
        if quic {
            assert!(protocols.split(',').any(|p| p == "h3"), "{protocols}");
            assert!(stats.h3_connections.load(Ordering::Relaxed) > 0);
        } else {
            assert!(protocols.split(',').all(|p| p == "h2"), "{protocols}");
        }
        stop.send(true).unwrap();
        server.await.unwrap().unwrap();
    }
}

struct Browser(std::process::Child);
impl Drop for Browser {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn page_title(port: u16) -> crate::acme::Result<String> {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await?;
    socket
        .write_all(b"GET /json/list HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() > 32768 {
            return Err("DevTools headers too large".into());
        }
        header.push(socket.read_u8().await?);
    }
    let header = std::str::from_utf8(&header)?;
    let length = header
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim())
        })
        .ok_or("DevTools content length")?
        .parse::<usize>()?;
    if length > 1048576 {
        return Err("DevTools response too large".into());
    }
    let mut bytes = vec![0; length];
    socket.read_exact(&mut bytes).await?;
    let pages: serde_json::Value = serde_json::from_slice(&bytes)?;
    let title = pages
        .as_array()
        .ok_or("DevTools pages")?
        .iter()
        .find(|page| {
            page["url"]
                .as_str()
                .is_some_and(|u| u.starts_with("https://proxy.example.test:"))
        })
        .and_then(|page| page["title"].as_str())
        .unwrap_or("");
    Ok(title.to_owned())
}
