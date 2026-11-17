//! Per-socket TCP policy. Never changes host sysctls or loads kernel modules.
use super::Result;
use moon_naive_core::config::{Config, TcpCongestion};

/// Set the listener's policy before bind/listen so children inherit BBR even
/// while waiting in the accept queue. Kernel TCP buffer autotuning is retained.
pub(super) fn listen(
    address: std::net::SocketAddr,
    algorithm: TcpCongestion,
) -> Result<tokio::net::TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    // Never let an IPv6 wildcard silently claim the IPv4 listener. Explicit
    // address-family ownership makes startup portable and avoids bind-order
    // dependence when one process hosts both families on the same port.
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    apply_socket(&socket2::SockRef::from(&socket), algorithm)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    Ok(tokio::net::TcpListener::from_std(socket.into())?)
}

/// UDP follows the same explicit-family ownership as TCP. Do not enable
/// SO_REUSEPORT: two endpoints must never accidentally split QUIC datagrams.
pub(super) fn listen_udp(address: std::net::SocketAddr) -> Result<tokio::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(tokio::net::UdpSocket::from_std(socket.into())?)
}

pub(super) fn effective(algorithm: TcpCongestion) -> Result<String> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    apply_socket(&socket2::SockRef::from(&socket), algorithm)?;
    #[cfg(target_os = "linux")]
    return Ok(String::from_utf8(socket.tcp_congestion()?)?
        .trim_end_matches('\0')
        .to_owned());
    #[cfg(not(target_os = "linux"))]
    Ok("system".into())
}

pub(crate) fn check(config: &Config) -> Result<()> {
    if config.transport.tcp_congestion == TcpCongestion::Bbr {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        #[cfg(target_os = "linux")]
        {
            socket.set_tcp_congestion(b"bbr").map_err(|_| "TCP BBR is unavailable in this kernel; load/configure it on the deployment host or explicitly select system")?;
            if !is_bbr(&socket.tcp_congestion()?) {
                return Err("TCP BBR was not applied".into());
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = socket;
            return Err("per-socket TCP BBR currently requires Linux".into());
        }
    }
    Ok(())
}
pub(super) fn apply(stream: &tokio::net::TcpStream, algorithm: TcpCongestion) -> Result<()> {
    apply_socket(&socket2::SockRef::from(stream), algorithm)
}
pub(super) fn apply_connecting(
    stream: &tokio::net::TcpSocket,
    algorithm: TcpCongestion,
) -> Result<()> {
    apply_socket(&socket2::SockRef::from(stream), algorithm)
}
fn apply_socket(socket: &socket2::SockRef<'_>, algorithm: TcpCongestion) -> Result<()> {
    if algorithm == TcpCongestion::Bbr {
        #[cfg(target_os = "linux")]
        {
            socket.set_tcp_congestion(b"bbr")?;
            if !is_bbr(&socket.tcp_congestion()?) {
                return Err("TCP BBR was not applied".into());
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Err("per-socket TCP BBR currently requires Linux".into());
        }
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn is_bbr(name: &[u8]) -> bool {
    name.split(|byte| *byte == 0).next() == Some(b"bbr".as_slice())
}

// Upstream references checked 2026-11-04 against the Linux CVE team's record:
// https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/refs/heads/master/cve/published/2026/CVE-2026-98432.mbox
// Release numbers cannot attest vendor backports, custom trees or live patches.
#[cfg(any(target_os = "linux", test))]
fn kernel_reference(release: &str) -> (&'static str, &'static str) {
    if release.contains("-rc") || release.contains("-next") {
        return ("unknown", "vendor_advisory");
    }
    let version = release.split(['-', '+']).next().unwrap_or("");
    let parts = version
        .split('.')
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>();
    let Ok(parts) = parts else {
        return ("unknown", "vendor_advisory");
    };
    let [major, minor, patch] = parts.as_slice() else {
        return ("unknown", "vendor_advisory");
    };
    let (fixed, reference) = match (*major, *minor) {
        (5, 10) => (272, "5.10.272"),
        (5, 15) => (223, "5.15.223"),
        (6, 1) => (190, "6.1.190"),
        (6, 6) => (159, "6.6.159"),
        (6, 12) => (113, "6.12.113"),
        (6, 18) => (56, "6.18.56"),
        (7, 2) => (10, "7.2.10"),
        (7, 3) => (0, "7.3"),
        _ => return ("unknown", "vendor_advisory"),
    };
    (
        if *patch >= fixed {
            "at_or_above_upstream_fix"
        } else {
            "below_upstream_fix_backport_unknown"
        },
        reference,
    )
}

pub(super) fn kernel_report() -> String {
    #[cfg(target_os = "linux")]
    {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        let release = release.trim();
        let (range, reference) = kernel_reference(release);
        // Diagnostic text only; never execute commands or accept a patch-status
        // claim from configuration. TLS/authentication cannot protect SYN paths.
        let release = if !release.is_empty()
            && release.len() <= 128
            && release
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-+_".contains(&c))
        {
            release
        } else {
            "unknown"
        };
        format!(
            "kernel_release={release}\ncve_2026_98432_version_reference={range}\ncve_2026_98432_upstream_fix={reference}\nkernel_patch_status=not_attested_verify_vendor\nkernel_security_checked_at=2026-11-04"
        )
    }
    #[cfg(not(target_os = "linux"))]
    "kernel_security=not_linux".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn explicit_ipv6_tcp_does_not_claim_ipv4_port() {
        let v6 = listen("[::]:0".parse().unwrap(), TcpCongestion::System).unwrap();
        let port = v6.local_addr().unwrap().port();
        let v4 = listen(([0, 0, 0, 0], port).into(), TcpCongestion::System).unwrap();
        assert!(socket2::SockRef::from(&v6).only_v6().unwrap());
        let _client = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        assert!(v4.accept().await.unwrap().1.is_ipv4());
    }
    #[tokio::test]
    async fn explicit_ipv6_udp_does_not_claim_ipv4_port_and_duplicates_fail() {
        let v6 = listen_udp("[::]:0".parse().unwrap()).unwrap();
        let port = v6.local_addr().unwrap().port();
        let v4 = listen_udp(([0, 0, 0, 0], port).into()).unwrap();
        assert!(socket2::SockRef::from(&v6).only_v6().unwrap());
        assert!(listen_udp(([0, 0, 0, 0], port).into()).is_err());
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(b"v4", (std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut bytes = [0; 2];
        let (len, from) = v4.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..len], b"v4");
        assert!(from.is_ipv4());
    }
    #[test]
    fn kernel_versions_are_references_not_vendor_patch_attestations() {
        for (before, after, reference) in [
            ("5.10.271", "5.10.272", "5.10.272"),
            ("5.15.222", "5.15.223", "5.15.223"),
            ("6.1.189", "6.1.190", "6.1.190"),
            ("6.6.158", "6.6.159", "6.6.159"),
            ("6.12.112", "6.12.113", "6.12.113"),
            ("6.18.55", "6.18.56", "6.18.56"),
            ("7.2.9", "7.2.10", "7.2.10"),
        ] {
            assert_eq!(
                kernel_reference(before),
                ("below_upstream_fix_backport_unknown", reference)
            );
            assert_eq!(
                kernel_reference(after),
                ("at_or_above_upstream_fix", reference)
            );
        }
        assert_eq!(
            kernel_reference("6.1.0-vendor-backport").0,
            "below_upstream_fix_backport_unknown"
        );
        assert_eq!(
            kernel_reference("6.18.57-custom").0,
            "at_or_above_upstream_fix"
        );
        for unknown in [
            "",
            "invalid",
            "6.18",
            "99.1.0",
            "7.3.0.rc1",
            "7.3.0-rc1",
            "7.3.0-next-20261104",
        ] {
            assert_eq!(kernel_reference(unknown).0, "unknown");
        }
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bbr_is_read_back_on_real_inbound_and_egress_sockets() {
        if !std::env::var("MOON_NAIVE_TEST_TCP_CONGESTION").is_ok_and(|v| v == "bbr") {
            eprintln!(
                "TCP BBR integration not requested; run with MOON_NAIVE_TEST_TCP_CONGESTION=bbr"
            );
            return;
        }
        let mut config = Config::parse(include_str!("../../config.example.toml")).unwrap();
        config.transport.tcp_congestion = TcpCongestion::Bbr;
        check(&config).unwrap();
        let connecting = tokio::net::TcpSocket::new_v4().unwrap();
        socket2::SockRef::from(&connecting)
            .set_tcp_congestion(b"reno")
            .unwrap();
        apply_connecting(&connecting, TcpCongestion::Bbr).unwrap();
        assert!(is_bbr(
            &socket2::SockRef::from(&connecting)
                .tcp_congestion()
                .unwrap()
        ));
        let listener = listen("127.0.0.1:0".parse().unwrap(), TcpCongestion::Bbr).unwrap();
        assert!(is_bbr(
            &socket2::SockRef::from(&listener).tcp_congestion().unwrap()
        ));
        let address = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        // Before the accepted-socket fallback runs, the child inherited BBR.
        assert!(is_bbr(
            &socket2::SockRef::from(&server).tcp_congestion().unwrap()
        ));
        socket2::SockRef::from(&server)
            .set_tcp_congestion(b"reno")
            .unwrap();
        apply(&server, TcpCongestion::Bbr).unwrap();
        assert!(is_bbr(
            &socket2::SockRef::from(&server).tcp_congestion().unwrap()
        ));
        let stats = std::sync::Arc::new(super::super::Stats::default());
        let mut egress = super::super::egress::Egress::new(&config, stats).unwrap();
        egress.test_target = Some(address);
        let authority = moon_naive_core::policy::Authority::parse("example.com:443").unwrap();
        let target = egress.dial(&authority).await.unwrap();
        assert!(is_bbr(
            &socket2::SockRef::from(target.tcp().unwrap())
                .tcp_congestion()
                .unwrap()
        ));
        drop(client);
    }
}
