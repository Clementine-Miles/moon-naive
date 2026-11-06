//! Per-socket TCP policy. Never changes host sysctls or loads kernel modules.
use super::Result;
use moon_naive_core::config::{Config, TcpCongestion};

/// Set the listener's policy before bind/listen so children inherit BBR even
/// while waiting in the accept queue. Kernel TCP buffer autotuning is retained.
pub(super) fn listen(
    address: std::net::SocketAddr,
    algorithm: TcpCongestion,
) -> Result<tokio::net::TcpListener> {
    let socket = if address.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    apply_connecting(&socket, algorithm)?;
    socket.bind(address)?;
    Ok(socket.listen(1024)?)
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

#[cfg(target_os = "linux")]
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
