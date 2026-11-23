# Deployment

The target is a single Linux node. No container orchestration, database or
external coordination service is needed.

## Build

Requirements: Rust 1.100 (pinned in `rust-toolchain.toml`), a C/C++
toolchain, make, CMake, libclang, Perl, pkg-config and Git (BoringSSL is
built from source). Neither Go nor Python is needed to build or run.

```sh
cargo build --release --locked -p moon-naive -p moon-naive-client
./target/release/moon-naive --version
```

`cargo xtask dist` and `cargo xtask check-elf` package and check a static
`x86_64-linux-musl` server binary built separately; a glibc build is not a
substitute for that target. `cargo xtask source OUT [REV]` produces a source
archive from a committed revision with its own `SHA256SUMS`.

## Server installation (systemd)

```sh
useradd --system --home /var/lib/moon-naive --shell /usr/sbin/nologin moon-naive
install -m755 target/release/moon-naive /usr/local/bin/
install -d -o moon-naive -g moon-naive -m700 /etc/moon-naive
sudo -u moon-naive moon-naive config init /etc/moon-naive/config.toml   # 0600
# edit: domain, users, website origin, DNS credentials, EAB (first registration only), accept_terms
sudo -u moon-naive moon-naive check /etc/moon-naive/config.toml
install -m644 deploy/moon-naive.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now moon-naive
```

An OpenRC script is in [`deploy/moon-naive.openrc`](../deploy/moon-naive.openrc).
The unit uses `Type=notify`: readiness is signalled only after the first valid
certificate is installed and all listeners are bound. `TimeoutStopSec=360`
covers the default `graceful_timeout_secs = 300` plus control-plane cleanup;
change both together. The unit grants only `CAP_NET_BIND_SERVICE`, uses
`ProtectSystem=strict`, and allows writes only to `/var/lib/moon-naive`.

Open TCP and UDP for every enabled public port (443 by default). DNS-01 does
not need port 80.

## Files and permissions

| Path | Mode | Contents | Back up? |
| --- | --- | --- | --- |
| `/etc/moon-naive/config.toml` | 0600 | Main configuration, possibly inline secrets | Yes (encrypted) |
| `/etc/moon-naive/*.toml` (users, DNS, EAB, ACL, ECH keys) | 0600 | Optional private files | Yes (encrypted) |
| `/var/lib/moon-naive/acme/journal-*.json` | 0600 | ACME account key and credentials, renewal journal, DNS lease intents | Yes; never delete pending intents |
| `/var/lib/moon-naive/certificates/` | 0700 | Verified certificate generations and `CURRENT` pointer | Yes |
| `/var/lib/moon-naive/acme/WORKER` | 0600 | Ephemeral renewal heartbeat (rewritten without fsync) | No |

All secret files are read through a private-file reader that rejects
symbolic-link final components, FIFOs, non-private modes and oversized
content. Parent directories must be controlled by a trusted administrator.
Never run `serve` and a maintenance command (`acme once`, `acme cleanup`) on
the same `state_dir` at the same time; the journal lock refuses it.

## Operations

```sh
moon-naive status /etc/moon-naive/config.toml        # certificate expiry, renewal worker heartbeat
moon-naive acme status /etc/moon-naive/config.toml
moon-naive acme check-ca /etc/moon-naive/config.toml # read-only directory check
journalctl -u moon-naive                             # key=value events, no secrets
```

`status` reports the heartbeat of the renewal worker (bound to PID, process
start time and boot ID), last success, next attempt, failure phase and whether
reconciliation is required. A heartbeat older than 15 seconds reads as
stopped. Log events to watch: `renewal_stopped`, `renewal_restart_scheduled`,
`renewal_restarted`, `certificate_wait`, `server_stopped clean=false`.

If the renewal controller stops while serving, the server restarts it from
the durable journal with backoff (60 s up to 1 h) and keeps serving the last
valid certificate. Persistent failures stay visible in `status` and the log.
After fixing the cause (credentials, trust, DNS), run
`moon-naive acme retry-certificate CONFIG` with the service stopped if a
certificate was blocked, or simply wait for the next attempt.

## Backup, restore and rollback

- **Backup:** `/etc/moon-naive` and `/var/lib/moon-naive` (excluding `WORKER`),
  taken with the service stopped or from a filesystem snapshot.
- **Restore:** reinstall the binary and unit, restore both directories with
  the same owner and modes, then run `moon-naive check` before starting.
  The ACME account is recovered from the journal; no new EAB is needed.
- **Rollback:** keep the previous binary. Journal version 3 records blocked and
  retired certificates; older binaries that predate it must not be started on
  the same `state_dir` without a reviewed migration. Certificate generations
  and `CURRENT` remain usable by both.

## TCP Fast Open

Moon-naive never enables TCP Fast Open (TFO). No project-owned code,
configuration, unit or documentation sets a TFO socket option or send flag,
or changes the kernel's TFO sysctl. `cargo xtask audit-tfo` enforces this in
CI, and tests assert that outbound sockets do not request TFO. The audit cannot
see the host: a kernel sysctl setting that forces server-side TFO without a
socket option is outside the program's control. Keep the distribution default.
The systemd unit's `ProtectKernelTunables=true` stops the service itself from
changing sysctls.

## Client installation

See [client.md](client.md) and
[`deploy/moon-naive-client.service`](../deploy/moon-naive-client.service).
