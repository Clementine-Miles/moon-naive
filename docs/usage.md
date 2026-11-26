# Usage

How to build, install, configure and operate the Moon-naive server and the
first-party client. The target is a single Linux node. No container orchestration, database or
external coordination service is needed.

## Server: build and install

Requirements: Rust 1.100 (pinned in `rust-toolchain.toml`), a C/C++
toolchain, make, CMake, libclang, Perl, pkg-config and Git (BoringSSL is
built from source). Neither Go nor Python is needed to build or run the
server. The client's engine build needs Python 3 and Ninja (see
[development](development.md#chromium-native-engine)).

```sh
cargo build --release --locked -p moon-naive -p moon-naive-client
./target/release/moon-naive --version
```

`cargo xtask dist` and `cargo xtask check-elf` package and check a static
`x86_64-linux-musl` server binary built separately; a glibc build is not a
substitute for that target. `cargo xtask source OUT [REV]` produces a source
archive from a committed revision with its own `SHA256SUMS`.

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

## Server configuration

The authoritative field list and defaults are the commented examples
[`config.example.toml`](../config.example.toml) (one endpoint) and
[`config.dual.example.toml`](../config.dual.example.toml) (two endpoints),
plus configuration validation in `core/src/config.rs`. Both examples are
parsed by tests. The client is configured separately; see [Client](#client).

```sh
moon-naive config init /etc/moon-naive/config.toml   # private 0600, never overwrites
moon-naive check-config /etc/moon-naive/config.toml  # structure only
moon-naive check /etc/moon-naive/config.toml         # full offline preflight
moon-naive check-transport /etc/moon-naive/config.toml
moon-naive serve /etc/moon-naive/config.toml
```

`check-config` validates structure. `check` also loads external files (users,
ACL, ECH, certificates) without contacting the CA or DNS provider and without
opening listeners. Create the parent directory, owned by the service user,
before `config init`.

### Essentials

- `domain`: the public host name. A/AAAA must point at a reachable address;
  do not publish AAAA for unreachable IPv6. The website origin must not point
  back at this name.
- `state_dir` (default `/var/lib/moon-naive`, mode 0700) holds the ACME
  account, renewal journal and certificate generations. It must persist.
- Users: `[[proxy.users]]` inline, or a private `credentials_file`. Passwords
  need at least 16 bytes; use 32+ random characters. SHA-256 is not a password
  hardening KDF, so low-entropy passwords are unsafe.
- `accept_terms = true` is required before any live ACME request.

### Endpoints and resource limits

Schema 1/2 `[listener]` and `[limits]` remain valid (TCP/UDP 443 by default).
`[[listeners]]` (up to 16) replaces `[listener]` entirely; never configure
both. Each endpoint has a unique ASCII `name` and its own `tcp`, `udp`, `h1`,
`h2`, `h3` switches. Disabling a protocol skips binding its transport. HTTP/1.1
serves the website only. IPv6 sockets are v6-only (`"[::]:443"`); add a
separately named endpoint per address family. Duplicate or overlapping binds
fail startup, and all sockets bind before any is used.

| Setting | Meaning |
| --- | --- |
| top-level `[limits]` | Process-wide ceilings: connections, H2/H3 streams, pending requests, tunnels per user, byte budgets |
| `[listeners.limits]` | Endpoint budgets and connect/idle/graceful timeouts; still bounded by the global limits |
| `listeners.handshake_timeout_secs` | Inbound handshake deadline (default 10 s) |
| `[listeners.flow]` | `h2_stream_window`, `h2_connection_window`, `h3_stream_window`, `h3_connection_window` in bytes |
| `listeners.public_addresses` | Public/NAT addresses of this endpoint; all of them join the mandatory self-connection deny set |
| `listeners.bandwidth_bytes_per_sec` | Optional per-endpoint byte rate (one bucket per direction, 16 KiB burst; 1024..10^12). Not a flow-control window |

An omitted endpoint `limits` table inherits the top-level values. A present
table uses the standard defaults for unspecified fields (no per-field merge).
Window defaults derive from the endpoint limits. The H2 connection window is at
least 65535. For H3, `stream window × max streams + control reserve` must fit
the connection window. Larger windows reserve receive credit that cannot be
returned early; they are not a speed switch. HTTP/1.1 has no multiplexing:
each connection carries one website request at a time, bounded by
`max_connections`.

`Alt-Svc` advertises only the endpoint's own enabled UDP/H3 port. The server
cannot verify public firewall, NAT or carrier UDP reachability; open TCP and
UDP for every enabled public port. Changes to listeners, ACL or limits need a
restart; certificates and ECH keys hot-reload.

#### QUIC network changes

Active (client-initiated) connection migration is disabled because the server
issues a single connection ID. Passive NAT rebinding keeps that ID and is
validated by quiche (path validation and anti-amplification). Each H3
connection survives at least 7 rebindings (bounded by
`active_connection_id_limit = 8`); after that it idles out and clients
reconnect. See [security.md](security.md#quic-paths-and-connection-ids).

### Website, forward proxy and next hop

- `[website].origin` is the single-site shorthand, such as
  `http://127.0.0.1:8080`: scheme, host and port only. HTTPS origins use
  correct SNI and chain verification. Redirects and cookies are not rewritten.
- Several origins use `[[website.upstreams]]` and `[[website.routes]]`
  (mutually exclusive with `origin`). Routes match the longest `path_prefix`
  and may set the Host header, TLS server name, a private CA, and H1 or H2
  upstreams. Configured origins may be private addresses; visitors can never
  choose an origin.
- Websites keep WebSocket, streaming responses, trailers, Range, SSE/gRPC and
  `no-transform` semantics. HTTP/1.1 framing, Host and Connection fields are
  checked strictly, and forged forwarding and proxy metadata is removed.
- Website defaults: 64 MiB upload, connect 5 s, read/write 30 s, upstream idle
  and DNS TTL 60 s. These are data and connection deadlines; bodies stream.
- `[proxy.forward]` (authenticated ordinary HTTP(S) forwarding) is
  independent of the website: 1 GiB upload, connect 10 s, read/write 120 s,
  idle pool 30 s, 32 concurrent requests per user. Established CONNECT tunnels
  and non-idempotent requests with uncertain state are never retried
  transparently.
- Egress dials only checked, concrete resolved candidates: ASCII DNS names,
  explicit ports, bracketed IPv6. Private, special-purpose, mapped-private and
  self addresses are denied. Configured website origins use their own trust
  policy.
- `[proxy.upstream]` HTTP/HTTPS/SOCKS5 next hops keep their own authentication
  and TLS checks, never fall back to direct egress, and never receive a
  hostname to re-resolve remotely around local checks.

### Destination ACL

Add `acl_file = "/etc/moon-naive/acl.toml"` to the existing `[proxy]` table.
The file must be a private (0600) regular file readable by the service user,
at an absolute path without `..`. Symbolic-link final components, FIFOs,
non-private modes, oversized files (over 256 KiB, 4096 rules, or 128 port
ranges per rule) and invalid content prevent startup; there is no
fail-open. `check-config` does not read the ACL; `check` does.

[`acl.example.toml`](../acl.example.toml) is a complete example: `default =
"allow" | "deny"` (deny when omitted) and ordered `[[rules]]`, each with
`action` and at most one selector:

| Selector | Matches |
| --- | --- |
| `domain = "example.org"` | That exact ASCII DNS name, case-insensitive |
| `suffix = "example.org"` | The name and subdomains on label boundaries (not `notexample.org`) |
| `ip = "1.1.1.1"` | One IPv4/IPv6 address |
| `cidr = "2606:4700::/32"` | A canonical network (host bits rejected) |
| none | Any destination, optionally limited by ports |

`ports = ["443", "8000-8080"]` is an optional union of closed ranges. Unicode
names, wildcards and trailing dots are rejected (convert IDNs to punycode).
IPv4-mapped IPv6 normalizes to IPv4; mapped CIDR prefixes must be at least
/96.

The first rule matching the original target name, port and the current
concrete IP candidate wins; otherwise `default` applies. Decisions that are
known before DNS run early; rules that depend on IP wait for the resolved
candidates, and every candidate is checked. The ACL applies identically to
CONNECT and ordinary forwarding on all endpoints. Mandatory private, special,
local-interface and self-address denials run before any `allow`; the ACL
cannot create private-network exceptions. A next hop is an administrative
trust boundary: the server can only verify the concrete address it hands over.

### Website routing example

Replace the existing `[website]` table with this block (and drop the `origin`
shorthand). Core tests parse this exact block.

```toml
[website]
compression_level = 5
[[website.upstreams]]
name = "app"
origins = ["http://127.0.0.1:3000"]
http2 = true
[[website.routes]]
path_prefix = "/api/"
upstream = "app"
strip_prefix = true
```

`/api/users?limit=10` becomes `/users?limit=10`; unmatched paths return 404.

### Credentials, EAB and migration

Users, DNS credentials and EAB may be inline or in private TOML files. Never
commit a filled-in configuration. `config migrate OLD NEW` writes a migrated
copy and keeps the original; legacy `fast_open` and `zero_rtt` keys are
rejected and dropped, never honored.

Google Trust Services needs External Account Binding (EAB) **only to register
the ACME account the first time**:

```sh
gcloud services enable publicca.googleapis.com
gcloud publicca external-account-keys create --format=json
moon-naive acme import-eab /private/export.json /private/eab.toml
```

`keyId`/`b64MacKey` map to `key_id`/`b64_mac_key` (keep the base64url text).
Use matching staging/production endpoints and EAB. Once the account is stored
in `state_dir`, the EAB may be removed: restarts and renewals recover the
persisted account. If the journal holds only a key (registration outcome
unknown), recovery looks the account up by key; EAB is then needed only if
the account truly does not exist. CAA must allow the chosen CA. Porkbun needs
API access enabled for the zone; Cloudflare needs a token with TXT edit rights
for the zone.

### ECH

```sh
moon-naive ech init CONFIG    # generate keys
moon-naive ech check CONFIG   # validate keys, public name and outer certificate
moon-naive ech dns CONFIG     # print the ECHConfigList for DNS HTTPS records and clients
```

ECH uses BoringSSL with an outer `public_name`, keys and a separate outer
certificate (the outer certificate's renewal is external). An expired outer
certificate pauses new TLS/QUIC handshakes; existing connections continue.
Validation can never be disabled to restore ECH. Publish a new ECHConfigList
in DNS only after `ech check` passes and the server has reloaded it, and keep
old keys configured until cached DNS records expire (at least the record TTL).

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

## Client

`moon-naive-client` is the first-party client for a Moon-naive server. It
exposes a local SOCKS5 and HTTP CONNECT proxy on one port and carries every
local connection over its own authenticated mona (Rupin) CONNECT stream on
HTTP/2 or HTTP/3. It is not compatible with upstream NaiveProxy servers.

The client is two parts. The Rust application (`client/`) handles
configuration, the local listener, the mona proofs and confirmations, and the
record codec. Every proxy connection is made by the **Chromium native engine**
(`libmoon_engine.so`, built from Chromium's network stack; see
[development](development.md#chromium-native-engine)): DNS, TCP/UDP sockets,
TLS 1.3 with BoringSSL, HTTP/2, QUIC/HTTP/3, the socket pools and certificate
verification. The client has no HTTP/2, QUIC or TLS implementation of its own
and no fallback to one: without the engine it refuses to start tunnels.

```sh
# From a client release archive (bin/ and lib/moon-naive/ keep their relative layout):
tar xzf moon-naive-client-VERSION-x86_64-unknown-linux-gnu.tar.gz
cd moon-naive-client-VERSION-x86_64-unknown-linux-gnu
sudo install -Dm755 bin/moon-naive-client /usr/local/bin/moon-naive-client
sudo install -Dm644 lib/moon-naive/libmoon_engine.so /usr/local/lib/moon-naive/libmoon_engine.so
# Or from source: cargo build --release --locked -p moon-naive-client, build the
# engine with `cargo xtask engine` (see development.md) and set engine_library.
install -Dm600 client.example.toml ~/.config/moon-naive/client.toml   # then edit
moon-naive-client check ~/.config/moon-naive/client.toml               # offline validation
moon-naive-client run ~/.config/moon-naive/client.toml
curl --proxy socks5h://127.0.0.1:1080 https://example.org/
```

The configuration contains the password, so `run` and `check` refuse files
that are group- or world-accessible. A systemd user unit is in
[`deploy/moon-naive-client.service`](../deploy/moon-naive-client.service).

### Configuration

See [`client.example.toml`](../client.example.toml); unknown keys are
rejected.

| Key | Default | Meaning |
| --- | --- | --- |
| `server` | required | `host:port` (DNS name, IPv4, or `[IPv6]:port`); H2 uses TCP and H3 uses UDP on this port |
| `server_name` | host of `server` | TLS name for SNI (or the ECH inner name) and certificate verification; required if `server` is an IP |
| `listen` | `127.0.0.1:1080` | Local SOCKS5 + HTTP CONNECT listener. It has no authentication, so only loopback addresses (`127.0.0.0/8`, `[::1]`) are accepted |
| `username`, `password` | required | A user configured on the server; password at least 16 bytes |
| `transport` | `h2` | `h2`, `h3`, or `h3-then-h2` |
| `ca_file` | Chrome Root Store | Additional PEM trust anchors (for a private CA); verification cannot be disabled |
| `ech_config_list` | none | Base64 ECHConfigList from `moon-naive ech dns`; when set, ECH is mandatory |
| `connect_timeout_secs` | 15 | Connection establishment and tunnel setup deadline |
| `local_handshake_timeout_secs` | 10 | Deadline for the local SOCKS5/HTTP request |
| `max_tunnels` | 256 | Concurrent local connections; excess connections are closed |
| `quic_idle_timeout_secs` | 30 | QUIC idle timeout; the connection is re-established on demand |
| `engine_library` | see below | Path to `libmoon_engine.so` |
| `log_level` | `info` | `error`, `info` or `debug`. Credentials and proofs are never logged; targets only at `debug` |

The engine is looked up in this order: `engine_library`, the
`MOON_NAIVE_ENGINE` environment variable, next to the executable, then
`../lib/moon-naive/` relative to the executable (the layout of the client
release archive). The engine's ABI version is checked when it is loaded.

### Behavior

- **Local protocols.** SOCKS5 `CONNECT` with "no authentication" (IPv4,
  IPv6 and domain targets; domains are sent to the server for resolution, as
  with `socks5h`). `BIND` and `UDP ASSOCIATE` are answered with "command not
  supported". HTTP `CONNECT host:port`; other methods get 405. Plain HTTP
  proxying (absolute-form `GET`) is not supported.
- **Authentication.** Each tunnel is a separate CONNECT stream with a proof
  bound to the TLS exporter and the stream ID that Chromium actually
  allocated (the patched engine calls back into the client after the ID is
  assigned and before HEADERS are encoded). Payload flows only after status
  200 and exactly one valid server confirmation; anything else closes the
  stream without sending a byte. `proxy-authorization` is never indexed by
  HPACK/QPACK.
- **TLS.** TLS 1.3 with Chromium's BoringSSL and certificate verifier
  (Chrome Root Store plus `ca_file`), hostname verification always on.
  With `ech_config_list`, ECH is mandatory: a server that does not accept ECH
  is refused and no proof is ever signed on a non-ECH connection. On HTTP/2,
  Chromium applies server-provided retry configurations once (ECH stays
  accepted); on HTTP/3 Chromium does not retry, so a stale list fails closed
  until the configured list is updated.
- **Transports.** Chromium's HTTP/2 and QUIC session pools share one
  connection per transport among all tunnels and reopen it on demand.
  `h3-then-h2` uses HTTP/2 only when a QUIC connection cannot be established
  (connection error or timeout), then avoids QUIC for 5 minutes. A server's
  answer (403, 502, …) is final on any transport, and tunnel bytes are never
  replayed. Half-close is carried in both directions (FIN / `END_STREAM`).
- **Errors to local applications.** Server 403 → SOCKS5 "not allowed" / HTTP
  403; 502 → "host unreachable" / 502; 504 or timeout → "TTL expired" / 504;
  authentication rejection, invalid confirmation and other failures →
  "general failure" / 502.
- **Resource bounds.** At most `max_tunnels` local connections. Each tunnel
  has one outstanding read (at most 64 KiB) and one outstanding write between
  the client and the engine, so flow control is Chromium's own.
- **TCP Fast Open** is never requested, and NaiveProxy's "fast open"
  (sending payload before the CONNECT reply) is refused for these tunnels.

### Platforms and limitations

Linux x86_64 with glibc is the supported and tested platform: the engine is
a glibc shared library, so the client must be a dynamically linked (gnu)
executable, not a static musl one. Other platforms are not built or tested.
DNS-based ECH discovery (HTTPS records) is not used; the ECHConfigList is
configured explicitly.

The engine makes the client's connections with Chromium's real network
stack, but this is not a claim that its traffic cannot be told apart from a
Chrome browser: the engine is a build of Chromium's `net/` without the
browser, its request pattern (one CONNECT per local connection, the mona
headers, record padding) is its own, and no fingerprint comparison has been
done.
