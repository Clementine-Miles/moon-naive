# Moon-naive

Moon-naive is a Rust HTTPS server and client for a single node with a few
trusted users. The server hosts real websites (reverse proxy over HTTP/1.1,
HTTP/2 and HTTP/3) and carries authenticated proxy tunnels with the **mona**
protocol, using its only profile, **Rupin** (formerly "revision 4"). It
manages its own certificates over ACME DNS-01. The first-party client exposes
a local SOCKS5 and HTTP CONNECT proxy and tunnels over H2 or H3 through the
**Chromium native engine**: a Rust application layer driving Chromium's own
network stack (TLS, HTTP/2, QUIC/HTTP/3, socket pools) behind a narrow C ABI.

- Per-stream authentication bound to the TLS 1.3 exporter and stream ID; failed
  authentication is served as ordinary website traffic and never dials out.
- Server: BoringSSL (TLS 1.3, ECH), Pingora (H1/H2, website), quiche (QUIC/H3).
- Client: Chromium's `net/` stack built as `libmoon_engine.so` from a pinned
  revision plus a small patch; the client has no TLS/H2/QUIC code of its own.
- Automatic certificate issuance and renewal (Google Trust Services or Let's
  Encrypt; Porkbun or Cloudflare DNS), with a durable recovery journal and
  supervised renewal.
- Destination policy on resolved addresses, layered quotas, bounded buffers.
- Never uses TCP Fast Open.

It is not compatible with upstream NaiveProxy, and it makes no claim of being
undetectable or unblockable; see [docs/security.md](docs/security.md).

## Quick start

Requires Linux, Rust 1.100, a C/C++ toolchain, CMake, libclang, Perl and
pkg-config (to build BoringSSL). The client also needs the engine library,
from a client release archive or built with `cargo xtask engine` (Python 3,
Ninja, curl; see [docs/development.md](docs/development.md#chromium-native-engine)).

```sh
cargo build --release --locked -p moon-naive -p moon-naive-client

# Server
./target/release/moon-naive config init /etc/moon-naive/config.toml
#   edit domain, users, website origin, DNS and (first registration only) EAB credentials,
#   then set accept_terms = true after reading the CA terms
./target/release/moon-naive check /etc/moon-naive/config.toml
./target/release/moon-naive serve /etc/moon-naive/config.toml

# Client
install -m600 client.example.toml client.toml   # edit server, username, password
MOON_NAIVE_ENGINE=/path/to/libmoon_engine.so ./target/release/moon-naive-client run client.toml
curl --proxy socks5h://127.0.0.1:1080 https://example.org/
```

## Documentation

| Document | Contents |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Components, ownership, routing, the Chromium native engine, dependencies |
| [docs/usage.md](docs/usage.md) | Build, install, server configuration (endpoints, ACL, website, EAB, ECH), operations, backup, client |
| [docs/protocol.md](docs/protocol.md) | Authoritative mona/Rupin wire specification |
| [docs/security.md](docs/security.md) | Threat model, controls, known limits |
| [docs/development.md](docs/development.md) | Layout, dependency policy, engine build, testing, measurements, release |
| [docs/reports/](docs/reports/) | Dated evidence: HTTPS differential, refactor audits, engineering reports |

## Status and limitations

Linux x86_64 is the supported platform for both binaries (the client as a
glibc executable with the engine library). Other platforms are not built. QUIC active migration is
disabled (passive NAT rebinding works up to 7 times per connection). ECH
configuration lists are given to the client explicitly (no DNS discovery).
See [the 2026-11-23 audit](docs/reports/refactor-audit-2026-11-23.md#not-done-with-reasons)
for validation not performed.

License: [Apache-2.0](LICENSE).
