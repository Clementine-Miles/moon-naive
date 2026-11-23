# Moon-naive

Moon-naive is a Rust HTTPS server and client for a single node with a few
trusted users. The server hosts real websites (reverse proxy over HTTP/1.1,
HTTP/2 and HTTP/3) and carries authenticated proxy tunnels with the **mona**
protocol, using its only profile, **Rupin** (formerly "revision 4"). It
manages its own certificates over ACME DNS-01. The first-party client exposes
a local SOCKS5 and HTTP CONNECT proxy and tunnels over H2 or H3.

- Per-stream authentication bound to the TLS 1.3 exporter and stream ID; failed
  authentication is served as ordinary website traffic and never dials out.
- BoringSSL (TLS 1.3, ECH), Pingora (H1/H2, website), quiche (QUIC/H3).
- Automatic certificate issuance and renewal (Google Trust Services or Let's
  Encrypt; Porkbun or Cloudflare DNS), with a durable recovery journal and
  supervised renewal.
- Destination policy on resolved addresses, layered quotas, bounded buffers.
- Never uses TCP Fast Open.

It is not compatible with upstream NaiveProxy, and it makes no claim of being
undetectable or unblockable; see [docs/security.md](docs/security.md).

## Quick start

Requires Linux, Rust 1.100, a C/C++ toolchain, CMake, libclang, Perl and
pkg-config (to build BoringSSL).

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
./target/release/moon-naive-client run client.toml
curl --proxy socks5h://127.0.0.1:1080 https://example.org/
```

## Documentation

| Document | Contents |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Components, ownership, routing, dependencies |
| [docs/protocol.md](docs/protocol.md) | Authoritative mona/Rupin wire specification |
| [docs/configuration.md](docs/configuration.md) | Server configuration, endpoints, ACL, website routing, EAB, ECH |
| [docs/client.md](docs/client.md) | Client configuration and behavior |
| [docs/deployment.md](docs/deployment.md) | Installation, files, operations, backup and rollback |
| [docs/security.md](docs/security.md) | Threat model, controls, known limits |
| [docs/testing.md](docs/testing.md) | Test suites, laboratories, measurements, latest results |
| [docs/development.md](docs/development.md) | Layout, naming, dependency policy, non-Rust inventory, release |
| [docs/audit.md](docs/audit.md) | 2026-11-23 refactor audit: findings and fixes |

## Status and limitations

Linux x86_64 is the supported platform for both binaries. Android and other
platforms are not supported by the Rust client. QUIC active migration is
disabled (passive NAT rebinding works up to 7 times per connection). ECH
configuration lists are given to the client explicitly (no DNS discovery).
See [docs/audit.md](docs/audit.md#not-done-with-reasons) for validation not
performed.

License: [Apache-2.0](LICENSE).
