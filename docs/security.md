# Security model

Moon-naive aims for correct, standards-compliant HTTPS behavior and a precise,
testable authentication protocol. It does **not** claim to be undetectable,
unblockable, impossible to fingerprint or probe, free of vulnerabilities, or
equivalent to any browser or server. Stable implementation differences
(certificate chain, TLS and QUIC parameters, HTTP behavior, compression) can
form a fingerprint; see the [HTTPS differential report](reports/https-differential-2026-11-17.md).

## Assets and trust boundaries

- Proxy user secrets, ACME account keys, certificate private keys, ECH keys,
  DNS provider and EAB credentials (all in private files or `state_dir`).
- The ability to make outbound connections from the server.
- The website origins, which may live on private networks.

Trust boundaries: the Internet ↔ listeners; authenticated proxy streams ↔
egress policy; the server ↔ CA, DNS provider API and next hop; the service
user ↔ the administrator who controls configuration directories.

## Threats and controls

| Threat | Entry point | Control | Residual risk / verification |
| --- | --- | --- | --- |
| Unauthenticated egress | H2/H3 request | Per-stream HMAC proof bound to TLS exporter, stream ID and request fields; failures route to the website, with no DNS or dial | Tests assert zero dials for missing, duplicated, malformed, replayed and misbound proofs; client e2e wrong-password test |
| Credential guessing | proof field | 256-bit HMAC; constant-time comparison across all users; passwords ≥ 16 bytes | Low-entropy passwords are guessable offline from captured proofs (SHA-256 is not a password KDF). Use random secrets |
| Replay / proof relocation | captured proof | Proof binds the exporter (unique per TLS session) and the stream ID; no 0-RTT or early exporters | Vectors and transport tests move proofs across streams, connections and transports |
| Malformed HTTP / framing | parsers | Strict pseudo-header and field validation, bounded header sizes, terminal codec errors, no panics on input | Differential malformed-request cases; core codec property-style tests; no fuzzing campaign was run |
| Resource exhaustion | connections, streams, slow peers | Layered quotas (global, endpoint, user, connection), bounded buffers and receive credit, handshake and idle deadlines, Retry-token address validation for QUIC | Multi-device saturation tests; large-scale flood testing not performed |
| SSRF / internal access | CONNECT and forward targets | Policy on every concrete resolved address; private, special-use, mapped, local-interface and self addresses always denied; ACL first-match; next hops never get names to re-resolve | Egress and ACL tests; DNS rebinding is defeated by dialing only the checked address |
| QUIC path abuse | spoofed or changing addresses | quiche path validation and anti-amplification; bounded path table (8) and path-event draining | See below |
| Compromised DNS API token | DNS provider | Ownership-aware TXT management only (never deletes records it does not own) | The token can still alter the zone; scope it to the zone |
| ACME account or key compromise | `state_dir` | 0600/0700 private files, private-file reader, no secrets in logs | Host compromise exposes keys |
| Invalid certificate or ECH material | renewal, reload | Full validation before activation; atomic generation swap; last valid generation retained | Activation failure tests in the ACME laboratory |
| Silent renewal failure | renewal thread | Supervised restart from durable journal with backoff; heartbeat and `status` | — |
| Malicious next hop | `[proxy.upstream]` | Separate TLS and auth verification; never falls back to direct | The next hop sees and routes traffic as it likes |
| Dependency vulnerabilities | Pingora, quiche, BoringSSL, instant-acme | Pinned revisions, source audit (`cargo xtask audit-native`), reviewed vendored patches | Advisories must be re-checked when bumping pins |
| Local misconfiguration | files and permissions | `check` preflight, private-file checks, refusal to start on invalid policy | — |

## Client-side controls

The client's connections are made by the Chromium native engine: Chromium's
certificate verifier (Chrome Root Store plus optional anchors), TLS 1.3,
mandatory ECH when configured (no proof is signed on a non-ECH connection),
and confirmation of the server's 200 response before any payload. Proofs are
bound to the exporter and the stream ID that Chromium actually allocated, and
`proxy-authorization` is never indexed by HPACK/QPACK. The unauthenticated
local listener only accepts loopback addresses. Its configuration file must
be private. The engine library is trusted code loaded into the client
process: install it from a release archive or a build you made, and keep it
as private as the client binary.

## QUIC paths and connection IDs

The server issues exactly one connection ID per connection and routes by it,
so active migration stays disabled (`disable_active_migration`). Passive NAT
rebinding keeps that ID. quiche validates the new path and enforces the
anti-amplification limit before trusting it. In the pinned quiche, when the
client has supplied no spare connection IDs, the pre-rebinding path keeps the
shared destination ID and is never evicted, while the path table is capped by
the local `active_connection_id_limit`. The original value of 2 therefore
stalled a connection at its second rebinding. The limit is now 8: each
connection survives 7 rebindings (regression test
`h3_nat_rebinding_consumes_path_events_and_preserves_session`), after which it
idles out and clients reconnect. Full CID rotation and retirement-based path
cleanup would need connection-ID routing support that is not implemented.

## Known deviations and limits

- quiche's QPACK encoder cannot set the never-index bit on H3 proof fields; it
  never uses the dynamic table (see [protocol.md](protocol.md)).
- TCP Fast Open is never used; the host sysctl boundary is described in
  [usage.md](usage.md#tcp-fast-open).
- No side-channel analysis beyond constant-time proof comparison has been done.
- `unsafe` is forbidden in all project-owned crates (`unsafe_code = "forbid"`)
  except `engine/bridge`, the FFI to the engine. Native code lives in
  BoringSSL (C/C++), in the Chromium engine (C++), and in vendored and
  third-party crates.
- The client uses Chromium's network stack, but no claim is made that its
  traffic is indistinguishable from Chrome's; no fingerprint comparison has
  been done.
