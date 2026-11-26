# HTTPS differential sample — 2026-11-17

This is a representative excerpt from a successful local experiment, not a claim of indistinguishability. The companion JSON retains selected evidence, configuration identity and reference checksums.

Reference: **Caddy v2.10.2**, official pinned Linux x86_64 binary. Both servers used the same temporary certificate and website origin. No production credentials or public CA were used.

510 observations: three repetitions against both servers; H1 10 cases, H2 33, H3 34, TLS 8 per server. Invalid observers, client-only rejections and probe timeouts: **0**. Complete report: **396 field differences**, including expected configuration differences and observations needing review. These are repeated field observations, not 396 separate defects.

| Protocol | Normal Moon response | Normal Caddy response | Body |
| --- | --- | --- | --- |
| H1 | 200 | 200 | identical 50 bytes and SHA-256 |
| H2 | 200 | 200 | identical 50 bytes and SHA-256 |
| H3 | 200 | 200 | identical 50 bytes and SHA-256 |

Observed examples:

- H1 header ordering, `Vary`/`Via`, and Alt-Svc lifetime differ. Raw Alt-Svc ports were verified before replacing dynamic port values in the report.
- H2 SETTINGS values differ. The malformed zero-length PING probe produced different GOAWAY error codes; raw frame evidence is retained in JSON.
- QUIC Retry, receive windows, stream limits, UDP payload limits and migration transport parameters differ. Moon active migration remains disabled.
- Malformed HTTP/3 method handling differs; follow-up valid-stream behavior is recorded independently.
- TLS 1.2 and TLS 1.3 session resumption were observed for both stacks using an independent OpenSSL client. Session tickets and TLS secrets are not retained.

Full coverage gaps remain explicit:

- ordinary authenticated forward requests beyond CONNECT remain covered by Moon regressions; not yet compared here
- HPACK/QPACK dynamic compression traces and extended malformed frame/fuzz corpus beyond deterministic pseudoheader and PING probes
- SETTINGS timing and header/body timing distributions across network environments; elapsed times here are descriptive loopback samples
- TLS extension and exhaustive cipher preference enumeration; resumption sampled with OpenSSL only where available
- H3 slow-reader flow-control update timing and extensive reset storms, half-closed states and graceful GOAWAY ordering
- kernel path QUIC loss/delay/NAT rebinding, migration attempts, CID rotation, congestion/pacing/retransmission benchmarks; three bounded post-handshake client UDP perturbations measured here
- malformed TLS/QUIC handshake corpus and packet-level CONNECTION_CLOSE comparison

Reproduce using `cargo xtask differential-fetch` and `cargo xtask differential` as documented in [development.md](../development.md#https-differential-experiment). Packet capture was optional and was not executed for this run. No production wire-protocol change was made.
