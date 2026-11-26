# Testing

## Everyday commands

```sh
cargo xtask vectors --check                 # independent auth/framing vectors
cargo xtask audit-tfo                       # TCP Fast Open prohibition
cargo test --locked --workspace             # server, core, client, xtask
cargo xtask verify                          # sources + TFO audit, fmt, clippy -D warnings, tests, release build
cargo xtask audit-native                    # pinned sources, no extra TLS backends, BoringSSL only
cargo test --manifest-path vendor/instant-acme/Cargo.toml --locked \
  --no-default-features --features time,x509-parser --lib
```

Default tests are offline and use loopback only. Ignored tests are explicit
measurements or laboratories and never count as passed unless run.

## What the suites cover

| Suite | Location | Scope |
| --- | --- | --- |
| Core | `core/src`, `core/tests` | Config validation, ACL, proofs, codec (all fragmentation sizes, sparse/finite transitions, truncation), shipped examples, fixed vectors |
| Server unit and integration | `src/**/tests`, `src/net/tests/` | Real TLS/QUIC on loopback: website on H1/H2/H3, authentication and routing, padding, flow control, half-close, resets, quotas, certificate reload, ECH, NAT rebinding, multi-endpoint isolation |
| Client e2e (interop) | `src/net/tests/client_e2e.rs`, `cargo xtask interop --engine LIB` | The real client and Chromium engine against the real server: SOCKS5 and HTTP CONNECT over H2 and H3, 3 MiB and concurrent transfers, half-close in both directions, missing/duplicate/corrupt confirmations (no payload, then recovery on the same connection), wrong password (zero dials), untrusted CA, ECH accepted, stale ECH (H2 recovers via retry configs, H3 fails closed), UDP-blocked H3→H2 fallback, reconnection after a server restart. Ignored by plain `cargo test` because it needs the engine library; a static audit that the client has no transport or TFO code runs always |
| Client unit | `client/src` | Config validation, SOCKS5/HTTP CONNECT parsing and rejections, framing round trips in all modes, confirmation checks |
| ACME | `src/acme/`, `src/net/tests/acme_live.rs` | Synthetic Rust ACME CA and DNS provider: issuance, renewal, recovery, EAB rules, activation failures, controller panic (degrade and supervised restart) |
| xtask | `tools/xtask` | Vector reference, vendor source audit on clean checkouts, TFO audit, packaging, lab evidence oracles |

The server's only test hook is a `#[cfg(test)]` dial override that sends
authenticated CONNECTs for public names to a loopback origin; production
builds cannot enable it.

## Laboratories (explicit)

```sh
cargo xtask lab --only oracles --run /tmp/mona-oracles-UNIQUE
cargo xtask lab --only acme --run /tmp/mona-acme-UNIQUE \
  --tcpdump /path/to/tcpdump --tshark /path/to/tshark --python /path/to/python-with-cryptography
cargo xtask lab --only pebble --run /tmp/mona-pebble-UNIQUE \
  --pebble /path/to/pebble --challtestsrv /path/to/pebble-challtestsrv \
  --pebble-source /path/to/pebble-checkout --python /path/to/python
```

Run directories must be new and outside the source tree. Laboratories use
Linux user and network namespaces, iproute2, tcpdump, tshark and Python
`cryptography` for the independent JWS/CSR/EAB oracle (`tools/analyze.py`).
The Pebble laboratory uses an external Pebble checkout at
`d52948ce25e7c1576bcd18ff0e20a1c24ec7c44b` with
[`tools/pebble.patch`](../tools/pebble.patch), built with Go. Go is never part
of the product build. `result.json` is the single machine-readable verdict of
each run; missing evidence, zero relevant results and oracle failures all
fail the run.

## HTTPS differential experiment

```sh
cargo xtask differential-fetch /tmp/moon-caddy-reference-UNIQUE
cargo xtask differential --caddy /tmp/moon-caddy-reference-UNIQUE/caddy \
  --run /tmp/moon-https-differential-UNIQUE
```

Compares Moon-naive's website behavior with a pinned Caddy v2.10.2 binary
(checksums verified) on H1, H2, H3 and TLS, including unauthenticated and
malformed requests, which must cause zero proxy dials. It is available as a
manual CI input. The latest report is in [reports/](reports/). Observations are
descriptive and do not prove indistinguishability.

## Measurements

```sh
cargo test --release --locked -p moon-naive --lib client_throughput -- --ignored --nocapture
cargo test --release --locked -p moon-naive --lib benchmark_h3_receive_windows -- --ignored --nocapture --test-threads=1
```

Client end-to-end loopback throughput, measured 2026-11-23 (release build,
4 vCPU cloud container, client, server and echo origin in one process,
64 MiB echoed each way, 3 runs):

| Transport | Each-way throughput |
| --- | --- |
| H2 | 1479–1637 Mbit/s |
| H3 | 380–417 Mbit/s |

These are loopback numbers for one environment, not Internet or production
throughput. H3 is CPU-bound in userspace QUIC (quiche with 1350-byte
datagrams, no GSO), which is expected.

## Network impairment

The NAT-rebinding test drives real encrypted QUIC through a relay that changes
its source port 7 times on one connection. Earlier work measured H3 receive
windows through a deterministic loss and delay relay. Kernel-level impairment
(`netem` loss, reordering, MTU reduction, address-family changes) has **not**
been run: it requires privileged network namespaces that were not available.

## Results of the 2026-11-23 refactor

Environment: Rust 1.100.0, Linux x86_64 container without IPv6 support.

| Check | Result |
| --- | --- |
| `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings` | pass |
| `cargo xtask vectors --check` | pass (byte-identical after renaming) |
| `cargo xtask audit-tfo`, `cargo xtask audit-native` | pass |
| `cargo test --workspace` | All pass except 3 IPv6 bind tests that fail with `EAFNOSUPPORT` because the container has no IPv6. These also fail on the unmodified baseline and are not modified or skipped |
| Release build of both binaries | pass |
| Client e2e suite (9 tests incl. ECH) | pass |

Not run in this session: Pebble and capture laboratories (need Go-built
Pebble, tcpdump/tshark and namespaces), the Caddy differential, public CA
issuance, kernel `netem` impairment, fuzzing campaigns.
