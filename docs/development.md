# Development

## Layout

```
src/            server (moon-naive): runtime, CLI, net/, acme/
core/           pure protocol, policy and configuration logic (moon-naive-core)
client/         first-party client (moon-naive-client)
engine/         Chromium native engine: pin, chromium.patch, args.gn, src/ overlay, bridge/ (moon-naive-engine crate)
tools/xtask/    verification, audits, laboratories, packaging (cargo xtask …)
vendor/         locally patched Pingora and instant-acme (see their patch notes)
deploy/         systemd and OpenRC units
docs/           this documentation; reports/ holds dated experiment evidence
```

`cargo build` builds the server and client (the workspace's default members).
Run `cargo xtask verify` before submitting changes. The workspace forbids
`unsafe` code, with one exception: `engine/bridge` (the FFI to the engine),
where every `unsafe` block carries a safety comment.

## Naming

| Concept | Name | Forms in code |
| --- | --- | --- |
| Project | Moon-naive | crates `moon-naive`, `moon-naive-core`, `moon-naive-client`; binaries `moon-naive`, `moon-naive-client`; paths `/etc/moon-naive`, `/var/lib/moon-naive` |
| Protocol | mona | `moon_naive_core::auth::PROTOCOL` |
| Profile | Rupin (formerly "revision 4") | `moon_naive_core::auth::PROFILE` |

The Rupin wire labels (`SCHEME`, `EXPORTER_LABEL`, and the key, request and
response domains in `core/src/auth.rs`) keep their historical byte values on
purpose. Changing any of them is a new, incompatible profile and needs new
vectors, a version negotiation design, and simultaneous client and server
changes. `cargo xtask vectors --check` fails if their bytes change.

## Dependency policy

Pins are exact (`Cargo.toml`, `Cargo.lock`): Pingora `f86ffda5`, quiche
`7ccccc7b`, instant-acme `1909bed8`, `boring`/`tokio-boring`/`boring-sys`
5.5.0 (server only; the client's TLS is Chromium's), and the engine's
NaiveProxy revision in `engine/UPSTREAM_REVISION`. Production features disable
other TLS backends;
`cargo xtask audit-native` rejects rustls, ring, OpenSSL, aws-lc and similar
in the server's normal dependency graph. Do not upgrade broadly without
compatibility testing and an advisory review, especially for quiche, BoringSSL,
Pingora and instant-acme. When changing a vendored tree, update its patch notes
and `SHA256SUMS` (the vendor audit verifies the file set and digests).

## Non-Rust inventory

All project-owned application logic is Rust. Non-Rust tracked files outside
`vendor/`:

| File(s) | Class | Decision |
| --- | --- | --- |
| `Cargo.toml`, `*/Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.cargo/config.toml` | Build system | Required |
| `config.example.toml`, `config.dual.example.toml`, `acl.example.toml`, `client.example.toml` | Configuration templates | Required; parsed by tests |
| `deploy/*.service`, `deploy/moon-naive.openrc` | Platform integration | Required |
| `.github/workflows/server.yml` | CI | Required |
| `engine/chromium.patch`, `engine/src/**` (C++), `engine/args.gn`, `engine/UPSTREAM_REVISION`, `engine/CHROMIUM_VERSION`, `engine/LICENSE.chromium` | Chromium native engine | Required; see below |
| `core/tests/vectors/*.tsv` | Test fixtures | Required; independent known answers |
| `assets/*.crt` | Test and staging trust roots | Required for staging and laboratory trust |
| `docs/**`, `README.md` | Documentation | Required |
| `LICENSE`, `licenses/*` | Legal texts | Preserved verbatim |
| `tools/analyze.py` | Laboratory oracle (Python `cryptography`) | Kept on purpose: an independently implemented JWS/CSR/EAB verifier for captures, so laboratory evidence does not depend on the code under test. Never part of build or runtime |
| `tools/pebble.patch` | Patch for the external Go test CA | Kept: the test CA is external; no Go enters the repository or product |
| `.gitignore`, `.gitattributes` | Repository metadata | Required |

Native code: the server uses BoringSSL (C/C++ and assembly, built by
`boring-sys`) for ECH, TLS exporters and quiche. The client's data plane is
the Chromium native engine (below). The 2026-11-23 refactor had replaced an
earlier Chromium-based client with Rust h2/quiche transports; those were
removed again in favor of the engine, which keeps the Rust application layer.

## Chromium native engine

`libmoon_engine.so` is Chromium's network stack from the NaiveProxy tree at
`engine/UPSTREAM_REVISION` (Chromium `engine/CHROMIUM_VERSION`), with:

- `engine/chromium.patch`: the edits to existing Chromium files (the
  channel-binding hook in `SpdySession`/`QuicProxyClientSocket`, exporter
  access, half-close, strict ECH with a configured list, never-indexed
  `proxy-authorization`, and the `moon_engine` GN target);
- `engine/src/`: new files copied into the tree (`net/tools/moon_engine/`,
  the C ABI in `moon_engine.h`, and `net/base/moon_tunnel_authenticator.h`);
- `engine/args.gn`: the build flags (no allocator shim, no
  PartitionAlloc-as-malloc, since the library lives in a Rust process).

The library exports only the eight `moon_*` functions of `moon_engine.h`
(version script) and needs only glibc. It contains no mona constants or
cryptography: the exporter label comes from the client, and the client signs
and verifies through callbacks.

```sh
cargo xtask engine fetch /work/chromium       # pinned tree + patch + overlay (new directory)
cargo xtask engine toolchain /work/chromium   # Chromium's pinned Clang; GN built from its DEPS pin
cargo xtask engine check /work/chromium       # tree == pin + chromium.patch + overlay
cargo xtask engine build /work/chromium       # ninja moon_engine, then check-engine
cargo xtask interop --engine /work/chromium/src/out/engine/libmoon_engine.so
cargo xtask engine export /work/chromium      # maintainers: regenerate chromium.patch from the tree
```

`toolchain --gn-source <git-url>` builds GN from a mirror when
`gn.googlesource.com` is unreachable; the commit is still checked against the
DEPS pin. The build needs Python 3, Ninja, `curl`, `xz`, about 1.5 GB of disk
for the tree and output, and on a 4-core machine roughly an hour or more.
CI caches the library by the hash of the engine inputs.

`cargo xtask interop` runs the ignored tests in `src/net/tests/client_e2e.rs`:
the real client and engine against the real server over H2 and H3 (tunnels,
bidirectional data, half-close, invalid confirmations and recovery, ECH,
transport policy).

## Vendored patches

- [`vendor/pingora/MOON-NAIVE-PATCHES.md`](../vendor/pingora/MOON-NAIVE-PATCHES.md)
- [`vendor/instant-acme/MOON-PATCH.md`](../vendor/instant-acme/MOON-PATCH.md)

The root workspace excludes both trees from membership but patches them in;
their standalone lockfiles are ignored by Git.

## Release

```sh
cargo xtask verify
cargo xtask check-elf /path/to/validated-musl-binary
cargo xtask dist /path/to/validated-musl-binary /outside/dist
cargo build --release --locked -p moon-naive-client          # x86_64-unknown-linux-gnu
cargo xtask dist-client target/release/moon-naive-client /path/to/libmoon_engine.so /outside/dist
cargo xtask source /outside/source HEAD
```

The client archive holds `bin/moon-naive-client`,
`lib/moon-naive/libmoon_engine.so`, the engine's pin, patch and flags, the
Chromium license and the client's Rust dependency notices. CI builds it as
the `moon-naive-client-x86_64-unknown-linux-gnu` artifact.

`source` packages only committed bytes of an explicit revision (rejecting
dirty trees, symbolic links and submodules), preserves executable bits,
records `SOURCE_REVISION`, and writes `SHA256SUMS` for the archive. Checksums
prove snapshot integrity, not correctness. Release inventories list normal
and build dependencies with their licenses. `licenses/` keeps the musl, GCC
runtime (with GPL-3.0) and Rust license texts for static musl releases.

## Testing

### Everyday commands

```sh
cargo xtask vectors --check                 # independent auth/framing vectors
cargo xtask audit-tfo                       # TCP Fast Open prohibition
cargo test --locked --workspace             # server, core, client, xtask
cargo xtask verify                          # sources + TFO audit, fmt, clippy -D warnings, tests, release build
cargo xtask audit-native                    # pinned sources, no extra TLS backends, BoringSSL only
cargo test --manifest-path vendor/instant-acme/Cargo.toml --locked \
  --no-default-features --features time,x509-parser --lib
cargo xtask interop --engine /path/to/libmoon_engine.so   # client + Chromium engine <-> server
```

Default tests are offline and use loopback only. Ignored tests are explicit
measurements or laboratories and never count as passed unless run.

### What the suites cover

| Suite | Location | Scope |
| --- | --- | --- |
| Core | `core/src`, `core/tests` | Config validation, ACL, proofs, codec (all fragmentation sizes, sparse/finite transitions, truncation), shipped examples, fixed vectors |
| Server unit and integration | `src/**/tests`, `src/net/tests/` | Real TLS/QUIC on loopback: website on H1/H2/H3, authentication and routing, padding, flow control, half-close, resets, quotas, certificate reload, ECH, NAT rebinding, multi-endpoint isolation |
| Client e2e (interop) | `src/net/tests/client_e2e.rs`, `cargo xtask interop --engine LIB` | The real client and Chromium engine against the real server: SOCKS5 and HTTP CONNECT over H2 and H3, 3 MiB and concurrent transfers, half-close in both directions, missing/duplicate/corrupt confirmations (no payload, then recovery on the same connection), wrong password (zero dials), untrusted CA, ECH accepted, stale ECH (H2 recovers via retry configs, H3 fails closed), UDP-blocked H3→H2 fallback, reconnection after a server restart. Ignored by plain `cargo test` because it needs the engine library; a static audit that the client has no transport or TFO code runs always |
| Client unit | `client/src` | Config validation, SOCKS5/HTTP CONNECT parsing and rejections, framing round trips in all modes, confirmation checks |
| ACME | `src/acme/`, `src/net/tests/acme_live.rs` | Synthetic Rust ACME CA and DNS provider: issuance, renewal, recovery, EAB rules, activation failures, controller panic (degrade and supervised restart) |
| xtask | `tools/xtask` | Vector reference, vendor source audit on clean checkouts, TFO audit, packaging, lab evidence oracles |

The server's test hooks are `#[cfg(test)]` only, so production builds cannot
enable them: a dial override that sends authenticated CONNECTs for public
names to a loopback origin, and a switch that makes the tunnel reply carry a
missing, duplicated or corrupt confirmation (for the client's interop tests).

### Laboratories (explicit)

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

### HTTPS differential experiment

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

### Measurements

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

### Network impairment

The NAT-rebinding test drives real encrypted QUIC through a relay that changes
its source port 7 times on one connection. Earlier work measured H3 receive
windows through a deterministic loss and delay relay. Kernel-level impairment
(`netem` loss, reordering, MTU reduction, address-family changes) has **not**
been run: it requires privileged network namespaces that were not available.

### Latest results

Dated results are kept in [reports/](reports/): the
[2026-11-23 refactor audit](reports/refactor-audit-2026-11-23.md) and the
engineering reports that follow it.
