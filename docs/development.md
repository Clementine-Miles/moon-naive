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
