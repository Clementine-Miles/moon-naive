# Development

## Layout

```
src/            server (moon-naive): runtime, CLI, net/, acme/
core/           pure protocol, policy and configuration logic (moon-naive-core)
client/         first-party client (moon-naive-client)
tools/xtask/    verification, audits, laboratories, packaging (cargo xtask …)
vendor/         locally patched Pingora and instant-acme (see their patch notes)
deploy/         systemd and OpenRC units
docs/           this documentation; reports/ holds dated experiment evidence
```

`cargo build` builds the server and client (the workspace's default members).
Run `cargo xtask verify` before submitting changes. The workspace forbids
`unsafe` code.

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
5.5.0. Production features disable other TLS backends;
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
| `core/tests/vectors/*.tsv` | Test fixtures | Required; independent known answers |
| `assets/*.crt` | Test and staging trust roots | Required for staging and laboratory trust |
| `docs/**`, `README.md` | Documentation | Required |
| `LICENSE`, `licenses/*` | Legal texts | Preserved verbatim |
| `tools/analyze.py` | Laboratory oracle (Python `cryptography`) | Kept on purpose: an independently implemented JWS/CSR/EAB verifier for captures, so laboratory evidence does not depend on the code under test. Never part of build or runtime |
| `tools/pebble.patch` | Patch for the external Go test CA | Kept: the test CA is external; no Go enters the repository or product |
| `.gitignore`, `.gitattributes` | Repository metadata | Required |

The 2026-11-23 refactor removed the experimental Chromium-based client
(`client/naiveproxy`: C++, GN, Kotlin and Python, 6,926 lines) in favor of the
Rust client. Native code that remains is BoringSSL (C/C++ and assembly, built
by `boring-sys`). It was kept deliberately: it provides ECH, TLS exporters and
quiche integration, and replacing it would raise risk without a security
benefit.

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
cargo xtask source /outside/source HEAD
```

`source` packages only committed bytes of an explicit revision (rejecting
dirty trees, symbolic links and submodules), preserves executable bits,
records `SOURCE_REVISION`, and writes `SHA256SUMS` for the archive. Checksums
prove snapshot integrity, not correctness. Release inventories list normal
and build dependencies with their licenses. `licenses/` keeps the musl, GCC
runtime (with GPL-3.0) and Rust license texts for static musl releases.
