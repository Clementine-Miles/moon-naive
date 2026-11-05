# Vendor review scope

No upstream baseline or vendored source was changed in this work. Keep notices
and inventories intact. Root dependencies remain pinned to:

| Component | Baseline | Retained patch purpose / regression evidence |
|---|---|---|
| Pingora | `4487f7b2ab50f159e4a2cf4f6a6b813f61bb6e19` | See the existing [patch inventory](../../vendor/pingora/MOON-NAIVE-PATCHES.md): informational responses/trailers/upgrades (website wire tests); literal IP SAN verification and trust isolation (`evolution` tests); H1 header deadline and framing/trailer sanitization (ingress/website tests); optional compression backends and negotiation (website tests); generic errors (H1 tests); channel binding stream ID (authentication and transport tests). |
| instant-acme | `4a9b80fdc22f23ab39b78dfd20ff5d4c92938e52` | [Additive durable account-key API](../../vendor/instant-acme/MOON-PATCH.md), covered by restored account persistence/EAB tests and the isolated Pebble EAB lifecycle. |
| quiche | `925b225825e2188f8e58e359114150500557bf61` | No local source patch in this work; H3 handshake and framing tests exercise integration. |

`cargo xtask audit-native` checks baseline, vendor inventories and the resolved
normal dependency graph. BoringSSL remains the TLS implementation. Format types
from rustls-pki-types do not add a rustls TLS stack. Native build and actual local
H2/H3 tests link boring 5.2.0, boring-sys 5.2.0 and tokio-boring 5.0.0 with quiche.

This is not a complete advisory review. Whether upstream equivalents now exist
for every patch has not been verified; no claim of vulnerability absence follows
from the version numbers or successful graph audit. Standalone vendor-test
execution results and blockers are recorded in REPORT.md. Do not silently amend
vendored lockfiles or enable alternative production TLS backends to run them.

Development dependencies restored: tempfile (and fastrand transitively),
flate2's Rust backend and Tokio test-util. Existing runtime rustix now exposes
its fs feature on Unix for safe descriptor opening. The declared minimum Rust
version and documented targets are unchanged; only the available Linux compiler
was tested. No broad dependency upgrade was performed.
