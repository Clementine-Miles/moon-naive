# Refactor audit record — 2026-11-23

Baseline: branch `claude/moon-naive-production-refactor-4cy8vi` at `72106dd`
(identical to `main`), clean working tree, Rust 1.100.0. The workspace had the
server, core and xtask crates (about 33,000 lines of Rust). It also held an
experimental Chromium-based client (C++/Kotlin/Python) outside the Cargo build,
and vendored Pingora and instant-acme trees with documented patches.

## Baseline results

| Check | Result |
| --- | --- |
| Debug build (workspace, all targets) | pass (≈2 min cold) |
| `cargo fmt --check`, `cargo clippy -D warnings` | pass |
| `cargo test --workspace` (server lib) | 231 passed, 17 ignored, 3 failed |

The three failures (`explicit_ipv6_tcp_does_not_claim_ipv4_port`,
`explicit_ipv6_udp_does_not_claim_ipv4_port_and_duplicates_fail`,
`candidate_fallback_in_both_address_family_orders`) are environmental: the
container kernel returns `EAFNOSUPPORT` for IPv6 sockets. They are unchanged.

## Confirmed defects and fixes

| # | Location | Observed behavior | Risk | Fix | Regression test |
| --- | --- | --- | --- | --- | --- |
| 1 | `src/net/tls.rs` (server QUIC config); quiche `on_peer_migrated` and `make_room_for_new_path` | A second passive NAT rebinding stalled an H3 connection: the old path keeps the shared DCID, is never evicted, and the path table was capped at the default `active_connection_id_limit` of 2 | Mobile and NAT clients lose H3 connections repeatedly | Bounded limit raised to 8 (7 rebindings per connection); active migration stays disabled | `h3_nat_rebinding_consumes_path_events_and_preserves_session` now rebinds 7 times (reproduced the stall at 2 before the fix) |
| 2 | `core/src/config.rs` `validate`; `src/acme/manager.rs` `Manager::open`; `src/acme/account.rs` `restore_or_create` | Google issuer configurations without EAB were rejected even when the journal already held the account | A restart after removing a used, single-use EAB failed | EAB is required only when no account is persisted; key-only journals recover by key lookup, and EAB is needed only if the account does not exist | `acme::tests::existing_account_recovers_without_original_eab`; updated config test |
| 3 | `src/runtime.rs` `serve_with` | After startup, a stopped renewal controller (error or panic) left the process serving forever without renewal; `Restart=on-failure` never triggered | Certificate silently expires | Supervised restart: after joining the thread, reopen a fresh `Manager` from the journal with backoff (60 s → 1 h, reset after 1 h healthy) | `acme_control_panic_is_restarted_by_supervisor`, `renewal_restart_backoff_doubles_and_is_capped` |
| 4 | `src/acme/health.rs` `Worker::pulse` | The ephemeral heartbeat was fsynced (file and directory) on every pulse, about twice per second (the control loop pulses every iteration) | ≈170k needless fsyncs per day; flash wear and latency | Atomic replace without fsync; unchanged content is rewritten at most every 5 s | `stopped_reused_pid_and_stale_heartbeat_never_report_running` (extended) |

## Investigated, not defects

- **TCP Fast Open:** no project-owned use. Matches were legacy config-key
  rejection and proxy-header stripping. Vendored Pingora contains opt-in TFO
  helpers that are unreachable without options this project never sets. A
  static audit and a socket assertion were added.
- **ECH lifecycle:** inner and outer material load into one immutable TLS
  generation; an expired outer certificate gates new handshakes without
  blocking inner reloads (existing tests). The client now has ECH e2e tests.
- **Certificate hot swap:** invalid material is rejected and the last valid
  generation stays active (existing activation tests).
- **Wire naming:** "revision 4" occurrences were human-readable. Protocol
  labels were kept byte-identical (vectors verified).

## Changes beyond fixes

- Naming: Moon-naive / mona / Rupin in CLI output, documentation, report
  schema and named constants. No wire bytes changed.
- New `moon-naive-client` crate with 11 unit tests and 9 end-to-end tests
  against the actual server.
- Removed the Chromium-based client (6,926 non-Rust lines) and an unverified,
  stale root `SHA256SUMS`.
- `cargo xtask audit-tfo` (also in `verify` and CI); CI builds both binaries.
- Documentation consolidated from Chinese `PROJECT.md` into English
  `docs/*.md`; the server example configuration was translated with identical
  parsed values.

## Not done, with reasons

- Kernel `netem` impairment, Pebble/capture laboratories, the Caddy
  differential, public CA issuance and fuzzing campaigns were not run (they
  need privileges, external binaries or credentials). Earlier recorded results
  are in Git history and `docs/reports/`.
- No server data-path optimization was attempted: there was no profile
  evidence of a bottleneck for the small deployment, so no server performance
  improvement is claimed. Client throughput is recorded in
  [development.md](../development.md#measurements).
- Full QUIC CID rotation and path cleanup (beyond the bounded limit) would
  require multi-CID routing; active migration stays disabled.
- ECH key rotation is operator-driven (`ech init/check/dns` plus DNS TTL
  overlap) rather than an automated state machine.

## Test results of the refactor

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
