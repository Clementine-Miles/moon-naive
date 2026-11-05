# Security implementation report — partial delivery

This is a reviewable implementation, **not completion of the full requested
security program or a production-readiness claim**. The remaining architecture
work below is unimplemented, not blocked by missing production credentials.
No push, release, production deployment, real CA order or public DNS modification
was performed. Network operations were source/dependency retrieval; operational
tests used loopback fixtures.

## Revision and scope

Start: `02c6bf5c3d67c054f8fef9eadbf9bc1ece8a5fa7`, clean `main`, exactly the
supplied audit reference. Code changes are the local commits listed below;
the final report/checksum commit is available with `git log -1`. The report's
final revision is therefore the commit containing this file, not a remote release.

Inspected manifests/lockfile, deleted test history, bridge and upstream paths,
ACME account/order/DNS/storage/validation, runtime lifecycle, TLS, budgets,
CLI/deployment documentation and vendor patch inventories. This was not an
exhaustive line-by-line audit of all vendored or protocol source. The supplied
request contained scenarios, but no separate detailed previous review report.
The [baseline matrix](WORK.md) records evidence classification and triggering
conditions. All confirmed findings are logic/operational defects or conditional
local filesystem risks; **no remotely exploitable denial of service was
reproduced or claimed**.

## Per-task acceptance status

| Task | Status | Delivered / remaining acceptance gap |
|---|---|---|
| 0 baseline | Partial | Actual revision, clean tree, baseline commands and findings matrix recorded before fixes. Exhaustive review of every requested component remains incomplete. |
| 1 verification | Partial | Restored 136 previously passing first-party tests and added 10 new tests plus assertions in an existing certificate test; guarded critical suites against zero passing tests. Full new-architecture fault-injection matrix, property/fuzz targets remain absent. |
| 2 H3 bridge | Partial | Replaceable healthy generations, bounded admission/construction, one-second backoff, cancellation, shared shutdown token, no replay, length validation and regression tests. No valid external H3 exploit reproduction; full malformed-wire/reset/replacement stress matrix remains incomplete. |
| 3 address selection | Partial | Retained validated TCP candidate vectors, two-attempt family fallback for CONNECT/forward/site/WebSocket, stable origin retry selection, fixed-origin self filtering, original SNI and existing pool isolation. One overall DNS+TCP+TLS deadline and TLS-handshake candidate fallback are not fully implemented. |
| 4 ACME recovery | Partial | Validated obsolete download classification, durable bounded retirement diagnostic and cooldown, account/DNS preservation, descriptor checks. Unit retirement and local lifecycle tests pass. Complete CA-response/disk-full/crash fault matrix for the new branch remains incomplete. |
| 5 process split | Partial — inspection only | Existing controller thread and combined config remain. No independent OS identities, publication ACL boundary or permission matrix implemented. |
| 6 dual identities | Partial — inspection only | No new independent outer-certificate manager or state migration. Existing manual outer certificate and HPKE operations remain. |
| 7 activation/expiry | Partial — inspection only | Existing snapshot/storage tests restored. No new coherent dual-identity activation acknowledgement, timed outer-expiry gating or retention GC. |
| 8 reservations | Partial — inspection only | Existing budgets and cancellation tests inspected/restored. No authenticated reservation or new per-user accounting implemented. |
| 9 vendor | Partial | Pins, patch inventory and native graph checked; seven instant-acme unit tests executed. Pingora standalone suite blocked by absent reproducible lockfile; full upstream-equivalence review outstanding. |
| 10 diagnostics | Partial — inspection only | No new rate-limited structured events, restricted status files or side-effect-free status CLI. No management listener added. |
| 11 integration/docs | Partial | Current behavior and limitations documented; build/tests/lint/release verification pass. No end-to-end verification of the unimplemented process/dual-identity architecture, cross-target validation or production deployment. |

## Implementation details and semantics

- [`Generations::get`](../../src/net/site/generation.rs): semaphore bounds waiting
  requests by configured max streams; mutex serializes construction; acquisition
  and construction share a three-second deadline. A cancelled/failed constructor
  still enforces a one-second cooldown. Only the current generation is cached.
  Shutdown is shared with forward sites, including newly created sites.
- [`Bridge::healthy`, `exchange`, `BodyLength`](../../src/net/site/bridge.rs):
  both driver handles and a watch channel expose termination; driver drop/abort
  wakes exchanges. Failure cancels the exchange, never resubmits it. Content-Length
  overrun/underflow is rejected before invalid DATA/end reaches shared H2 parsing.
  Existing H2 protocol protections remain enabled. New requests may fail during
  cooldown and must be retried by the client according to its own semantics.
- [`Egress::dial_candidates`](../../src/net/egress.rs),
  [`Origin::peer`](../../src/net/site/forward.rs),
  [`Pool::peer`/`ResolvedConnector`](../../src/net/site/upstream.rs): connection
  attempts use concrete validated addresses, keeping logical SNI separate.
  At most two TCP dials run concurrently, with at most 32 candidates. DNS limits
  and egress policies remain separate for fixed origins and arbitrary targets.
  Existing request replay policy was not broadened. A native Pingora TCP stream
  is retained for fixed origins so pooling and readiness checks keep working.
- [`Validator::download`](../../src/acme/certificate.rs) validates obsolete
  results at a time within the leaf's lifetime, including SAN, private-key match,
  chain and server usage. That path returns an obsolete lifetime, **never an
  installable expired bundle**. If historical chain validation fails, the order
  remains for investigation. `verify` for activation still requires current time.
- [`Manager::reconcile`](../../src/acme/manager.rs) and
  [`Journal::retire_completed`](../../src/acme/state.rs) retire a verified obsolete
  completed order before any new order. Persisted cooldown is at least one hour,
  also respecting configured max retry and observed Retry-After. One bounded
  diagnostic contains order-URL hash, timestamp, expiry and reason; obsolete
  private key is discarded. Account and DNS lease state survive. Persistence
  failure suspends the manager; temporary installation failures keep the order.
- `state::open_private`, `validate_private`, and
  [`store::read_bounded`](../../src/acme/store.rs) validate opened descriptors,
  reject final-component symlinks/FIFOs, bound reads and preserve owner-only
  permissions. Parent directory ancestry is still a trusted boundary; this is
  **not** a full directory-FD-based publication design.

No authentication transcript, proof, padding negotiation or protocol mode was
changed. H1, H2/H3, CONNECT, forwarding, website/WebSocket and existing ECH code
remain present. Passing local tests does not establish every client combination.

## Executed evidence

Environment: Linux GNU, Rust 1.99.1, libclang 19, existing matching BoringSSL
build cache; Pebble v2.8.0 and local challtestsrv. Full command logs are in
`/tmp/moon-security-evidence/` in this workspace. Build setup used the existing
`/workspace/.moon-naive-tools/activate.sh`, libclang/GCC include paths, and
BORING_BSSL_PATH/BORING_BSSL_INCLUDE_PATH pointing at the same-source cache.

| Command / check | Observed result |
|---|---|
| Baseline build/test/Clippy/fmt/audit | All exited 0; test suite had no first-party tests and supplied no functional evidence. |
| Restored `cargo test --workspace --locked` | 136 passed, 11 ignored. Initial restored `--locked` attempt required updating dev-dependency lock entries; offline resolution then succeeded. |
| Final `cargo build --workspace --locked` | Passed. |
| Final `cargo test --workspace --locked` | 146 passed: 115 main library, 29 core, 2 CLI; 11 ignored. Main library duration 19.48 s. Empty binary/doc suites are not counted as evidence. |
| `cargo xtask verify` | Passed critical nonzero test suites, fmt, all-target Clippy, release build (1m32s), generated-private-config CLI and incomplete-setup rejection checks. |
| Final all-target Clippy `-- -D warnings` and `cargo fmt --all -- --check` | Passed. |
| `cargo xtask test-isolated` with local Pebble environment variables | 2 passed, final run 8.42 s; issuance, readiness, renewal, EAB restart, account recovery and DNS outage. Not a dual-identity test. |
| Actual bridge driver termination / POST regression | 1 passed; three actual bridge generations and three origin POSTs, successful recovery, old weak references released. |
| Bounded generation replacement | 1 passed in 0.01 s; 64 generations, 16 concurrent acquisitions each, exactly 64 constructions, old generation references released. Paused clock, not a duration soak or OS task/RSS measurement. |
| Single configured origin, multiple candidates; opposite IP-family fallback | Passed using local listeners and closed local ports. No public targets used. |
| `cargo xtask audit-native` | Passed after moving generated vendor test target artifacts outside the vendor inventory. No vendored source changed. |
| instant-acme standalone locked unit suite, no defaults, time/x509-parser | 7 passed after fetching missing development packages. Production features unchanged. |

Intermediate failures were used rather than concealed: a virtual-stream wrapper
broke four origin pool/keepalive tests; returning Pingora's native TCP stream fixed
them and the full suite passed again. Two Clippy redundant-closure errors were
fixed. The first attempted new bridge test selected zero tests after a failed edit;
that was not counted. The subsequent real test ran one named test and passed.

## Unexecuted checks and constraints

- Standalone Pingora command with `boringssl` and `--locked` cannot create its
  absent `vendor/pingora/Cargo.lock`. Root-package invocation also reports that
  this excluded package requires dev-dependencies and is not a workspace member.
  Offline attempts additionally lacked document-features; online retry confirmed
  the lockfile issue. No standalone Pingora test success is claimed. Its runtime
  integration is exercised by first-party wire tests.
- Optional external browser/client, packet capture and benchmark tests remain
  ignored. Their tools/workloads were not provisioned or executed in this work.
- No 24-hour soak, OS task/RSS leak measurement, throughput comparison, fuzz run,
  musl/container smoke, alternate target or MSRV 1.89 compilation was performed.
- No tests can verify the unimplemented process split, dual identities, publication
  permissions, activation acknowledgements, resource reservations or status CLI.
  These are implementation gaps, not external environmental blockers.

## Configuration, deployment and vendor consequences

No new live domains or credential mappings were invented. Existing configuration
continues to run the embedded control thread; operators must not infer privilege
separation. Existing ECH outer certificate provisioning, HPKE rotation and
HTTPS/SVCB publication remain manual. There is no automated ECH downgrade.

Journal migration is additive via optional `retired_order`, preserving account,
orders and leases on read. Older binaries reject the new field; downgrade requires
explicit state-format handling, not journal deletion. All private files remain
owner-only; narrowly group-readable publication is not implemented. Parent
state/secret directories must remain administrator-controlled.

See [deployment consequences](../VPS-GUIDE.md), [test instructions](../VERIFICATION.md)
and [vendor record](VENDOR.md). No upstream refresh occurred. Restored dev-only
packages are tempfile/fastrand, flate2 Rust backend and Tokio test-util; runtime
rustix exposes safe filesystem flags on Unix. Lockfile changes are limited to
the restored development packages. The declared MSRV and targets were not raised.

## Reviewable patch sequence

1. `2f9da48` — baseline and finding/work plan.
2. `58be4ce` — historical first-party test restoration and dev dependencies.
3. `2a8ef0b` — replaceable bridge generations, length checks, shutdown and tests.
4. `06163fa` — retained concrete TCP candidates and origin retry selection.
5. `c3aa7be` — completed-order retirement and opened-file validation.
6. Subsequent local verification/documentation commit — nonzero suite guard,
   refined replacement regression, current instructions, this report and inventory.

Performance-sensitive changes are candidate racing, bridge admission/locking and
file metadata checks. No throughput claim is made. Reproduce existing ignored
benchmarks with `cargo test --release --locked benchmark_ -- --ignored --nocapture
--test-threads=1` only in the documented isolated environment; compare matching
hardware/configuration and separate any test fixture setup from measurements.
