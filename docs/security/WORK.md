# Security implementation evidence

Starting revision: `02c6bf5c3d67c054f8fef9eadbf9bc1ece8a5fa7` (main), clean tree,
identical to the supplied audit reference. No separate previous review report was
provided; findings below refer to the scenarios in the implementation request.
No production credentials, certificate orders, public DNS mutations or remote
repository writes are authorized or used.

## Baseline (2026-11-05)

Executed on Linux with Rust 1.99.1, libclang 19 and the existing same-source
BoringSSL build cache. Build, workspace tests, all-target Clippy with warnings
denied, formatting, and `cargo xtask audit-native` all exited 0, with `--locked`
where applicable. The workspace contained no first-party tests: the test exit
status supplies no functional evidence. `xtask verify` currently runs formatting,
lint and release build, not tests; it has not yet been run in this work.

## Findings and implementation dependencies

These are static findings unless an executed regression is recorded separately.
None is a demonstrated remote vulnerability.

| Scenario / status | Current location and trigger | Boundary, authentication, classification | Closing evidence |
|---|---|---|---|
| Cached dead bridge: confirmed | `net/site/mod.rs: Site::start`, `bridge.rs: Bridge::new`; either driver exits after successful OnceCell initialization | Shared H3 website/forward availability; anonymous website or authenticated forward; recovery defect | Driver death, single-flight replacement, cancellation, no replay and repeated replacement tests |
| Lost candidates: confirmed | `site/forward.rs: Origin::peer` retains first permitted address; `site/upstream.rs: Pool::peer` advances global cursor on retry | Upstream availability; authenticated forward or anonymous fixed-origin website; logic defect | Controlled multiple-address fallback, policy and pool isolation tests |
| Completed unusable order: confirmed | `acme/manager.rs: reconcile` validates before clearing order | Renewal availability after crash/late recovery; local controller state, no demonstrated remote trigger; operational defect | Persisted expired completed-order fixture, cooldown, storage failures and DNS ownership tests |
| Combined process/secrets: confirmed | `runtime.rs: Control::start` uses a thread and combined Config | OS privilege boundary; local compromise prerequisite; architectural hardening | Separate processes/configs and actual identity/permission checks |
| Independent outer issuance: unresolved implementation | Existing primary manager and `net/tls.rs` outer certificate files | ECH availability/identity; operational requirement | Two isolated identities, migration and provider failure tests |
| Read/check race: confirmed | `acme/state.rs: read_private`, `store.rs` metadata then open | Local filesystem trust; attacker able to mutate path; conditional risk | Opened-descriptor validation, trusted directory tests |
| Expiry/reload and retention: unresolved | `net/tls.rs`, `acme/store.rs` | New handshake validity and key retention; operational requirement | Advance clock without file change; atomic reload and retention tests |
| Reserved capacity: unresolved | `core/policy.rs`, `net/mod.rs` budgets | Anonymous vs authenticated availability; hardening requirement | Mixed streams, per-user limits, cancellation and saturation tests |
| Malformed H3 escalates to bridge loss: unresolved | `net/h3.rs`, `site/bridge.rs` | Shared connection availability, potentially anonymous | Valid isolated malformed framing reproduction; retain H2 protections |
| Vendor vulnerabilities: unresolved | pinned Pingora/instant-acme manifests and patch inventories | Depends on actual patch/path; no version-only conclusion | Explicit vendor tests, patch-by-patch upstream comparison |

Order of work: restore verification from `857ec949` (test-only deletion was
checked against current source); fix and exercise bridge recovery; address
selection and ACME terminal transitions; process/config/publication separation;
independent identities and activation; capacity and diagnostics; final integration.
Tests and fault boundaries precede broad architecture changes. Restored optional
external-client/capture tests remain opt-in and are not evidence until run.
