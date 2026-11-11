# Implementation and validation checkpoint

## Current stage: correctness and maintainability refactor (2026-11-11)

The actual starting checkout was `work` at `da8ed48`, following local commits
`1379712` and repository baseline `d99433c`. The requested review baseline
`d0f6a082` is older; `bcf418e` had already corrected and consolidated many of its
findings. Initial uncommitted changes were the preceding stage's H3 performance
fixture/test entry and test-only HTTP helper. Nothing unrelated was reset.
This report covers the latest stage, not completion of every server milestone.

### Findings and implementation

- **Fixed:** reject deprecated 6to4 relay `192.88.99.0/24` in the central prefix
  table, including IPv4-mapped IPv6. Boundary and adjacent-address tests execute.
- **Fixed:** per-candidate synchronous UDP socket creation is replaced with a
  fresh interface snapshot at each admission boundary. Existing locked nix
  0.31.3 supplies safe getifaddrs; no new package version/backend or unsafe code.
  Eight blocking-job permits survive cancellation. Retained vectors cap at 4096
  addresses; lookup failure rejects admission. There is no TTL security cache.
  The cap bounds our vector, not getifaddrs' OS-provided allocation. Administrative
  interface changes can still race check-then-connect, as with the previous check.
- **Fixed:** successful ARI Retry-After was clipped to 24 hours. Preserve remote
  hints on success/error separately from order waits and certificate renew_at.
  Local fallback/recheck policy never shortens a representable remote wait.
- **Hardened:** retry scheduling preserves durable next_attempt; Manager account/
  order state assertions return explicit errors. TLS watcher error throttling
  uses Option instead of assuming Instant can always subtract 60 seconds.
  Structural assertions (fixed arrays, known path parents, bounds established by
  lookup) were retained; this is not a mechanical unwrap replacement.
- **Fixed diagnostics:** renewal stop/cleanup no longer formats arbitrary remote
  Problem bodies or URLs. Private health reports phase/liveness/reconciliation;
  full typed DNS/TCP/TLS/CA failure classification remains future work.
- **Restored validation:** one public `cargo xtask lab`, one private Python runner
  and suite definition, one authoritative result.json per run. No env.sh or
  parallel orchestration framework. Required crypto dependencies are checked
  before scenarios. Missing scenarios/captures, zero decoded packets, decoder or
  crypto failures, zero tests, failed baseline collection and original test exit
  codes cannot become successful evidence. Four oracle tests cover rejection.
- **Restored fixtures:** Pebble tests are cfg(test) under acme; the worker filter
  includes its actual module path. Loopback cleartext is no longer a production
  Http method. The pinned CA patch is test infrastructure, not a server dependency.
  Two instant-acme RetryState tests execute; vendor checksums/provenance updated.

**Already fixed, revalidated against current code:** endpoint-specific order 404
errors; checked Retry-After syntax/overflow and finalize/restore/refresh retention;
Preparing versus CreateUncertain DNS state; ownership/borrowed-record protection;
validation-aware cleanup; bounded certificate diagnostic prefix/hash/length;
separate publication, network TLS activation and diagnostic writes; shared H1/H2/H3
WebSocket leases; bounded LRU initialization outside cache locks; Bridge Drop
aborting owned drivers. Existing regressions execute, including actual H2/H3
rotation and mixed transport admission with half-close.

**Not applicable:** C++ fixed offer 0x02 does not conflict with configurable server
preferences: the server selects only offered capabilities. A new test covers
8/16 preferred records with sparse on/off. No wire revision, signing, ALPN,
production client, TLS backend or cryptographic construction changed.

### Corrected test oracles and evidence

The old ARI test required clipping the remote hint; it now requires preserving
it and proves the ARI endpoint was reached twice. An initial new assertion that
next_attempt remained zero was also wrong: restoring an account sets its short
local cooldown. The corrected assertion distinguishes that bounded cooldown from
leaking the century-long ARI delay into order scheduling.

DNS intent-cancel, Pebble barrier ordering, endpoint-stage assertions, fault-hit
checks and control-panic availability oracles were already corrected in the
restored bcf418e fixtures; their original incorrect variants were not reintroduced.

Failed experiments remain outside Git: `mona-refactor-acme` rejected missing
Python cryptography (Rust tests succeeded, required JOSE/CSR verification did
not run); `mona-refactor-acme-verified` rejected it at startup;
`mona-refactor-acme-crypto` preserved Rust exit 101 from the new wrong assertion
although all 58 capture analyses had no errors. The final run succeeded:
`/workspace/scratch/mona-refactor-acme-final/result.json`, 89 tests passed,
7 external Pebble tests ignored, 58 captures analyzed, 213 JWS signatures verified,
zero evidence errors. It used Python cryptography 50.0.0, tcpdump 4.99.5 and tshark
4.4.18. Tools were extracted outside the checkout from signed Debian repository
packages. The private artifact bundle SHA-256 is
`e49afc3fed79f6d3ab68ad750054659f76b91d95c2852ad199ce4e7809b603cf`.
Raw journals/keylogs are not committed or pushed.

### Ownership and file map

| Historical split | Current owner | Current-stage action |
| --- | --- | --- |
| acme/eab + account | acme/account.rs | retained existing consolidation |
| acme/state + store | acme/persist.rs | distinct journal/generation semantics retained |
| net/outbound + egress | net/egress.rs | fresh interface checks |
| site/forward + upstream | site/upstream.rs | private fixed-origin/public-forward policies remain distinct |
| site/generation + bridge | site/bridge.rs | existing single-flight, cooldown and Drop retained |
| network resolver | src/resolve.rs | shared bounded job owner reused |
| ACME aliases / CertificateSlot | crate-root aliases / Manager local bundle | network TLS slot remains shared and distinct |
| removed lab runner/fixtures | tools/acme-lab + acme/pebble.rs | restored one runner, no duplicate env/setup layer |

Counts use Git-listed paths (including intended new files), raw byte splitlines,
and no target/work/artifact directories. Dedicated test files are tests/*.rs,
*/tests/*.rs, */tests.rs and acme/{lab,lab_support,pebble}.rs. Other src/core Rust
files are the production-file bucket **including inline cfg(test) code**; these
are file-ownership counts, not a claim of pure production statement counts.
Tools, vendor and imported client are separate whole-tree buckets; generated
indexes are docs/*.json. Non-Rust documentation/configuration is excluded here.

| Bucket | d0f6a082 files/lines | Stage baseline da8ed48 | Current stage |
| --- | ---: | ---: | ---: |
| Production Rust files, including inline tests | 41 / 14571 | 38 / 15596 | 38 / 15711 |
| Dedicated test files | 12 / 10433 | 8 / 8547 | 10 / 9834 |
| Tools | 12 / 1655 | 6 / 970 | 9 / 1566 |
| Generated indexes | 5 / 46968 | 0 / 0 | 0 / 0 |
| Vendor | 474 / 204942 | 277 / 76255 | 277 / 76281 |
| Imported client | 0 / 0 | 58 / 7160 | 58 / 7160 |

The current stage does not claim earlier vendor/test deletion as simplification.
Production file count remains 38; restored executable validation adds files.
No further meaningful ownership boundary was merged solely to reduce a number.

### Commands actually executed

Linux x86_64, Rust 1.94.0 unless indicated. Logs are in ignored work/.

| Command | Observed result |
| --- | --- |
| `python3 tools/vectors/generate.py --check` | passed, independent fixed vectors unchanged |
| `cargo test --locked -p moon-naive-core` | 31 unit + 2 vector tests passed |
| `cargo test --locked -p moon-naive --lib deferred_order_wait_survives_restart` | 1 passed |
| `cargo test --locked -p moon-naive --lib mixed_h1_h2_h3_websocket_admission_holds_through_half_close` | 1 passed |
| `cargo test --locked -p moon-naive --lib ari_` | corrected oracle: 3 passed |
| `cargo test --locked -p moon-naive --lib acme_live` | 9 real activation/renewal tests passed; last TLS-watch-only rerun recorded below |
| `cargo test --locked --workspace` | 206 server + 31 core + 2 vectors + 1 packaging; zero failures; 16 external/slow tests ignored |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | passed |
| `cargo +1.89.0 check --locked -p moon-naive` | passed, including native dependencies; 2m46s |
| `cargo build --release --locked -p moon-naive` | passed; 1m20s before final TLS-watch-only adjustment |
| `cargo xtask audit-native` | passed; existing pins and BoringSSL 5.2.0 backend retained |
| `cargo test --manifest-path vendor/instant-acme/Cargo.toml --locked --no-default-features --features time,x509-parser --lib` | 2 RetryState tests passed; target moved outside vendor afterward (set CARGO_TARGET_DIR outside vendor for reproduction) |
| `cargo xtask lab --only oracles --run /workspace/scratch/mona-refactor-oracles-final` | 4 oracle tests passed |
| `cargo xtask lab --only acme --run /workspace/scratch/mona-refactor-acme-final --home /workspace/scratch/mona-lab-tools` | passed with crypto-capable Python selected on PATH; results above |

Interface-change regression was executed, not merely ignored:

```sh
unshare --user --map-root-user --net -- sh -c 'ip link set lo up;
  MONA_INTERFACE_TEST_NETNS=1 cargo test --locked -p moon-naive --lib \
  local_snapshot_observes_interface_addition_and_removal -- --ignored --exact \
  net::egress::tests::local_snapshot_observes_interface_addition_and_removal'
```

One test passed, observing actual add/delete of a loopback interface address.
The same bounded job implementation's cancellation regression executes normally.
CI now also runs evidence oracles and vendor RetryState tests. GitHub CI itself
is not reported passed merely because its workflow was edited.

### H3 measurements retained from the preceding stage

`cargo test --release --locked -p moon-naive --lib benchmark_h3_receive_windows
-- --ignored --nocapture --test-threads=1` passed all 12 configurations. Actual
QUIC, bounded 4096-datagram loopback relay, 128 KiB upload per stream, one sample
per configuration. RTT is injected relay delay, not measured Internet RTT; loss
is every 100th datagram in both directions, not random independent packet loss.
Configuration cap changes both maximum streams and derived receive window;
production defaults were not changed on the basis of this small experiment.

| RTT / loss | Active streams | cap100 / 4587B Mbps | cap32 / 14336B Mbps |
| --- | ---: | ---: | ---: |
| 0ms / none | 1 | 9.9105 | 38.0453 |
| 0ms / none | 8 | 59.5691 | 126.0877 |
| 20ms / none | 1 | 0.9481 | 4.5677 |
| 20ms / none | 8 | 6.4883 | 14.5771 |
| 80ms / every100 | 1 | 0.2711 | 1.2648 |
| 80ms / every100 | 8 | 1.9738 | 3.0103 |

CPU time was 0.01–0.44 seconds per case, process RSS 18,472–20,020 KiB. Both
include client, server and relay; they are not isolated server CPU/memory claims.
Payload/half-close and post-shutdown receive/admission ledger recovery were
checked. These short uploads do not establish sustained throughput, many-idle
scheduler scalability, independent user fairness or production memory bounds.
No irreversible QUIC credit reservation was multiplied or returned early.

### Operations and remaining acceptance

Start with `moon-naive check-config CONFIG`, `moon-naive check CONFIG`, then
`moon-naive serve CONFIG`. Initial issuance requires explicitly configured real
credentials/terms; none were used here. `moon-naive status CONFIG` reports current
certificate validation/expiry, process-bound renewal heartbeat and possibly stale
TLS-LOADED diagnostics; listeners require a real probe. Reload watches validated
CURRENT/ECH files every five seconds; failed replacement leaves the old generation.
ECH outer renewal is the operator's separate responsibility. SIGTERM stops
admission and drains within configured graceful_timeout_secs (default 300s);
systemd TimeoutStopSec is 360s. Preserve private journals/generations for restart
or rollback; never delete uncertain DNS intents to force progress.

Current-stage limitations: real Pebble scenarios are restored but not executed
here (no built patched Pebble/challtestsrv provided); build the documented pinned
external CA and run `cargo xtask lab --only pebble`. Required capture ACME suite
uses a controlled synthetic CA/provider, not Pebble or a public CA. No production
DNS, production certificates, deployment, merge, release publication or production
client development occurred. Detailed error taxonomy and full original server
acceptance (all resource/fairness stress and performance scenarios) remain open.
The original phases have executable protocol/lifecycle/policy coverage and release
validation, but must not be labeled fully production-ready from these results.

Final verification/archive/push observations are appended below after completion.

Final checks: `cargo xtask verify` passed (format, denied-warning Clippy, 206 +
31 + 2 + 1 executed tests, locked release). The final TLS watcher adjustment was
then checked with 9 real activation tests (23.66s), denied-warning Clippy (10.74s)
and locked release build (1m12s), all passed. These results replace earlier pending
build notes. Source archive validation and remote revision are recorded after
committing so packaging can enforce its clean tracked-worktree policy.
