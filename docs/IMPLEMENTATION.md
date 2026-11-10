# mona server implementation checkpoint

This is an execution record, not a production-readiness claim.

Baseline: `d99433c5b4f939a1f42db14d405566390f3a7e3f`, local branch `work`,
clean tracked/untracked worktree at task start. No repository AGENTS.md.
Linux x86_64; provisioned Rust 1.94.0. Declared MSRV 1.89 awaits validation.
Pins: Pingora 4487f7b2 (local patches), instant-acme 4a9b80fd (local patches),
quiche 925b2258 (Git), boring/boring-sys 5.2.0.

## Ordered checklist

- [ ] Phase 1: restore meaningful tests, independent vectors, authoritative protocol, CI/MSRV.
- [ ] Phase 2: incomplete H3 headers, retry accounting, duplex/admission, HTTP semantics.
- [ ] Phase 3: forward policy/quotas, bounded cache, resolver/next-hop ownership.
- [ ] Phase 4: renewal health, control dial deadlines, DNS reconciliation, reload/shutdown.
- [ ] Phase 5: measured H3 window/scheduler changes and reproducible performance checks.
- [ ] Phase 6: tracked-revision source packages, operations docs, full locked validation, push.

## Confirmed baseline findings

- Root/core tests and doctests disabled; first-party tests removed by b242494.
- No root CI; xtask verify performs fmt/clippy/release compilation only.
- H3 header timer starts at TLS handshake, with no incomplete-header deadline after establishment.
- Website request_body_filter accumulates replay bytes on retries.
- Source packaging selects untracked files and walks vendor working directories.
- Forward policy/cache, ACME control dialing and H3 window findings: inspection pending.

## Work and evidence

Restoring deterministic first-party core and loopback server tests from bcf418e,
checking them against current production paths. Test-only resolver/transport hooks
remain behind cfg(test); no production authentication/egress bypass is introduced.
Imported Chromium client and live public issuance tests are excluded.
Restoration adds tempfile/fastrand only to the locked development graph.

Commands and outcomes will be recorded here as checks finish. Logs are in ignored
`work/`; failures and ignored benchmarks are not passing acceptance evidence.

## Checkpoint: restored validation and first correctness/policy changes

Implemented:
- Enabled core/server/xtask tests and doctests, restored first-party tests from
  bcf418e including synthetic ACME activation fixtures; added root CI and tests
  to xtask verify. No application unsafe-code relaxation or production bypass.
- Added authoritative PROTOCOL.md, independent Python-generated TSV vectors,
  H3 stream-zero authentication, malformed encoding and codec fragmentation tests.
  Revision 4 is unchanged: received padding octets may be nonzero; encoder uses zeros.
- H3 tracks incomplete request headers before h3.poll consumes partial bytes,
  with a 10-second absolute deadline, client-bidirectional IDs only, bounded map.
  Expiry closes the connection with 0x107 to release parser state; sends close
  without waiting for further traffic. Control streams are excluded. Unrelated
  requests progress before expiry. Completed/reset requests clear the deadline.
- Retry upload limits use Pingora's downstream body_bytes_read, which excludes
  replay. attempted_upload separately counts bytes offered across attempts.
- Ordinary forwarding uses independent proxy.forward policy (1 GiB streaming
  upload, 10s connect, 120s read/write, 30s pool idle, 32 requests per user).
  Existing configs adopt these defaults rather than inheriting website settings.
  Active forwards share global tunnel admission, with separate per-user budgets.
- Forward cache: 128-entry LRU, lazy 300-second TTL, per-key async OnceCell,
  blocking initialization outside cache locks, job-owned initialization permits.
  Eviction does not terminate active exchanges. Shutdown clears cache; bridge
  shutdown remains shared. TTL is lazy, not a background eviction guarantee.
- Default test DNS is a cfg(test) deterministic fixture; no external resolver is
  contacted. Numeric loopback services and synthetic CAs remain verified normally.
  The explicitly ignored system-DNS namespace experiment uses ACME_LAB_DNS_LISTEN.

Completed validation (Linux x86_64):
- cargo +1.89.0 test --locked -p moon-naive-core --target-dir work/msrv-target:
  30 unit + 2 independent-vector tests passed.
- cargo +1.89.0 check --locked -p moon-naive --target-dir work/msrv-target:
  passed before Phase 3 changes; final MSRV rerun still required.
- Restored baseline cargo test --locked -p moon-naive --lib -- --test-threads=4:
  189 passed, 7 explicitly ignored experiments/benchmarks, 132.90s.
- retry_body_limit: full and partial replay of 600 bytes under 1024-byte limit passed.
- h3_partial_headers: absolute deadline with continuing normal requests passed.
- h3_fragmented_headers: bytewise headers, reset cleanup and later request passed.
- forward filter: 5 passed, 1 benchmark ignored (cache and HTTP/HTTPS forwarding).
- acme_live filter: 9 passed, including actual control-worker panic, invalid renewal,
  two renewals, existing H2/H3 connections, ECH expiry/recovery and persistence faults.
- Full workspace tests, Clippy and locked release build launched; consult
  work/full-tests.log, work/clippy.log, work/release.log for final results.

Remaining acceptance work (do not mark complete):
- Phase 1: final CI/xtask execution, native dependency audit, stale manual claims.
- Phase 2: additional upload boundary and upstream H2 retry regressions, complete
  HTTP semantic coverage audit; restored tests are evidence only for named cases.
- Phase 3: transport-level per-user forward fairness/cancellation tests, cache pool
  connection/task recovery measurements, egress parsing audit and limits table.
- Phase 4: private worker heartbeat/process identity and error classification;
  control_socket still calls sequential TcpStream::connect(addresses); distinguish
  confirmed externally deleted DNS record from uncertain creation. Existing
  activation/reconciliation tests do not establish these new requirements.
- Phase 5: no H3 window changes or throughput/RTT/loss measurements yet. Historical
  default 4587-byte maximum remains; scheduler still allocates packet buffers/scans.
- Phase 6: source packaging still includes untracked files and walks vendor;
  fix selection before creating a release. Update provenance/checksums/docs and
  create final report, coherent commits, then push as authorized by user.

No release, production DNS/certificate action, deployment or push has occurred.

Follow-up: restored synthetic activation suite now passes all 9 cases. The first
attempt exposed fixture dependence on external DNS and a 3-second fixture QUIC
idle timeout; fixed deterministic test resolver inputs and set the incomplete-
header fixture idle timeout to 30 seconds (production timeout unchanged).
Control HTTP dial now shares bounded two-candidate racing with 2-second attempts,
250ms stagger and a 10-second dial ceiling, within the existing overall HTTP
request deadline. This supersedes the sequential-control-dial remaining item above;
its dedicated regression/final validation still needs completion.
Remote read check: origin/main remains baseline d99433c. Push is authorized but
has not occurred; do not describe this checkpoint as the finished server milestone.

Latest full workspace result: 203 server tests + 30 core unit tests + 2 independent
vector tests passed; 0 failed; 7 explicitly ignored. Server portion 129.14 seconds.
Empty binary/xtask/doctest targets are not counted as runtime evidence.
Shared dialer/next-hop targeted regressions: 8 passed, 3 benchmarks ignored.
Formatting and git diff --check passed. Final Clippy/release results remain in
work/clippy.log and work/release.log (running at this checkpoint).
Initial Clippy found two test-only style issues (redundant pending closure and
identical timeout branches); corrected without changing behavior. Rerun output:
work/clippy-final.log. Release build is still running; do not record it as passed.

## Continued work after 1379712

Confirmed previous final Clippy passed (16.42s) and locked Linux x86_64 release
build passed (1m08s). New changes:
- Private renewal WORKER observation with process start/boot binding, monotonic
  heartbeat, stop/panic state, next attempt and per-run last installation success.
  Existing CLI status separates these observations from certificate readiness.
- Confirmed externally missing/modified TXT records require reconciliation;
  uncertain-creation semantics remain conservative, no automatic recreation.
- Source snapshots now use resolved Git commit objects, reject dirty tracked
  files, symlinks/submodules; exclude untracked files, preserve executable bits,
  record revision and generate archive/content checksums.

Validation: xtask packaging fixture passes (including untracked vendor secret,
executable bit, dirty input, committed symlink and checksum checks); native graph
and vendor checksum audit passed. Health identity/stale-state/symlink test passed.
Confirmed-record unit test passed. ACME suite and worker activation regression
results: work/acme-next.log and work/health-live-tests.log. Clippy after changes:
work/clippy-health.log. These logs must be checked before marking final success.

Remaining: detailed sanitized transport/ACME failure classes (currently phase),
additional fairness/retry acceptance tests and resource measurements, H3 performance
harness/comparisons and justified window policy, final MSRV/release/full-suite run,
source-archive smoke validation at committed revision, final acceptance report and
GitHub push. None of these are implied complete by the restored regression count.

Verified continued-work results: ACME suite 88 passed/0 failed (127.11s), actual
worker/activation suite 9 passed/0 failed (23.29s), health and confirmed-record
tests passed, Clippy -D warnings passed (15.84s), fmt and diff --check passed.
