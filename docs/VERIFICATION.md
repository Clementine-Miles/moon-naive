# 验证范围

当前正确性修复、模块合并、测试判据和隔离实验结果见 [ACME-LAB.md](ACME-LAB.md)。本页下方旧提交的执行记录只作历史证据，不代表本轮检查结果。

已恢复 `857ec949` 中仍适用的第一方测试，并增加桥接恢复、地址回退、订单退役和文件读取回归测试。历史执行结果和未完成项见下方[安全实施记录](#安全实施记录)。测试通过不等于生产部署验收。

## 可重复检查

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo xtask test
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
cargo xtask audit-native
cargo xtask verify
```

`xtask test` 分别执行 core、ACME、网络和 CLI 套件，每组必须至少有一项通过；零测试视为失败。普通 workspace 测试还覆盖运行时、信任根和文档测试。`verify` 在本机执行这些关键套件、格式、Clippy、Release 构建和 CLI 冒烟检查；指定交叉编译 target 时不执行目标二进制测试。

## 测试类别

- 纯单元：认证绑定、头部清理、帧解析、地址策略、配置和证书验证。
- 确定性状态/故障：`site::bridge::generation_tests` 使用暂停时钟验证重建、取消、冷却和截止时间；ACME 测试验证持久化、DNS 所有权及退役。
- 本地传输：`net::tests` 使用临时 CA 和回环源站覆盖 H1/H2/H3、WebSocket、CONNECT、转发、取消及连接池隔离。生产代码无回环白名单开关。
- 隔离 ACME/DNS：`tests/acme_pebble.rs` 启动本地 Pebble 和 challtestsrv，覆盖签发、EAB、重启、更新和 DNS 故障。
- 可选：外部浏览器/客户端、抓包和微基准默认忽略。未提供的新模糊测试及长期 soak 不算已验证。

```sh
export PEBBLE_SOURCE=/path/to/pebble-source
export PEBBLE_BIN=/path/to/pebble
export CHALLTESTSRV_BIN=/path/to/pebble-challtestsrv
cargo xtask lab --run /absolute/path/outside-checkout/run-id
```

本次使用 Pebble v2.8.0。隔离套件不访问公网 DNS 或真实 CA。测试工具属于开发环境，不进入运行时依赖。显式 lab 入口要求抓包和独立协议验证，工具发现、可选 bootstrap 及工件说明统一见 ACME-LAB；普通测试不强制抓包。

## 验证边界

本轮仅验证 Linux GNU 主机；未验证 musl 镜像、其他目标、声明的最低 Rust 版本、真实域名部署、长期稳定性或吞吐。历史抓包摘要 [packet-lab-results.json](packet-lab-results.json) 不代表当前版本测量。独立控制进程、双证书自动管理及容量预留尚未实现，不能宣称完成安全重构。


## 安全实施记录

This is a reviewable implementation, **not completion of the full requested
security program or a production-readiness claim**. The remaining architecture
work below is unimplemented, not blocked by missing production credentials.
During that implementation pass no push, release, production deployment, real CA
order or public DNS modification was performed. Operational tests used loopback
fixtures. Later documentation consolidation and repository synchronization do not
constitute a new security acceptance or a rerun of the historical tests.

### Revision and scope

Start: `02c6bf5c3d67c054f8fef9eadbf9bc1ece8a5fa7`, clean `main`, exactly the
supplied audit reference. The tested implementation ended at
`486b416f28464f35a46dad09fd76a90d7841e307`. The evidence below belongs to that
implementation pass; later documentation commits do not change its scope.

Inspected manifests/lockfile, deleted test history, bridge and upstream paths,
ACME account/order/DNS/storage/validation, runtime lifecycle, TLS, budgets,
CLI/deployment documentation and vendor patch inventories. This was not an
exhaustive line-by-line audit of all vendored or protocol source. The supplied
request contained scenarios, but no separate detailed previous review report.
The [baseline matrix](#基线发现) records evidence classification and triggering
conditions. All confirmed findings are logic/operational defects or conditional
local filesystem risks; **no remotely exploitable denial of service was
reproduced or claimed**.

### Per-task acceptance status

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

### Implementation details and semantics

- [`Generations::get`](../src/net/site/bridge.rs): semaphore bounds waiting
  requests by configured max streams; mutex serializes construction; acquisition
  and construction share a three-second deadline. A cancelled/failed constructor
  still enforces a one-second cooldown. Only the current generation is cached.
  Shutdown is shared with forward sites, including newly created sites.
- [`Bridge::healthy`, `exchange`, `BodyLength`](../src/net/site/bridge.rs):
  both driver handles and a watch channel expose termination; driver drop/abort
  wakes exchanges. Failure cancels the exchange, never resubmits it. Content-Length
  overrun/underflow is rejected before invalid DATA/end reaches shared H2 parsing.
  Existing H2 protocol protections remain enabled. New requests may fail during
  cooldown and must be retried by the client according to its own semantics.
- [`Egress::dial_candidates`](../src/net/egress.rs),
  [`ForwardOrigin::peer`](../src/net/site/upstream.rs),
  [`Pool::peer`/`ResolvedConnector`](../src/net/site/upstream.rs): connection
  attempts use concrete validated addresses, keeping logical SNI separate.
  At most two TCP dials run concurrently, with at most 32 candidates. DNS limits
  and egress policies remain separate for fixed origins and arbitrary targets.
  Existing request replay policy was not broadened. A native Pingora TCP stream
  is retained for fixed origins so pooling and readiness checks keep working.
- [`Validator::download`](../src/acme/certificate.rs) validates obsolete
  results at a time within the leaf's lifetime, including SAN, private-key match,
  chain and server usage. That path returns an obsolete lifetime, **never an
  installable expired bundle**. If historical chain validation fails, the order
  remains for investigation. `verify` for activation still requires current time.
- [`Manager::reconcile`](../src/acme/manager.rs) and
  [`Journal::retire_completed`](../src/acme/persist.rs) retire a verified obsolete
  completed order before any new order. Persisted cooldown is at least one hour,
  also respecting configured max retry and observed Retry-After. One bounded
  diagnostic contains order-URL hash, timestamp, expiry and reason; obsolete
  private key is discarded. Account and DNS lease state survive. Persistence
  failure suspends the manager; temporary installation failures keep the order.
- `state::open_private`, `validate_private`, and
  [`persist::read_bounded`](../src/acme/persist.rs) validate opened descriptors,
  reject final-component symlinks/FIFOs, bound reads and preserve owner-only
  permissions. Parent directory ancestry is still a trusted boundary; this is
  **not** a full directory-FD-based publication design.

No authentication transcript, proof, padding negotiation or protocol mode was
changed. H1, H2/H3, CONNECT, forwarding, website/WebSocket and existing ECH code
remain present. Passing local tests does not establish every client combination.

### Executed evidence

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

### Unexecuted checks and constraints

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

### Configuration, deployment and vendor consequences

No new live domains or credential mappings were invented. Existing configuration
continues to run the embedded control thread; operators must not infer privilege
separation. Existing ECH outer certificate provisioning, HPKE rotation and
HTTPS/SVCB publication remain manual. There is no automated ECH downgrade.

Journal migration is additive via optional `retired_order`, preserving account,
orders and leases on read. Older binaries reject the new field; downgrade requires
explicit state-format handling, not journal deletion. All private files remain
owner-only; narrowly group-readable publication is not implemented. Parent
state/secret directories must remain administrator-controlled.

See [deployment consequences](VPS-GUIDE.md), [test instructions](#可重复检查)
and [vendor record](#依赖维护). No upstream refresh occurred. Restored dev-only
packages are tempfile/fastrand, flate2 Rust backend and Tokio test-util; runtime
rustix exposes safe filesystem flags on Unix. Lockfile changes are limited to
the restored development packages. The declared MSRV and targets were not raised.

### Reviewable patch sequence

1. `2f9da48` — baseline and finding/work plan.
2. `58be4ce` — historical first-party test restoration and dev dependencies.
3. `2a8ef0b` — replaceable bridge generations, length checks, shutdown and tests.
4. `06163fa` — retained concrete TCP candidates and origin retry selection.
5. `c3aa7be` — completed-order retirement and opened-file validation.
6. `486b416` — nonzero suite guard,
   refined replacement regression, current instructions, this report and inventory.

Performance-sensitive changes are candidate racing, bridge admission/locking and
file metadata checks. No throughput claim is made. Reproduce existing ignored
benchmarks with `cargo test --release --locked benchmark_ -- --ignored --nocapture
--test-threads=1` only in the documented isolated environment; compare matching
hardware/configuration and separate any test fixture setup from measurements.

## 基线发现

以下矩阵记录 `02c6bf5` 的静态检查，并非当前修复后的缺陷清单。已修复的范围、回归证据及剩余验收差距见上方实施记录；未复现的远程拒绝服务不记为已确认漏洞。

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


## 依赖维护

The following maintenance record belongs to the historical implementation above. Current small vendor patches and their validation are in ACME-LAB.md. Keep notices
and inventories intact. Root dependencies remain pinned to:

| Component | Baseline | Retained patch purpose / regression evidence |
|---|---|---|
| Pingora | `4487f7b2ab50f159e4a2cf4f6a6b813f61bb6e19` | See the existing [patch inventory](../vendor/pingora/MOON-NAIVE-PATCHES.md): informational responses/trailers/upgrades (website wire tests); literal IP SAN verification and trust isolation (`evolution` tests); H1 header deadline and framing/trailer sanitization (ingress/website tests); optional compression backends and negotiation (website tests); generic errors (H1 tests); channel binding stream ID (authentication and transport tests). |
| instant-acme | `4a9b80fdc22f23ab39b78dfd20ff5d4c92938e52` | [Additive durable account-key API](../vendor/instant-acme/MOON-PATCH.md), covered by restored account persistence/EAB tests and the isolated Pebble EAB lifecycle. |
| quiche | `925b225825e2188f8e58e359114150500557bf61` | No local source patch in this work; H3 handshake and framing tests exercise integration. |

`cargo xtask audit-native` checks baseline, vendor inventories and the resolved
normal dependency graph. BoringSSL remains the TLS implementation. Format types
from rustls-pki-types do not add a rustls TLS stack. Native build and actual local
H2/H3 tests link boring 5.2.0, boring-sys 5.2.0 and tokio-boring 5.0.0 with quiche.

This is not a complete advisory review. Whether upstream equivalents now exist
for every patch has not been verified; no claim of vulnerability absence follows
from the version numbers or successful graph audit. Standalone vendor-test
execution results and blockers are recorded in the implementation report above. Do not silently amend
vendored lockfiles or enable alternative production TLS backends to run them.

Development dependencies restored: tempfile (and fastrand transitively),
flate2's Rust backend and Tokio test-util. Existing runtime rustix now exposes
its fs feature on Unix for safe descriptor opening. The declared minimum Rust
version and documented targets are unchanged; only the available Linux compiler
was tested. No broad dependency upgrade was performed.

## 版本沿革

- 0.6.0：整合单进程证书管理、网站及 H2/H3 隧道，引入修订4认证、可选填充和传输调度。
- 0.7.0：账户管理独立成模块，EAB 注册统一使用 instant-acme，兼容持久化账户。
- 构建精简：工具迁至 tools/xtask；曾删除第一方测试、实验工具和交接文件，保留 vendor 来源及清单。
- 安全恢复：恢复第一方测试，修复桥接重建、候选地址与 ACME 退役，尚未完成上表中的整体架构目标。
- 文档整合：配置、部署、协议与架构、验证与安全记录共四份 Markdown；历史测量 JSON 独立保留。

旧文件名、命令和工作区路径仅用于追溯，不作为当前操作说明。

## 本轮可靠性修复与验收边界

本轮起点为 `e9066c7a576eb7fa831214485bc010005650df58`；开始时本地和远端
main 一致、工作区干净。此前文档的历史结果不作为本轮执行结果。

已修复的路径：

- 固定 16 MiB 连接预留改为受全局预算支持的公平常驻信用；等待、逐用户 CONNECT、
  连接、request/tunnel 和应用 Bytes 额度有明确所有者，QUIC 控制流保留信用。
- TCP 尝试有两秒期限，最多两个同时运行；锁定 Pingora 的 opt-in L4 接口允许在
  HTTP 请求发送前重试完整 TCP/TLS，保留原始 SNI 和证书验证。每候选三秒上限，
  请求级连接期限不会因网站源站回退重置。下一跳握手失败也推进具体候选。
- 系统 DNS job 在真正结束前持有许可，取消 waiter 不退款。数据面 32 个、控制面
  8 个 job，均不无界排队；不能宣称 timeout 能终止 libc 解析。
- 固定网站 DNS 错误在 peer 选择阶段冷却并选择备用；WebSocket 共用长期源站池、
  DNS 和健康状态。Upgrade 请求开始写出后不做透明重试。
- 多字段 WebSocket 子协议 token 校验；原始斜杠、转义、query 和可信 forwarded
  元数据统一处理，正向代理继续删除身份元数据。
- outer 自然到期有时间门禁，inner 载入与外层有效性分开；磁盘 CURRENT、载入状态
  和真实新握手分别核对。刷新错误不再丢弃。
- DNS uncertain create/deletion 持久对账，NS 地址回退、单轮期限和失效刷新；
  completed certificate 隔离与 future notBefore 等待。
- `cargo xtask verify <target>` 是 compile-only；`verify-run <target> <runner> [args...]`
  才显式执行目标 CLI，参数不经过 shell，每条 CLI 命令最多 60 秒再加 5 秒终止宽限。

代表性新增测试使用真实回环 IO 验证：第五条混合 H2/H3 连接、源站 DNS 失败备用、
TCP 已通但 TLS 不进展后的候选切换、WebSocket 真正使用备用、重复子协议字段和
原始 target、outer 自然到期后的新握手拒绝及恢复后 H2/H3 新证书。确定性测试覆盖
前两个候选永久 pending、取消 resolver waiter、Bytes 克隆/切片额度、晚到 DNS
创建和 NS 地址回退。原有 POST 不重放、codec、权限、半关闭与 reset 测试继续执行。

尚不能据此声称全部架构验收完成：

- 不是所有库内存都经过应用缓冲池，不能把两项字节预算相加当作 RSS 硬上限。
  QUIC final-size/乱序及未知控制流的完整恶意线报文矩阵仍需专项实验。
- 不自动撤销已授予信用，不引入认证后全连接登录或新代理 0-RTT/Fast Open；
  exporter label、实际 stream ID、transcript、response proof 与 codec 源码保持不变。
- 控制面仍是同进程线程。后续应拆成独立 UID/进程、单独持有 DNS/ACME 密钥，
  通过只允许 generation 描述的 IPC 发布；数据面无 DNS/ACME 密钥读取权限。
  验收需覆盖 IPC 凭据、目录 writer/reader/rename 权限、崩溃及升级/回滚。
- 配套 revision 4 Chromium 客户端尚未实现。普通 Chromium 仅能验证匿名网站、
  WebSocket、H2/H3 和其支持的 ECH；不能替代逐流代理 proof 的互通验收。
- 没有匹配硬件/内核/编译选项/配置的服务性能 A/B 数据，性能收益未知。
  后续固定 Chromium commit、补丁与构建摘要，记录真实协议/连接复用、证书/ECH、
  错误路径；负载同时记录成功率、p50/p95/p99、吞吐、CPU、RSS、FD、task/queue、
  连接/stream/permit、缓冲和 bridge generation。确认瓶颈后才改变复制、channel、
  批处理或调度。BoringSSL 或少量抓包不构成不可识别性证据。

### 本轮实际执行结果

最终工作区 `cargo test --workspace --locked`：服务库 127、core 30、CLI 集成 2、
xtask runner 1，共 **160 项通过、0 失败**。服务库 9 项和 Pebble 集成 2 项忽略，
不计为通过；binary/doc 的零测试运行也不计数。

`cargo xtask verify` 实际完成非空 core/ACME/net/CLI 套件、fmt、
`clippy --workspace --all-targets --locked -- -D warnings`、Release 构建和真实 CLI
冒烟；`cargo xtask audit-native` 以及根目录 SHA256SUMS 校验通过。
这些结果来自本轮命令，不来自上方历史安全实施记录。

执行环境：Linux 6.18.57、x86_64 GNU、Intel Xeon Platinum 8573C、5 个可见逻辑 CPU，
Rust 1.93.0、四路构建。Release 复用本机同锁定 boring-sys 5.2.0 的已验证静态库。
未验证最低 Rust 1.89、外国架构 runner、真实 CA/DNS、Chromium、24h soak 或性能 A/B。
