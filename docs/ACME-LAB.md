# ACME 正确性修复与实验入口

审阅和修改基线为 `d0f6a082eeaabd7dac2e976fff09e6c7baf3fbe5`。开始时 HEAD 与参考提交相同，工作区干净；没有额外的 AGENTS.md。先核对旧报告、生产代码和测试判据，再修改。旧报告的失败数不是独立缺陷数，也不是本轮执行结果；旧版本可直接从该提交读取。

本轮实现生产修复、回归修正和模块合并。revision 4、逐流认证、exporter/transcript/proof、成功拨号后才回复 CONNECT、ACL、证书验证和请求不可隐式重放的约束保留。没有新增代理协议、TLS 后端、provider 注册表或工作流框架。

## 固定集成契约

| 项目 | 当前实现与验证契约 |
|---|---|
| instant-acme | 0.9.0，`UPSTREAM_REVISION=4a9b80fdc22f23ab39b78dfd20ff5d4c92938e52`；两个 Cargo.lock 和 features 不变；`default-features=false`，仅 `time,x509-parser` |
| 本地补丁 | [MOON-PATCH.md](../vendor/instant-acme/MOON-PATCH.md)：持久密钥注册、请求归因、可检查的 Retry-After 与轮询时序；源码摘要同步更新 |
| CryptoProvider | [crypto.rs](../src/acme/crypto.rs)：BoringSSL P-256/ES256，JOSE 原始 64 字节 r\|\|s、PKCS#8 恢复、JWK thumbprint；继续使用库内 nonce/JWS/EAB |
| HTTP | [http.rs](../src/acme/http.rs)：BoringSSL/Tokio/Hyper HTTP/1；保留 CA/主机名校验、HTTPS CONNECT 代理、path/query；请求期限覆盖 DNS、TCP、TLS、头和有限 body；取消释放 driver/socket |
| CSR/EAB | [certificate.rs](../src/acme/certificate.rs) 生成带 DNS SAN 的 DER CSR，原样传入 finalize_csr；[account.rs](../src/acme/account.rs) 管理持久账户 key、一次性 EAB/HS256 和恢复 |
| 类型依赖 | rustls-pki-types 仅用于 DER/密钥类型；没有启用 ring、rcgen、hyper-rustls 或第二套运行时 TLS |
| 本地 CA | Pebble v2.8.0，commit `d52948ce25e7c1576bcd18ff0e20a1c24ec7c44b`；[测试补丁](../tools/acme-lab/pebble-lab.patch) 只提供 keylog、验证/查询屏障及修正 0% 授权复用的随机边界，不进入服务端生产依赖 |

规范依据：[RFC 8555 的 nonce、POST-as-GET、挑战与订单](https://www.rfc-editor.org/rfc/rfc8555)、[RFC 9110 Retry-After](https://www.rfc-editor.org/rfc/rfc9110#section-10.2.3)、[RFC 9773 ARI](https://www.rfc-editor.org/rfc/rfc9773)。下文的 ARI 上下界和证据预算是项目本地政策，不宣称由协议规定。

## 已修复行为

| 条件与原故障 | 当前边界及结果 | 对应回归 |
|---|---|---|
| 恢复订单前 HEAD newNonce 返回 404，被共享 last_status 误认成订单消失 | [account.rs](../vendor/instant-acme/src/account.rs) 在真正订单 POST-as-GET 的响应处附加 `Error::Response {method,url,status,source}`；[Manager::reconcile](../src/acme/manager.rs) 只凭该订单 URL 的 POST 404 退役。适配器继续把 ACME Problem/badNonce 交给库处理 | nonce404 保留 URL/key/CSR；order404 对照确实请求订单端点 |
| Retry-After 极大数导致时间加法 panic，外层又饱和保存极大时间 | [RetryAfter](../vendor/instant-acme/src/lib.rs) 区分 Absent/Malformed/At/Unrepresentable；库与 HTTP 共用解析，检查 SystemTime/Instant 和指数退避算术；不持久化溢出值 | 秒数、HTTP-date、过去/缺失/非法值、u64::MAX 与超过 u64；order/ARI 路径 |
| finalize/recovery 丢失等待头；首次 poll 提前；等待中重启可丢失调度 | [order.rs](../vendor/instant-acme/src/order.rs) 保留各响应等待；[Manager::poll_order](../src/acme/manager.rs) 每次刷新后的等待先写 UTC next_attempt，再用单调时钟等待。本轮剩余期限不足则持久延期；保留原订单，不重复 finalize Processing/Valid | 120 秒首轮等待、超出 operation budget、恢复首轮、等待中取消后重开不产生请求 |
| 只读发现/列表失败也留下 CreateUncertain | [dns.rs](../src/acme/dns.rs)、[porkbun.rs](../src/acme/porkbun.rs)：prepare 只读，Preparing 可恢复；写入 CreateUncertain 后才调用 present。只有结构化 401/403 权限拒绝才确认为无副作用 | 两真实 provider 的发现、列表、拒绝、准备取消、真实持久 intent/send gap、晚提交/空 cleanup/重启 |
| challenge ACK 后超时/退出立即删除 TXT | [Manager::cleanup](../src/acme/manager.rs) 查询原 order/authz/challenge；Pending/Processing 验证继续保留，确定终态才清理。Validating 在 ACK 前持久化；Pending ACK 间隙可以重发 set_ready，Processing 不重发 | Pebble 屏障下 timeout、SIGTERM、SIGKILL/重启；先观测保留，再释放 CA，最后检查原订单进度和持久清理 |
| HTTP 内的异常证书经 Vec JSON 膨胀超过 journal 上限 | [BlockedCertificate::evidence](../src/acme/persist.rs) 在复制/序列化前仅取 16 KiB prefix，保存原长、完整 body SHA-256、分类和 retry_at。HTTP 4 MiB、证书 1 MiB、journal 8 MiB 各自保留；正常拒绝不再误作持久化不确定 | 可解析/不可解析材料的 1 MiB、+1、2/3/4 MiB、4 MiB+1；完整摘要、长度、journal <128 KiB、旧证书可用 |
| control panic/error 停止仍有有效证书的 listener | [runtime.rs](../src/runtime.rs) 捕获 unwind，丢弃失败 Manager，结束控制 runtime；已有网络继续有效性准入并报告 renewal_stopped，不自动恢复潜在不一致的 Manager。初始无证书仍无法启动；已启动后的控制清理错误独立报告，不因 shutdown/control 先后顺序改变正常网络关闭的返回值 | invalid renewal 和 control panic 后真实新 H2/H3 握手仍取旧有效身份，driver 为零，显式关闭成功 |
| TLS-LOADED 写失败阻止加载或掩盖已完成的替换 | [Slot::refresh](../src/net/tls.rs) 构建/验证完整不可变 H2/H3/ECH generation 后原子替换，独立尽力写诊断。report 错误单独记录，失败清理临时文件 | create/rename/fsync 命名故障必须命中；实际 rename 失败时新 H2/H3 leaf 已改变；持续两次续期 |
| H1 网站 Upgrade 没有与 H2/H3 共用 tunnel 准入 | [Router::request_filter](../src/net/site/mod.rs) 在合法网站路由/Upgrade 校验后、打开 upstream 前取共享 lease；Context 保持至完整双工结束。[Pingora 补丁](../vendor/pingora/MOON-NAIVE-PATCHES.md) 保留 Upgrade 两个半方向 | max_streams=1、足量连接；H1/H2/H3 混用，满额不打开源站，拒绝/reset/EOF 回收，upload 半关闭仍占用 |
| H3 本地队列的四项预算耗尽后依赖新的外部事件，合并通知可留下已排队工作 | [drive_stream/drive_website](../src/net/h3.rs) 返回本地工作是否用尽预算；driver 主动 yield 后继续。空队列、流控阻塞与已关闭方向不忙轮询；四项预算不变 | 九个不产生 QUIC 包的合法 Body 任务：旧行为处理四个后不再调度；新行为有界排空且恢复 request/active 资源 |

DNS read-only prepare/传播各有 15 秒总预算；候选解析最多 5 秒，传播候选最多 1 秒，最多 32 个地址。HTTP 控制请求也改用根 resolver 的独立控制预算。已运行的系统阻塞解析 job 持有 permit 至实际结束；取消 async waiter 不会提前返还。同步 fsync 不能被普通 async timeout 抢占。

ARI 成功响应的重新检查间隔限制为 60 秒至 24 小时；429/503 的有效 Retry-After 不套用该 cap。订单和限流等待同样不受 ARI 本地上界截断。没有可用等待头时保留原库 250 ms、倍增退避，DNS 传播另用 poll_interval。无法表示的远端时间返回错误并保留订单，随后按有界错误退避重试，不转换成 u64::MAX。

证书 invalid-material、本地 I/O/trust-config、链或本地信任待调查、future-notBefore、暂态 HTTP 与真实 durability uncertainty 分开处理。future-notBefore 保留原订单/key/CSR；永久异常材料有界阻塞供调查，不无限下载/创建订单。链错误无法单凭验证失败归责远端或本地；保留待调查分类。持久化不确定令 Manager suspended，不继续副作用；网络独立检查身份有效性。

outer 文件不变也继续按时间检查；outer 到期暂停新握手，inner 更新仍可加载，恢复 outer 后重新准入；不静默关闭 ECH，旧连接按原生命周期继续。CURRENT、内存 loaded generation 和 TLS-LOADED 是三种事实，status writer 明示未进行握手探测。

## 状态、所有权与合并

DNS 单域名单订单状态为 `Preparing → CreateUncertain → Created → Validating → DeleteUncertain → removed`。可借用记录保留 borrowed，始终不删除；marker/record ID 仅允许清理自己记录，foreign TXT 保留。默认 recover 也拒绝无证据的不确定创建。两 provider 共用 adopt/recover/cleanup 所有权政策，保留各自认证与 API 语义。

必须保留崩溃间隙：持久 intent 后、POST 前崩溃，与 POST 后响应丢失可能磁盘状态相同。空列表不是未发送证明；无服务端幂等/提交期限承诺时保留对账和人工调查路径，不清 journal、不删除所有同名 TXT。

Manager 直接拥有本地 `Option<VerifiedBundle>`；只有网络 TLS generation 仍需共享不可变 Arc。持久化模块保留 journal、generation/CURRENT 提交、no-overwrite import 三类不同失败语义，没有把它们伪装成一个事务。

| 删除/迁移的源文件 | 现在的职责位置 |
|---|---|
| acme/eab.rs | acme/account.rs：账户、EAB 导入/注册 |
| acme/state.rs + acme/store.rs | acme/persist.rs：锁、journal、发布、私密导入 |
| net/outbound.rs | net/egress.rs：已验证候选、固定下一跳、Stream |
| net/site/forward.rs | net/site/upstream.rs：共用 peer/timeout/TLS 构建，公共转发 ACL 与配置源站政策仍不同 |
| net/site/generation.rs | net/site/bridge.rs：有界 single-flight 重建、冷却、共享 shutdown、无重放 |
| net/resolve.rs | src/resolve.rs：控制/数据独立预算，没有中间转发层 |
| tools/acme-lab/env.sh | 私有 run.py 的工具发现和参数；没有第二套 suite 定义 |
| tools/acme-lab/README.md | 本文的运行说明 |
| 四个 docs/acme-lab-*-index.json | 先归档可用原始工件，再移出维护源码；不计为生产复杂度下降 |

公共 Rust 路径随合并调整：`acme::eab` 改为 account 中的函数，state/store 改为 persist；通用 Error/Result 在 crate 根；Http.last_status 与 certificate::CertificateSlot 移除；Manager::slot 改为 current(now)。本包 publish=false，但源码嵌入者需更新调用。CLI 配置和 revision 4 wire 不变。vendor 新 Error 变体影响穷尽匹配，轮询等待现在遵守响应头。

journal 写入版本 3，读取旧版本 1/2 并保守迁移未标注 lease；旧全文证据在读入后截断再保存。旧二进制不能安全读取新状态；回滚必须使用事先备份并对账的完整状态目录，不能降级版本号或只删除 lease。已经超过旧 8 MiB 读取限额的历史损坏文件仍需保留调查，不能自动清空。

## 源码计量

按 Git 基线文件与当前文件逐项计数（不含 target/reports/外部工件），物理行用 `len(bytes.splitlines())`，包含注释和空白。src/core 中 runtime-bearing Rust 与独立测试文件分开；内联 cfg(test) 项/字段/语句及 test 项按 Rust AST 区间单列，不能把它们算作生产代码增长。旧 codec 的 `&raw` 解析器诊断位于完整排除的未改测试模块，已核对边界。

| 类别 | 文件数：前 → 后 | 物理行：前 → 后 |
|---|---:|---:|
| 运行相关 Rust（含内联测试） | 41 → 36 | 14571 → 15083 |
| 独立测试 Rust | 12 → 12 | 10433 → 11214 |
| 工具及其说明 | 12 → 10 | 1655 → 1747 |
| 生成 JSON（含未改的 packet-lab-results） | 5 → 1 | 46968 → 36856 |
| vendor（含其测试/文档/清单） | 474 → 474 | 204942 → 205048 |

运行相关文件中，内联测试为 3788 → 3928 行；扣除后的生产物理行估计为 10783 → 11155（增加 372）。生产正确性修复增加了代码；本轮减少的是文件数、重复职责和无用共享所有权，不声称生产代码整体缩短。另有 28 个配置/文档/许可等第一方文件；第一方文件合计 98 → 87。生成索引单独减少 4 文件/10112 行，不能计作生产简化。

工具行数增加包含严格证据失败判据；删除重复的 Rust 隔离编排和 env.sh，保留唯一 Python orchestrator，避免维护两套流程。完整逐文件计量及一次性计数脚本在外部 `source-metrics.json`/`measure.py`，没有新增维护中的计量系统。

## 回归判据修正

- keylog 现在不再暗中把测试客户端接收窗口从 64 KiB 扩大至 1 MiB；网站/codec 抓包沿用原窗口和 5 秒断言。旧 packet-lab 摘要属于旧 profile，不作当前性能对照。
- intent_cancel 现在取消显式只读 prepare；另两个 case 单独保留真正 durable-intent/send 间隙。后者空查询必须仍不确定。
- Pebble 重启先等待 control_restored，不等待本不应发生的 cleanup。释放验证屏障前检查 TXT/lease 和删除标记；释放后同时等待 provider 完成与 journal 持久清空，避免把两者间隙误判成未清理。
- 隔离 mock 的“确定未发送”故障位于 prepare；不再用默认 recover=Ok 假装恢复创建。生产 Cloudflare/Porkbun 的实际恢复路径由单独 HTTPS mock 覆盖。
- retry_case 必须到达 finalize、返回预期 Tick、且等待 case 真正发生 poll；None 不满足计时断言。溢出 case 则必须有界延期。
- panic 测试改为有效网络继续、控制器不自动复活；Drop 屏障固定“用户关闭先于控制退出”，仍保留命中和真实握手断言；命名 IO/API/nonce 故障均断言实际命中，避免重构绕开故障点。
- 保留既有 codec、认证、预算、取消、半关闭、桥重建/POST 不重放、证书及权限回归；不以 ignored、通用重试或延长 sleep 隐藏失败。

## 唯一实验入口

普通 `cargo test --locked --workspace` 不要求抓包工具。`ACME_LAB_CAPTURE=optional` 可尝试抓包并保留失败原因；显式实验由下列入口强制要求证据：

```sh
cargo xtask lab --run /absolute/path/outside-checkout/run-id
# 缩小范围；suite 定义只在私有 run.py 一处
cargo xtask lab --only acme --run /absolute/path/outside-checkout/acme-id
cargo xtask lab --only pebble --run /absolute/path/outside-checkout/pebble-id
```

默认一次运行 oracles、workspace、Pebble、生产 features 的 vendor library、真实系统 resolver。可选择 `network/vendor/resolver/oracles`；`test-isolated` 只是同一入口的兼容命令。xtask 委托唯一 Python orchestrator；analyze.py 仅处理 tshark/独立密码验证，不维护第二套命令清单。

需要 Rust/native 构建环境、Python 3 与 cryptography、Linux unshare/user+network namespace、iproute2、tcpdump、tshark，以及指定版本的 Pebble/challtestsrv。环境不支持时明确失败，不把日志当 pcap。工具可显式提供：

```sh
cargo xtask lab --home /absolute/lab-home \
  --pebble-source /path/pebble-source --pebble /path/pebble \
  --challtestsrv /path/pebble-challtestsrv \
  --tcpdump /path/tcpdump --tshark /path/tshark \
  --run /absolute/artifacts/run-id
```

也接受 `PEBBLE_SOURCE/PEBBLE_BIN/CHALLTESTSRV_BIN/ACME_LAB_TCPDUMP/ACME_LAB_TSHARK`；命令行优先。默认 home `/workspace/.moon-naive-acme-lab`，无 env.sh。`--bootstrap` 是可选的 Debian/Linux amd64 开发机工具安装，要求 curl/git/apt-get/dpkg-deb、Debian keyring 与网络；仅下载/解包到 home，不安装系统包。固定 Go 1.27.3/Pebble commit，校验下载和补丁。其他平台自行提供工具，不能把 GNU 实测当交叉目标执行。

实验只使用本地测试 CA、合成 EAB/DNS 凭据、测试域名和独立状态目录。实际监听端口、PID、版本/摘要、命令、退出码、UTC/单调基准、日志、journal 快照和证书摘要保留。CA 端 keylog 或测试客户端 BoringSSL callback 明确写入 NSS 行并补换行；不假设 SSLKEYLOGFILE 自动生效，不关闭证书验证，release 没有 keylog 开关。

`result.json` 是唯一权威运行结果，包含每条原命令退出码、预期 named case、证据错误和最终 success。baseline.json 是环境/源码摘要，timeline/analysis/decoder 文件是证据，不覆盖命令结果。缺 case/capture、tshark 失败、JOSE/URL/CSR/EAB 校验失败或未执行、目标 outage 被跳过、零相关测试都会令验证失败。独立 oracle 实际测试空 pcap、失败 decoder、失败/未执行的密码验证及“索引成功不能覆盖原失败”。每条命令有 600 秒进程组期限，原始错误码保留。

## 本轮执行与工件

最终命令均实际执行于应用本轮改动的工作树，HEAD 仍为审阅基线；工件的 src SHA-256 已逐项与最终源码核对一致。提交只封装该已验证源码。没有将旧报告的结果算入本轮成功。

| 实际命令/检查 | 本轮结果 |
|---|---|
| `cargo test --locked --workspace`（由 `cargo xtask lab` 调用） | server 198、CLI 2、core 30、xtask 1 通过，0 失败；10 个 server 可选项、7 个 Pebble 项在普通 workspace 中 ignored |
| `cargo test --locked --test acme_pebble -- --ignored --test-threads=1 --nocapture` | 7 通过，0 失败；包含 nonce 100% 拒绝的预期有界失败，而非要求签发成功 |
| `cargo test --manifest-path vendor/instant-acme/Cargo.toml --locked --no-default-features --features time,x509-parser --lib` | 9 通过，0 失败 |
| `actual_system_dns_cancellation -- --ignored --nocapture` | 1 通过；隔离 namespace 中实际 libc DNS 请求、取消及 permit 回收 |
| Python evidence oracles | 3 通过；空抓包、decoder 失败、密码验证失败/未执行，以及原命令失败/零测试/缺 suite 不能被索引覆盖 |
| `cargo clippy --locked --workspace --all-targets -- -D warnings`；`cargo fmt --all -- --check`；`cargo xtask audit-native` | 各通过；正常依赖图、源 pin 和 vendor 摘要通过；图审计本身不等于原生编译 |
| `cargo check --locked -p moon-naive --lib`；`cargo build --locked --release -p moon-naive` | 各通过；GNU host 产物，不是 musl 发布物 |
| release CLI `--help/--version/status/config init/check-config/serve` 冒烟 | 成功；配置私密/no-overwrite，默认未授权 ACME 的 serve 拒绝且未开 listener |

最终入口的 oracles/workspace/Pebble/vendor/resolver 原始退出码全部为 0，verification errors=[]。74 份 pcap 解码得到 1641 条 HTTP/DNS 行、独立验证 372 个 JOSE 签名和 1 个 EAB HS256，错误签名和 protected.url 不一致均为 0；有 164 条 DNS 帧。214 是解码的证书项数，包含链和重复项，不等同握手次数或性能样本。

以下帧号局限于对应 case 的 wire.pcap；源为 pcap 的字段与测试日志事件在 timeline 中明确区分：

| case | 本轮可核对证据 |
|---|---|
| `nonce404-133161-1793961001795973598` | 帧 63 HEAD newNonce →65 HTTP 404；没有 POST /order/1；journal 前后 URL/key/CSR 相同 |
| `retry-after-133161-1793960881042076612` | finalize 帧 97→99，Processing、Retry-After:120；下一次 order POST 为114；服务端单调实测 120073 ms，Installed |
| `retry-after-beyond-deadline-133161-1793961015122193112` | finalize 97→99；没有后续 order poll，日志为 RetryScheduled，保留原订单和 UTC next_attempt=1793961136 |
| `dns-cloudflare-late-133161-1793960865136986665` | 创建提交 epoch 1793960865.820851；空 cleanup 的 journal 在 1793960866.594318；远端提交在 1793960867.022518，重开后按原 marker 对账，foreign TXT 保留 |
| `live-renew-outer-133161-1793961055564780278` | 实际新 H2/H3 leaf serial 均为 11→12→13，CURRENT/TLS-LOADED 跟随 generation，旧连接持续请求；handshake-analysis 有独立解码的证书项 |

试运行目录 `pebble-corrected`、`final-lab`、`verified-consolidation`、`acceptance` 的非零退出码全部保留；分别暴露了 provider mock/清理观察时序、我引入的备用等待间隔错误、control/shutdown 顺序竞态及旧 H3 时限反例。`coalesced-wake-before.log` 为确定性队列反例 0 通过/1 失败，修复后通过；不是按失败条数累加独立缺陷。
- 当前证据目录：`/workspace/consolidation-evidence/`（私密，源码树外）。
- 历史原始工件及被删除的四索引：`baseline-evidence.tar.gz`；本环境中旧报告引用的六组原始资料均可归档。旧结果仍属于旧提交。
- 最终入口输出：`verification-final/result.json` 与 `verification-final.tar.gz`；pcap、测试 keylog、完整 journal 只在外部私密工件，不进入 Git/source archives。
- 每个 case 的 timeline 明确区分 `pcap` 帧和 `test_log` 事件；网络激活依据实际新 H2/H3 握手 leaf serial/fingerprint，文件/Manager 变化不足以证明激活。

## 验证边界

旧网站和 codec 用例各出现过一次间歇 H3 超时。补齐原窗口抓包后的 20 次隔离诊断均通过，未捕获同一次停滞；有界队列进度缺陷另由确定性组件反例证实并修复。不能据此证明该修复解释了所有时限失败，或以后不会复现；原始失败与诊断工件保留。

独立 Pingora 上游全套、其他 target/MSRV/musl 静态 ELF 门禁本轮未执行；改动的三个 Pingora 文件由本仓库真实网络回归覆盖。

本轮主机为 Linux GNU x86_64、Rust 1.93.0。真实 Chromium revision 4 配套客户端仍未实现；没有用官方 Naive、TLS 成功或少量 pcap 推断兼容性或不可识别。没有真实 CA/DNS、生产凭据、独立进程/UID、自动 outer 签发、其他 target、长期 soak 或 release 性能实验。

控制线程仍与网络同进程/UID，不能视为密钥权限隔离。静态 bounded 设计和测试 RSS/FD 观测不是吞吐优化证明。性能基线仍需匹配硬件/内核/编译/配置，测成功率、p50/p95/p99、吞吐、CPU/RSS/FD、task/queue、连接/stream/permit 和 bridge generation；没有这些测量，本轮不宣称提升，也不建议改队列/复制/批处理。
