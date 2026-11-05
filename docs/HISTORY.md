# 历史阶段记录

以下原文按原路径合并；旧名称、命令与测试结果仅用于追溯，不作为当前版本部署说明。原文中的相对链接可能指向旧路径。当前用法见 VPS-GUIDE.md 和 CONFIGURATION.md，当前结果见 VERIFICATION.md。历史中的 ACME.md、RELEASING.md、SERVER-COMPARISON.md 及旧多份配置示例现已合并，不再作为独立文件提供。

---

<a id="acceptance"></a>

## 原文件：docs/history/ACCEPTANCE.md

# 验收清单与证据分级

2026-10-22 后续进展：项目现名 moon-naive，配置统一 TOML，真实 H2/H3 实验入口、网站/CONNECT/取消、证书热更新和官方 Linux 客户端已有本地网络证据，见 NETWORK.md / MOON-NAIVE-VERIFICATION.md。目标 VPS、公网 CA/DNS、网络差分和长时间稳定性仍未完成；局部通过不代替整项验收。

2026-10-21 补充：网站/参考服务端的行为差分矩阵、共享入口和双传输 generation 门槛见 [ARCHITECTURE.md](ARCHITECTURE.md)。以下未完成项不会因领域测试通过而自动通过。

只有存在实际命令输出/报告，才可将下面项目标为通过。核心模型验证不能替代原生构建、网络互操作或真实 CA 验证。

## A. 本轮框架验收

执行：`cargo run --release --locked -p xtask -- verify`。

检查：
- 上游六仓 revision 与工作区干净度。
- 根 workspace 与 native 接缝代码格式。
- 根 workspace clippy `-D warnings`。
- Debug 与 Release 单测（包含 wire vectors、分片/合并、认证分流、H1/Fast Open/0-RTT 禁用、额度并发、证书事务与调度）。
- Release 构建。
- CLI 输出与 `tests/fixtures/check-config.stdout` **逐字节一致**。
- H1 配置反例实际执行 CLI 返回非零。
- `serve` 在网络 adapter 未接通时实际返回非零。

执行：`cargo run --release --locked -p xtask -- audit-native`。
- normal 依赖图中只有 boring/boring-sys 5.2.0。
- 不混入 rustls、hyper-rustls、OpenSSL、AWS-LC、ring 实现；允许不执行 TLS 的 rustls-pki-types。
- **这只是依赖解析证据，不是编译/链接成功证据。**

执行：`cargo run --release --locked -p xtask -- soak 100000`。
- 100,000 次确定性核心模型循环，每轮十次编码，包含第八帧到原始流切换。
- 分块解码后逐字节比较输入；续期失败保留旧证书、过期不 ready；permit 每轮归还。
- 记录真实比较字节数、耗时、最终 permit 数。
- **这不是 100,000 个网络连接，也不是 24h 网络 soak。**

## B. Linux 原生构建（本地真实握手通过）

已完成 Linux x86_64 / Rust 1.89.0 的 native check/test/release build、真实 H2/H3 实验前端与本地握手、站点/隧道、双协议证书热更新，以及独立 ACME 工作进程的本地 CA 签发/续期。最新证据见 NETWORK-VERIFICATION.md；生产入口与目标 VPS 验收仍未完成。

- [x] 在本会话 Linux x86_64 用 `native/Cargo.lock` 执行 check/test/release build。
- [ ] 验证 BoringSSL 链接来源、唯一性、最终依赖版本及工具链；审计供应链安全公告。
- [x] 本地实际 H2-only TLS handshake：h2 成功，http/1.1/无 ALPN 被拒绝，不进入 Pingora H1 fallback。
- [ ] 实际 H3-only QUIC handshake，无其他 ALPN，无 0-RTT。
- [ ] 把 native transport 与核心合成真正的 `moon-naive serve`，再允许解除 fail-closed 闸门。
- [ ] 实际目标仍以 Cargo 构建，无 xcaddy/Caddy 服务进程。

## C. Naïve/网页互操作（本地矩阵通过，完整上线范围未完成）

- [ ] 固定当前与一个旧稳定 Naïve 客户端，分别测试 `https://` 和 `quic://`。
  本地 154.0.8037.49-4 与相邻稳定版 -3 的 H2/H3 已通过；更早 150.0.7871.63-1 的 H2 已通过，H3 受该版客户端对本地根的限制，等待公网受信证书测试。不是两个不同 Chromium 主版本的 H3 全部通过。
- [ ] 首个请求、连接复用后的早到 DATA、同时多个目的地；200 必须晚于目标连接成功。
- [ ] 延迟/失败 DNS、ACL 拒绝、端口不可达时不提前回 200。
- [ ] H2/H3 的首页/资源 GET/HEAD、preamble、404 与普通网站基线一致。
- [ ] 错误/缺失/重复凭据对照网站路径，不解析 CONNECT 目标或建立隧道；网站只可访问管理员固定配置的反代上游。
- [ ] padding 启用和普通无 padding 代理客户端；下载、上传、双向 echo 的 payload 字节和 hash 对拍。
- [ ] 目标先发 banner，单向大流量、长连接、半关闭、RST/GOAWAY、H3 RESET_STREAM/STOP_SENDING。
- [ ] 每用户/全局/连接额度、慢读、窗口耗尽、取消、异常 padding 后资源释放。
- [ ] IPv4/IPv6、mapped IPv6、域名重绑定、metadata/self-loop、不安全端口策略。

## D. 真正 ACME 自动管理（当前未完成）

同日 ACME 实施状态见 [ACME.md](ACME.md) 与 [ACME-VERIFICATION.md](ACME-VERIFICATION.md)：已实现实际协议/密码学/DNS/事务流程，并通过真实本地 CA 签发、续期、ARI 和恢复。以下包含公网 staging/production 与 listener 的完整验收项仍不自动勾选；本地通过不等于公网已验收。

默认 DNS-01。必须先取得测试域名、明确 DNS provider 和最小权限 API token；没有这些时不得把 mock 输出标为真实成功。

- [ ] BoringSSL HTTP client 验证 CA 证书/主机名，具备请求大小/超时/重定向限制。
- [ ] BoringSSL JWS provider 的 ES256/PKCS#8/JWK/SHA-256/HMAC 向量对拍；注意 JWS ECDSA 使用 raw r||s，不是 DER signature。
- [ ] ACME account 密钥私有持久化、重启恢复；订单状态持久化，避免重启产生订单风暴。
- [ ] 自动创建 DNS TXT、权威传播检查、通知 CA、按 Retry-After 轮询、CSR finalize、下载链。
- [ ] TXT 幂等操作不覆盖他人记录；只删除本订单创建的记录；失败 cleanup journal 可恢复。
- [ ] 验证域名 SAN、证书链、有效期、密钥匹配后才进入 generation 提交。
- [ ] staging 完整签发和续期；再经授权切换 production。
- [ ] CA 429、badNonce、DNS 403、传播超时、网络断开、磁盘满、签发任务取消/重启。
- [ ] 旧证书仍有效时续期失败不影响服务；即将过期告警；没有有效证书时不启动业务 listener。
- [ ] ARI/随机抖动及重试预算；不得靠默认 90 天寿命写死调度。
- [ ] 原子更新后 H2/H3 新握手使用同一 generation，旧连接继续使用旧快照。
- [ ] CURRENT rename 后 fsync 失败：停止盲目重签，重新读取并验证 CURRENT；崩溃锁只显式恢复。

## E. 稳定性与上线门槛（当前未完成）

1. 在受限测试端口/测试域名先跑功能矩阵，再进行 **至少 24h** soak；分阶段保存日志/进度，不能让 agent 单条命令阻塞一天。
2. 每分钟采样 RSS、fd、任务数、连接/流数、全局/用户额度、收发字节、失败类型、证书 generation；不记录代理目标或密码。
3. 周期性执行 H2/H3 上传下载、短流风暴、长 SSH 类流、单向 idle、半关闭、取消与连接重建。
4. 注入丢包、延迟、MTU 变化、IPv6 不可达、QUIC 迁移/重绑定；记录恢复过程而非只测平均吞吐。
5. 周期性证书更新和 graceful reload；验证 drain deadline、GOAWAY、目标 socket 与 QUIC 资源回收；不承诺无限长连接无损迁移。
6. 验收：payload 零不明损坏；无 panic/死锁；负载消退后 fd/task 回归基线；RSS 达到平台而非持续增长；所有队列在已配置上限内；未认证出站始终为零。
7. 记录基线、峰值、采样间隔、持续时间、工具与版本；小样本结果不能外推 VPS 极限吞吐。
8. DNS 写入、CA 生产订单、绑定 443、防火墙/能力授权、实际 init 服务文件和替换现有节点都需要另行确认。不要把框架测试命令当成部署授权。

---

<a id="acme-verification"></a>

## 原文件：docs/history/ACME-VERIFICATION.md

# ACME 实施验证（2026-10-21）

本文保留 2026-10-21 验证时的 `naived` 命令名称与原始日志。2026-10-22 已更名为 `pinaive` / `pinaive-acme`，当前命令见 [BUILD-AND-USE.md](BUILD-AND-USE.md)，更名后复验见 [VERIFICATION-2026-10-22.md](VERIFICATION-2026-10-22.md)。

实际平台：Linux x86_64，Rust 1.89.0，GCC 14.2.0，CMake 3.31.6，libclang 19。Go 1.24.2 仅用于编译本地测试 CA，不是生产运行依赖。

| 项目 | 本轮当前结果 |
| --- | --- |
| 根 workspace fmt/clippy、Debug/Release 测试与构建 | 通过，两个 profile 各 38 项（core 25 + control 13） |
| native fmt/clippy `--all-targets -D warnings` | 通过 |
| native Debug | 12 个单测 + 2 个显式启用的真实 Pebble 集成测试通过 |
| native Release | 12 个单测 + 2 个显式启用的真实 Pebble 集成测试通过 |
| Release 工作进程 | `native/target/release/naived-acme` 构建并实际执行通过，7,309,248 bytes（约 7.0 MiB） |
| CLI | --help、status 实际验证已安装证书、未接受条款时 once 返回非零 |
| 公网 HTTPS 只读检查 | 最新 Release 成功读取 GTS staging 与 production directory，TLS 验证启用，无账户/DNS 写入；先前轮次也验证过 Let's Encrypt staging |
| Porkbun + GTS 配置 | 推荐配置实际通过 check-config，显示 GTS staging 端点，不读密钥、不开端口 |
| 原生依赖审计 | 通过，只有 boring/boring-sys 5.2.0，无额外 rustls/OpenSSL/AWS-LC/ring TLS 后端 |
| 公网 Porkbun / Cloudflare / CA 签发 | 未执行，没有真实域名、DNS API 密钥或 GTS EAB |
| 实际 H2/H3 listener 证书热加载 | 未执行，listener 尚未实现 |

两个 workspace 合计每个 profile 52 项测试。这里的 Pebble 测试是实际 HTTPS/JWS/CSR/DNS-01/证书签发，不是核心模型 soak。两个集成测试分别覆盖普通 ACME 与强制 EAB 账户注册。

## 单测与集成测试的证明范围

- BoringSSL PKCS#8 生成/恢复，JWK 一致性；独立按 r/s 验证 JWS 原始 64-byte ECDSA 签名，篡改 payload 会失败；RFC 4231 HMAC-SHA256 向量。
- 签名与信任链均有效时，缺失 DNS SAN/只有 CN、只含 clientAuth 用途仍拒绝；正常 serverAuth + SAN 对照通过。
- HTTP 明文默认拒绝、loopback 测试例外、超大响应有界拒绝、deadline 取消；未引入不验证 TLS 的生产模式。
- Cloudflare 兼容 API：TXT 创建成功而 HTTP 返回失败，重建 provider 后按 marker 恢复，不重复创建；删除仅作用于自身记录，保留其他记录；借用同值外部 TXT 不删除；HTTP 429 的 Retry-After 被记录。
- Porkbun 兼容 API：验证官方请求路径、POST auth JSON、相对名称、整数 TTL、Idempotency-Key 与 notes；创建成功但 HTTP 500 后用持久化 intent 找回，创建次数为 1；清理幂等，保留外部记录与借用记录。外部 NS 委派时写入前拒绝；域名边界不接受 badexample.dev 冒充 example.dev。
- EAB：用独立 BoringSSL ECDSA 验签和 HMAC 校验核对内外 JWS、相同 JWK、kid/url、contact；显式 badNonce 后重试成功。
- GTS 测试根：按 issuer/environment/directory 隔离；Google staging、Let's Encrypt staging 各自只带对应测试根，production 和自定义目录不会隐式加入。
- journal：原子写入/恢复、0600、软链接拒绝、单 writer 文件锁。
- 实际 Pebble：首次签发 → 验证证书 → 持久化 → 重启不重签 → 提前推进计划做续期 → DNS API 故障保留 CURRENT → 重启遵守退避 → 复用相同账户及 pending 订单恢复续期。
- ARI：真实读取建议窗口，持久化选点，重启后不重新随机；实际 replaces 续期。
- 实际已签发证书的错误 SAN、错误私钥、过期和错误信任根反例。
- 实际续期时同一 CertificateSlot 更新，已持有的旧 Arc 不改变。
- 模拟 CURRENT 已持久化而 journal 未清除：重启按 key 匹配恢复，不再签一张。
- 实际执行工作进程 status 校验证书，once 在未接受条款时拒绝运行。
- 强制 EAB 的 Pebble：账户创建成功后删除 EAB JSON，重启及再次签发仍成功；模拟账户已在 CA 创建、但本地尚未保存账户 URL 的间隙，原私钥找回同一账户，不重新读取 EAB 文件、不额外下单。

Pebble v2.7.0，commit `bbe7775c27078417e379287a431fa5a716a6788d`。集成测试所有服务仅绑定 127.0.0.1/localhost 随机端口，结束后回收子进程。challtestsrv 的递归 DNS 模拟器不设置 AA，测试用 Rust 权威 facade 补 AA；生产校验没有关闭。测试证书与私钥在临时目录，未进入源码包。

## 命令与日志

```text
cargo run --release --locked -p xtask -- verify
cargo run --release --locked -p xtask -- audit-native
cargo clippy --manifest-path native/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path native/Cargo.toml --locked -- --include-ignored --nocapture
cargo test --manifest-path native/Cargo.toml --locked --release -- --include-ignored --nocapture
cargo build --manifest-path native/Cargo.toml --release --locked --bin naived-acme
native/target/release/naived-acme check-ca config.porkbun-gts.example.toml
```

显式执行 ignored 集成测试的两个 test 命令设置了 `PEBBLE_BIN`、`CHALLTESTSRV_BIN`、`PEBBLE_SOURCE`。原生构建工具的本会话选择与先前 VERIFICATION-2026-10-21 相同；普通系统使用完整 C/C++/CMake/libclang 开发工具链即可。

最新 Porkbun + GTS 轮次证据：

- `reports/verification-1792586669394236576-45789.txt`、`gts-root-verify-2026-10-21.txt`。
- `reports/native-graph-1792586693426963227-47804.txt`、`gts-audit-2026-10-21.txt`。
- `reports/gts-clippy-2026-10-21.txt`。
- `reports/gts-release-build-2026-10-21.txt`。
- `reports/gts-debug-tests-2026-10-21.txt`、`gts-release-tests-2026-10-21.txt`。
- `reports/gts-config-check-2026-10-21.txt`。
- `reports/gts-staging-check-ca-2026-10-21.txt`、`gts-production-check-ca-2026-10-21.txt`；production 只读检查用推荐示例的临时副本，把 environment 设为 production、accept_terms 设为 true，没有创建账户。

前一轮 Let's Encrypt + Cloudflare 证据保留：

- `reports/verification-1792585342711997137-41397.txt` 及 `acme-root-verify-2026-10-21.txt`。
- `reports/native-graph-1792585343313675353-42014.txt`。
- `reports/acme-clippy-2026-10-21.txt`。
- `reports/acme-debug-tests-2026-10-21.txt`。
- `reports/acme-release-tests-2026-10-21.txt`。

Release `check-ca` 的实际观察输出：

```text
ca_directory=reachable
tls_verification=enabled
account_created=false
dns_modified=false
```

没有声称公网证书已签发、Porkbun / Cloudflare 生产 API 已验收、Caddy 的全部证书产品功能已复制，或 H2/H3 握手已热加载。具体功能范围见 ACME.md。

---

<a id="acme"></a>

## 原文件：docs/history/ACME.md

# 自动证书管理（2026-10-21）

本轮实现真正的 ACME DNS-01 证书管理器 `moon-naive-acme`，不使用 Caddy、certbot、acme.sh 或 shell DNS hooks。生产运行只需 Cargo 构建出的 Rust 程序和配置；Go/Pebble 仅是本地测试依赖。

当前覆盖项目的**单机、单域名**证书生命周期；不把它描述为 Caddy 全部 TLS/ACME 产品能力的完整复制。公开服务继续仅 H2/H3，不为证书申请开放 80/H1。

## 与 Caddy 常用自动证书功能对照

| 功能 | 当前实现 | 验证范围 |
| --- | --- | --- |
| 首次自动申请 | 自动创建/恢复账户、订单、DNS-01、CSR、下载证书 | 真实本地 Pebble CA |
| 无人工执行续期命令 | `run` 常驻，按持久化调度自动检查并续期 | Pebble 实际再次签发，测试提前推进持久化到期时刻 |
| 账户/私钥持久化 | 网络创建账户前先保存 P-256 PKCS#8；重启复用账户 | Pebble 账户身份不变 |
| 订单恢复 | 保存 URL、CSR、对应证书私钥；恢复 pending/ready/processing/valid | 真实 pending 订单失败后重启继续 |
| 失败保留旧证书 | DNS/CA/校验失败不修改旧 CURRENT 和有效快照 | DNS 故障注入、域名/key/有效期/信任失败 |
| 有界重试 | 持久化指数退避、随机抖动、HTTP Retry-After、请求和流程 deadline | HTTP 429、恢复后退避仍有效 |
| ARI 续期建议 | 读取窗口、持久化随机选点与检查时间，窗口不变不反复重抽；支持 replaces | Pebble 实际 ARI 与续期订单 |
| 无 ARI 回退 | 按证书实际寿命及续期窗口计算，带提前抖动，不写死 90 天 | 与已有 Lifetime 策略共用 |
| DNS 自动创建/清理 | Porkbun / Cloudflare Rust API；先写 intent，按 notes/comment marker 恢复结果，只删自己创建的 TXT | 两个 provider 的本地兼容 API：创建已成功但响应失败、幂等恢复、保留他人 TXT |
| DNS 传播检查 | 对配置 zone 的权威 NS 直接查 TXT；验证源、ID、question、AA、rcode；截断转 TCP | 本地实际 UDP DNS-01；TCP fallback 已实现但未专门故障注入 |
| 密码学校验 | BoringSSL 验证链/SAN/key/有效期；额外要求叶证书非 CA、TLS server EKU/签名用途；拒绝仅 CN | 真实 CA 证书及签名有效但用途错误/无 SAN 的反例 |
| 原子证书安装 | generation 完整写入并 fsync，原子 CURRENT，之后发布 CertificateSlot | 原有事务测试 + 实际签发/轮换 |
| 崩溃恢复 | kernel 文件锁随进程退出释放；CURRENT 已提交但 journal 未完成时按匹配 key 恢复 | 单 writer/重启测试；提交后恢复注入 |
| 证书内存更新 | 验证并持久化后更新 Slot，既有 Arc 保留 | 实际续期 Slot 切换 |
| 服务端握手热加载 | 观察 CURRENT 并共同发布 H2/H3 TLS generation | 本地实际双协议新握手换证；旧连接继续使用，坏 CURRENT 保留上代 |
| GTS EAB 注册 | HS256 外部账户绑定 + 已持久化的 ES256 账户密钥；账户创建响应丢失时先按原 key 找回 | 要求 EAB 的真实本地 Pebble CA；删除 EAB 文件后重启/续期及账户找回 |
| 多 CA 自动切换、按需域名、通配符/多 SAN、分布式锁 | 未实现 | 可显式选择 GTS 或 Let's Encrypt；失败时不会自动换到另一 CA |
| OCSP stapling、TLS 上下文统一发布 | 尚待 TLS listener 阶段 | 不计作 ACME 协议已验收项 |

真实 Porkbun / Cloudflare 公网 API、GTS / Let's Encrypt staging/production 签发尚未执行：本会话没有真实域名和凭据。上述本地 CA 流程是真实网络/签名/验证，不是 FakeIssuer，但不能代替公网验证。

## 推荐：Porkbun DNS + Google Trust Services（.dev）

完整配置见 [config.porkbun-gts.example.toml](../../config.porkbun-gts.example.toml)，按用户要求使用 `issuer = "google"`、`dns_provider = "porkbun"`。`.dev` 支持 GTS，但后缀本身不限定 CA；其 HSTS 要求意味着浏览器使用时需要受信任的 production 证书，不能使用 staging 测试证书。

未设置自定义 directory_url 时，签发使用下列 GTS 端点，不自动回退到其他签发方：

| environment | ACME directory |
| --- | --- |
| staging | `https://dv.acme-v02.test-api.pki.goog/directory` |
| production | `https://dv.acme-v02.api.pki.goog/directory` |

域名示例为 `proxy.example.dev`，`dns_zone = "example.dev"` 应填写 Porkbun 管理的注册域，而非代理主机名。先在 Porkbun 开启该域名的 API 访问，再创建 API key；密钥需要允许读取 registry NS 以及读取/创建/删除该域名的 TXT。域名必须实际使用 Porkbun 权威 DNS；只有注册商是 Porkbun、NS 却在其他 DNS 服务商时，此 provider 会在写入前拒绝。不自动迁移 NS，不更改网站 A/AAAA/CAA 记录。

`dns_token_file` 指向本机 0600 TOML 文件，例如 `/etc/moon-naive/porkbun.toml`，内容格式：

```toml
apikey = "pk1_你的API密钥"
secretapikey = "sk1_你的Secret密钥"
```

适配使用官方 `https://api.porkbun.com/api/json/v3`，TXT 名称转换为相对域名（如 `_acme-challenge.proxy`），TTL 600 秒，并以 notes 标记自身记录。创建请求携带 Idempotency-Key；响应不确定后按持久化 marker 找回。清理仅按记录 ID 删除匹配 name/value/marker 的记录，保留他人的 TXT；同值外部记录只借用、不删除。逐个检查 registry NS 的权威 TXT 可见性后才通知 CA。当前不支持自定义/白标 Porkbun NS、CNAME/NS challenge 委派或通配符证书。

GTS 首次注册 ACME 账户需要 **EAB**。在自己的 Google Cloud 项目启用 Public CA API（`publicca.googleapis.com`），操作者需要 `roles/publicca.externalAccountKeyCreator` 或包含对应权限的角色。按 [GTS 官方教程](https://docs.cloud.google.com/certificate-manager/docs/public-ca-tutorial)取得 EAB；下列命令由操作者在已登录的 gcloud 环境执行，本项目不会创建 Cloud 项目或申请权限。

Production EAB（在私有目录中运行，避免保存到共享目录）：

```sh
umask 077
gcloud publicca external-account-keys create --format=json > gts-production-eab.json
```

Staging 需要**单独的 staging EAB**，官方教程要求将 Public CA API endpoint 暂时切换到测试环境：

```sh
umask 077
gcloud config set api_endpoint_overrides/publicca https://preprod-publicca.googleapis.com/
gcloud publicca external-account-keys create --format=json > gts-staging-eab.json
gcloud config unset api_endpoint_overrides/publicca
```

如果原来已设置该 override，应记录并恢复原值。不要并行在同一 gcloud 配置生成两个环境的 EAB。gcloud 输出为 JSON，包含 `keyId`、`b64MacKey` 和可选 metadata；运行前用本项目的本地导入命令转成私有 TOML：

```sh
moon-naive-acme import-eab gts-staging-eab.json /etc/moon-naive/gts-staging-eab.toml
```

命令不访问 CA/DNS，不在终端打印密钥，生成 0600 文件并拒绝覆盖已有目标；输入也须是私有普通文件，父目录须可信。目标 TOML 字段是 `key_id`、`b64_mac_key`，然后将 `eab_credentials_file` 指向它。Production 的导入方法相同，但必须使用自己的 production EAB。主配置、用户和 DNS/EAB 的运行配置均为 TOML；JSON 只用于 gcloud 导出导入、远端 API 协议和内部状态。密钥不放公开主配置/版本管理、不作为命令行参数、不发进聊天。Porkbun 和 EAB 文件都必须是当前运行用户可读的私有 0600 普通文件，禁止软链接。

未使用的 GTS EAB 有效期为 7 天，每份只能绑定一个账户，成功后即消耗；staging 和 production 不通用。管理器先持久化账户私钥，注册成功后保存账户 URL；重启和续期复用账户，不要求重复生成 EAB。若账户注册响应丢失，先用相同持久化 key 查询已存在账户，再决定是否注册。已成功注册后可移除启动用 EAB 文件（配置路径可保留），但必须妥善备份整个私有 `state_dir`；丢失账户状态时，已消耗的 EAB 无法用于创建新账户。

建议先复制推荐配置，填入实际 domain、dns_zone、contact 和两个私有文件路径：

```text
moon-naive check-config /etc/moon-naive/config.toml
moon-naive-acme check-ca /etc/moon-naive/config.toml
```

这两步不创建账户、不改 DNS；`check-config` 不读取密钥。接受 GTS 条款后设置 `accept_terms = true`，用 staging 凭据执行 `moon-naive-acme run /etc/moon-naive/config.toml`，确认实际签发/恢复；再停止 worker，将 `environment` 改成 `production` 并换成 production EAB 文件，重新启动。不同 environment 使用独立账户 journal。切换前若仍有待清理 TXT，应先用原配置运行 cleanup。Production 启动后由常驻 run 自动续期。

已有 CAA 限制时需允许 Google 的 `pki.goog`，例如 `0 issue "pki.goog"`；不需要因为没有 CAA 就主动增加，本程序不会覆盖原有 CAA。签发归属由 GTS 端点及正常证书链验证确定，不将叶证书 issuer 的某个固定显示名称写死。

GTS 测试根已附带，仅用于默认 Google staging 目录所签证书的校验；不会加入 production、CA API 或 Porkbun HTTPS 的信任库，也不会使 staging 证书获得浏览器信任。

官方参考：[Porkbun API](https://porkbun.com/api/json/v3/documentation)、[GTS Public CA](https://docs.cloud.google.com/certificate-manager/docs/public-ca-tutorial)、[GTS ACME 建议与 CAA](https://pki.goog/updates/september2025-acme-best-practices.html)。

## 使用

构建独立证书工作进程，根 workspace 仍可保持轻量测试：

```text
cargo build --manifest-path native/Cargo.toml --release --locked --bin moon-naive-acme
native/target/release/moon-naive-acme --help
native/target/release/moon-naive-acme run /etc/moon-naive/config.toml
```

`run` 持续执行签发/续期/恢复；`once` 只执行当前计划允许的一次协调，不强制提前续期，重试/未就绪会返回非零；`status` 重新校验已安装证书，不向 CA/DNS API 发请求；`cleanup` 仅重试 journal 中记录的 DNS 清理，不创建 CA 订单。`check-ca` 仅通过验证的 HTTPS 读取 directory，不需要 token、不创建账户、不改 DNS。

ACME 当前仍用独立控制进程运行。后续同日已接入实验前端 `moon-naive-net`：它验证并观察磁盘 CURRENT，构造与共同发布 H2/H3 TLS generation，已有实际双协议热加载测试。生产入口 `moon-naive serve` 保留验收闸门；运行方式见 [NETWORK.md](NETWORK.md)。

仍支持 Let's Encrypt + Cloudflare，完整配置为 `config.example.toml`，私有凭据须转换为本轮 TOML 格式；ACME 部分如下。本用户的 Porkbun + GTS 路线使用上节的专用示例：

```toml
[acme]
enabled = true
environment = "staging"
challenge = "dns-01"
dns_provider = "cloudflare"
dns_zone_id = "实际的32字符ZoneID"
dns_token_file = "/etc/moon-naive/cloudflare.toml"
contact = "operator@example.com"
accept_terms = true
renew_before_secs = 2592000
retry_initial_secs = 60
retry_max_secs = 21600
request_timeout_secs = 30
operation_timeout_secs = 900
poll_interval_secs = 5
```

Zone ID 不是 Account ID。Token 放私有 TOML 文件中，内容为 `api_token = "实际 token"`，禁止软链接，文件权限 0600；日志不输出 token、JWS、私钥或原始 API 错误响应。Cloudflare token 需对指定 zone 有 DNS Edit 和 Zone Read 权限；不需要账户级 API Key。旧版仅含 token 的纯文本文件需要先转换。

确认使用 staging 后，再将 environment 改成 production。不同 directory/domain 使用独立账户 journal，但共享本机 manager 锁；若其他 issuer 尚有待清理 TXT，先用原配置执行 cleanup，避免切换 CA 时遗弃记录。不要删除 state 来“重试”，这会丢失账户、退避和 cleanup 信息。

默认 Let's Encrypt staging 已带入两个官方测试根，仅用于验证 staging 签发的证书。**它们不会让浏览器信任 staging 证书**，也不加入 production 验证器、CA API 或 Cloudflare API 的 HTTPS 信任库。公开浏览器访问需要 production 证书。

私有/本地测试 CA 可配置 `directory_url`（必须 HTTPS）、`directory_ca_file`（CA API 的 HTTPS 信任）和 `certificate_ca_file`（所签证书的链信任）。二者不同；DNS provider HTTPS 不接受 directory_ca_file。没有跳过 TLS 或主机名校验的生产开关。

## 存储与恢复

```text
state_dir/
  acme/
    manager.lock                     # 0600，kernel lock，保留文件
    journal-<directory+domain hash>.json
  certificates/
    writer.lock                      # 0600，kernel lock，保留文件
    CURRENT
    generation-*/chain.pem
    generation-*/key.pem
    generation-*/lifetime
```

目录 0700、状态/私钥文件 0600，父目录必须可信。journal 含账户和当前订单密钥，应作为秘密备份。旧证书保留，当前实现不自动 GC 历史 generation。

本轮把旧版证书存储的目录锁改为 Rust 1.89 kernel 文件锁，进程崩溃后 OS 释放锁，不依赖猜测 PID 或删除锁文件。若检测到旧版 `writer.lock` **目录**，仍拒绝自动删除；仅在确认旧 writer 已停止、校验 CURRENT 后显式处理该旧锁。这是旧版状态迁移，不是新版正常重启要求。

证书提交点之后 fsync 失败或 journal 写入不确定时，管理器停止继续下单，交由重启读取并验证 CURRENT。CURRENT 已有效安装但 journal 仍指向同一 key 的旧订单时，恢复会完成该事务，不重复申请。newOrder 本身没有通用幂等 token，响应丢失而没有 URL 的间隙只能通过已持久化 cooldown 限制重建，不能承诺严格 exactly-once。

SIGTERM/SIGINT 会取消当前网络流程并尝试限时清理；若清理失败，保留 journal 供下次启动恢复。日志提供 `last_failure_phase`（如 dns-present、dns-propagation、finalize、certificate-validation）；不输出可能含秘密的第三方原始错误。

`deploy/moon-naive-acme.service` 是未安装的 systemd 模板，适用于独立 worker。安装前需已有 `moon-naive` 用户、程序和配置文件，且 config.state_dir 对应 `/var/lib/moon-naive`。模板使用 Restart 与网络就绪依赖；本轮未对 VPS 执行安装或启动。

## 复现本地 CA 测试

Pebble v2.7.0：commit `bbe7775c27078417e379287a431fa5a716a6788d`，构建 `cmd/pebble` 与 `cmd/pebble-challtestsrv`。测试程序自行分配 loopback 端口、生成隔离 CA、启动并回收子进程，不绑定公网 443、不写公网 DNS。

```text
PEBBLE_BIN=/absolute/path/pebble
CHALLTESTSRV_BIN=/absolute/path/pebble-challtestsrv
PEBBLE_SOURCE=/absolute/path/pebble-source
cargo test --manifest-path native/Cargo.toml --locked --test acme_pebble -- --ignored --nocapture
```

三个变量需作为该命令的环境变量设置。测试服务 challtestsrv 模拟递归 DNS，原始响应不含 AA；测试 harness 用 Rust UDP 权威 facade 显式补 AA。生产查询仍要求权威回答，没有为测试关闭该检查。

普通 `cargo test --manifest-path native/Cargo.toml --locked` 会跑本地单测，并明确把外部 Pebble 测试标为 ignored；不能把 ignored 当作本地 CA 验收通过。本轮已经显式执行该测试。

---

<a id="architecture"></a>

## 原文件：docs/history/ARCHITECTURE.md

# 面向网站行为一致性的架构优化（2026-10-21）

后续进展：同日 ACME 实施已完成真实单域名 DNS-01 工作进程和本地 CA 验证，详见 [ACME.md](ACME.md)。本文件的“ACME 尚未实现”描述保留架构审查时点的状态；网站/listener 的未完成项仍有效。

本次用户确认：服务端兼容性沿用原服务端，不要求嵌入 Chromium net/。
当前只保留 Pingora H2 + BoringSSL + Cloudflare quiche H3；官方 Naïve 客户端是兼容基线。网站现使用完整 Pingora HttpProxy，QUIC/TCP BBR 独立配置，当前架构和边界见 [WEBSITE.md](WEBSITE.md)。本文件其余内容保留初期设计背景，未宣称生产验收通过。
目标是在既有约束内减少可观察的异常行为；目前没有实测证据可以称为“最强”或证明封锁概率降低。

## 源码审查结论

| 现状 | 影响 | 本次处理 |
| --- | --- | --- |
| `auth::route` 只有 Site/Tunnel 结果，无网站请求边界 | 两个 adapter 容易各自处理私有 header、扩展 CONNECT 和网站回落 | 增加共享 `ingress::dispatch`，清理网站请求中的代理字段，拒绝已认证的非普通 CONNECT |
| 缺少响应 Padding 生成 | 协议正确性和头部长度分布尚无保证 | 增加与 pin 版本 forwardproxy 同分布的生成器和独立向量 |
| H3 空闲时长、流数、窗口写死 | TOML 与实际协议配置容易分离 | 增加 `TransportProfile`，H3 接缝读取共享配置；H2 应用尚待实现 |
| 网站仅有 `site_root`，没有 handler | 不能验证浏览器、preamble 或未认证探测的实际行为 | 把真实网站和同栈网站对照设为网络实现的首批门槛 |
| 证书快照只有 PEM 与生命周期 | 尚不保证 TCP/UDP 握手同时切换已构造 TLS 上下文 | 明确运行时 generation 的原子发布边界，见下文 |
| 领域代码与原生依赖隔离 | 轻量测试有效，但不能证明网络可用 | 保留隔离，native 显式依赖 core；不提前开放 `serve` |

本次新增的都是领域边界与配置接缝。listener、网站文件服务、DNS/dialer、流式 pump、真实 ACME 仍未实现。

构建来源也要区分：同级 `boringssl/` 的 pin 是调研源码，当前 Cargo 实际编译的是 `boring-sys 5.2.0` 自带的 BoringSSL 及其构建补丁，并不自动使用该调研仓库。发布证据必须记录 Cargo.lock、features、构建工具链与实际源来源；不能拿调研仓库的 HEAD 充当最终 TLS 库来源证明。

## 优先级与取舍

1. 先保证官方协议兼容和未认证时的真实网站行为，再评估传输参数。
2. 同一公开前端负责网站与 CONNECT；认证结果不切换 TLS、H2 SETTINGS、H3 SETTINGS 或 QUIC transport parameters。
3. 使用成熟实现的稳定默认行为，记录依赖版本；不增加随机 cipher 顺序、伪造 Server 标头、定时心跳、全流量自定义填充或私有协商。
4. 自定义客户端扩展仍允许作为后续实验，但本次没有引入；需要独立对照后才决定是否启用。

H2/H3-only 会拒绝常见的 H1 与无 ALPN 连接；关闭 0-RTT 会改变恢复握手行为；延迟 200 与原 forwardproxy 的提前 200 有时间差异。这些是继续保留的用户约束，不描述为伪装收益。网络兼容范围是官方客户端的 H2/H3 使用路径，不是原服务端全部协议与逐包输出。

## 目标数据面

```mermaid
flowchart TD
    TCP[TCP / TLS / Pingora H2] --> HEAD[HTTP 语法与大小限制]
    UDP[UDP / quiche H3] --> HEAD
    PROFILE[共享 TransportProfile] --> TCP
    PROFILE --> UDP
    HEAD --> ROUTE[逐流 ingress dispatch]
    ROUTE -->|普通请求或认证失败| SITE[同一个真实静态网站 handler]
    ROUTE -->|已认证普通 CONNECT| QUOTA[隧道额度与内存预算]
    QUOTA --> DNS[有界解析 / 每个候选 IP 的 ACL]
    DNS --> DIAL[直接拨已校验 IP]
    DIAL --> READY[Admission Ready]
    READY --> SUCCESS[200 + Padding / 不结束响应流]
    SUCCESS --> PUMP[独立双向 codec / 背压 / 半关闭]
```

图中除领域状态机和配置接缝外，网络组件均是待实现设计。

### 请求分流与能力边界

- adapter 负责协议语法、伪头顺序/重复、普通 header 的大小与数量上限、非法 connection-specific 字段；不得把任意未验证头部交给业务层。
- adapter 只能调用共同的 `ingress::dispatch`，不维护连接级“已认证”标记。`TunnelRequest` 字段私有，只有认证后的 dispatch 能生成它；未来 egress API 以它为输入，而非任意字符串目标。
- 缺失、错误、重复凭据均进入网站路径；目标 authority 的私有校验不先于认证。协议层本身非法的消息仍按 HTTP 标准由 adapter 处理。
- 网站只获得清理后的普通字段；不接收 Proxy-Authorization、Padding、padding-type-* 等。不得同时把未经清理的请求传给 handler 或记录到日志。
- 普通 header 值按原始字节保留，不要求全部为 UTF-8；仅 Basic 认证值按 ASCII/UTF-8 解析，非法认证文本进入相同网站路径。
- CONNECT 目标 authority 与节点 SNI 是不同语义，不要求二者相等。网站 host/path 校验由网站自身执行；不得把恶意 authority 写入重定向或当成反代地址。
- 当前 `auth::route` 保留为兼容的低层策略函数，生产 adapter 应使用完整 dispatch 边界。纯函数测试没有网络出站能力；未认证出站计数为零仍需网络阶段验证。

### 真实网站是公开服务

先实现固定 `site_root` 的静态网站，避免额外网站反代进程及其请求头传播边界。准备真实首页、CSS/图片资源、合理链接及错误页，不根据 Padding、凭据错误类型或 User-Agent 输出专用“掩护页”。preamble 与浏览器访问同样内容。

GET/HEAD、Content-Type、Content-Length、缓存验证（ETag/Last-Modified/304）、404/405、压缩行为必须内部一致，H2/H3 使用同一实现。HEAD 保留对应 GET 的元信息且不发送正文。所有公开错误都由相同的响应构造层生成；站点响应无代理专用 header，不提供公网指标或健康诊断接口。

先支持确实实现并测试的常见语义，不为了看似完整而宣告未实现的 Range/压缩。文件读取必须有路径归一化、根目录约束、symlink 策略和有界流式读取。网站不拥有任意出站能力；ACME/DNS 是独立控制面出站，不计入网站数据面指标。

在相同 native 前端、相同内容和配置下，用测试 harness 将所有请求交给网站，形成“只有网站”的对照。不要另写一个具有不同 TLS/HTTP 行为的伪站点作为对照。

### 隧道兼容边界

- 仅普通 CONNECT；不误启 extended CONNECT、MASQUE 或 CONNECT-UDP。
- legacy 模式读取请求的**首个 Padding 字段的值是否非空**。仅 `padding-type-request` 不启用 codec，不新增 `padding-type-reply`。保留原服务端行为：成功响应即使对无填充流也生成 Padding，但该流数据仍为原始字节。
- 响应 Padding 长度均匀分布 30..61，前 16 字符来自 `!#$()+<>?@[]^\x60{}`，其余为 `~`。调用方为每次响应提供新的密码学随机输入；测试注入固定向量。此算法不尝试保证 HPACK/QPACK 编码器一定选择不索引，实际编码策略须单独验证。
- 原始字节 → encoder 只执行一次。短写持有已编码 buffer 和 offset，不能重试编码。两方向、每个 CONNECT 各自持有 codec 状态。
- DNS/ACL/目标 connect 成功后才能 commit 200；响应不带 Content-Length、Transfer-Encoding、Content-Encoding 或 END_STREAM。早到 DATA 有界暂存，不能误当 TLS 0-RTT 拒绝。
- 已消费且下游缓冲有容量后才归还相应流控 credit。QUIC/H2 库缓冲、应用队列、已编码待发字节与早到 DATA 都计入预算；增大 wire 窗口不能替代内存上限。
- 双向 pump 独立处理 FIN、RST、取消和超时；单向结束不立即杀死另一方向。站点的压缩/缓存中间件不触碰隧道流。

### 资源与协议配置

`TransportProfile::from_config` 是启动时统一推导点：空闲超时、并发双向流数、单流接收窗口、连接接收窗口。连接窗口暂设上限 16 MiB，H3 控制流另有固定有界余量；这是资源起点，没有指纹优化或吞吐最优的实测结论。

H2 将这些值应用到 builder/运行时流控，H3 应用到 quiche Config。两者还需要共同的 header 限额、请求 deadline 和应用预算；相同资源目标不意味着两种协议参数能逐项相等。QUIC 的连接数限制是累计流开放信用，还需活动流 permit 独立约束。H2 不能把单流 idle timeout 当作连接空闲时长。

网站流与隧道共享连接的协议参数，应用层为网站请求保留资源余量，限制已认证隧道占用，避免代理负载耗尽时首页失效。额外设置全局缓冲字节预算与认证后的用户额度；现有 `max_buffer_bytes_per_stream * max_streams * max_connections` 不是可接受的内存容量承诺。

TCP/UDP 使用同一证书域名与公开端口策略。仅在 H3 listener 实际就绪、证书可用、UDP 外部可达性验证后，给网站输出真实可用的 Alt-Svc；监听绑定端口不一定是 NAT 后的公开端口，不能盲目拼接。H3 不可用时撤销宣告，不能靠修改认证路径的设置掩盖错误。

## 证书与控制面

保留现有 issue → 密码学校验 → 持久化 → publish 顺序、DNS-01 与失败保留旧证书。补齐真实驱动时，引入运行时 `TlsGeneration`：

1. 同一候选证书校验 SAN、链、有效期、私钥匹配。
2. 在独立控制执行器构造 H2 TLS 上下文和 H3 可用配置；任何构造失败均不提交。
3. 持久化完整 generation 并提交 CURRENT。
4. 一个共享 `Arc<TlsGeneration>` 指针发布两个已准备好的传输上下文；握手只加载一次 generation，已建立连接持有旧引用。

现有 `CertificateSlot` 尚未做到上述双上下文构造与发布。H3 driver 需验证 quiche 的配置/现存连接 ownership，不能在数据面写锁中重建 Config。磁盘与内存之间无法用一次 CPU 原子操作共同提交；重启以已验证的 CURRENT 恢复，提交不确定仍按现有 suspended 策略处理。

ACME HTTPS/JWS、DNS API、权威传播检查、账户/订单、TXT cleanup journal、ARI、退避与抖动独立于数据面。文件 fsync、证书解析与 DNS propagation 不阻塞数据面 worker；控制队列有界。管理状态经本地 socket/CLI 输出，日志不含凭据、私钥、原始 header 或目标域名。

## 行为验证与推进门槛

先完成 Linux native 编译/链接关卡，再实现业务 adapter。随后按以下顺序推进，H2/H3 均通过后才开放生产服务：

| 阶段 | 交付与证据 |
| --- | --- |
| 1. 网站前端 | 严格 ALPN、无 H1/0-RTT，真实网站；浏览器和 preamble；未认证出站为零；网站对照 |
| 2. H2 CONNECT | 共享 dispatch、真实 DNS/ACL/dial、延迟 200、legacy Padding、双向 pump；官方当前及旧稳定客户端 |
| 3. H3 CONNECT | 同一业务路径；UDP 路由/定时器、控制流、背压、迁移、reset/cancel；相同 payload 对拍 |
| 4. 证书控制面 | Pebble → staging，真实 SAN/key/chain 校验、故障恢复、H2/H3 generation 切换 |
| 5. 行为与稳定性 | 下述差分矩阵及 24h 网络 soak，随后部署 |

差分测试使用三个对象：同栈网站对照、固定版本 Caddy+forwardproxy 参考部署（仅测试）、本项目。参考部署明确记录 H1/Fast Open/0-RTT 差异；不要把用户约束造成的差异隐藏在归一化规则中。

采集 TLS 协商/恢复/错误、H2 SETTINGS/窗口更新/GOAWAY、QUIC transport parameters/H3 SETTINGS/QPACK/关闭语义、网站响应头与资源语义、连接复用下的包长/间隔分布。网络时间与随机字段采用重复实验和分布比较，payload 与确定性 codec 则逐字节比较。对结果记录客户端/库版本、网络条件、内容、证书代数及样本量；依赖升级重跑受影响矩阵。

网络探测矩阵覆盖正常浏览器、无认证 CONNECT、错误/重复/畸形凭据、非空/空/重复 Padding、只给版本头、异常目标、认证后普通 GET/HEAD、同连接先隧道后未认证请求。已知凭据的主动客户端当然能使用代理，不能把它纳入“与纯网站不可区分”的承诺。

通过标准：相同公开请求在网站对照与本项目得到相同应用语义且无代理专属响应；未认证数据面 DNS/目标连接为零；官方 H2/H3 payload 无损；取消/故障后资源回归；无依赖认证结果的握手/SETTINGS 切换。性能和时间分布先建立可重复基线，再设置阈值，不能凭一次抓包认定伪装成功。

本文件定义设计与验收，不代表网络实验已经执行。

---

<a id="build-and-use"></a>

## 原文件：docs/history/BUILD-AND-USE.md

# moon-naive 当前可用范围、构建与使用（2026-10-22）

项目现名 **moon-naive**，主配置和运行时凭据均为 TOML。当前有真实 H2/H3 实验前端和独立 ACME worker；`moon-naive serve` 仍保留完整生产验收闸门，实际网络命令为 `moon-naive-net run <config.toml>`。配置格式与旧版迁移见 [CONFIGURATION.md](../CONFIGURATION.md)，本轮验证范围见 [MOON-NAIVE-VERIFICATION.md](MOON-NAIVE-VERIFICATION.md)。

## 距离实际节点还有哪些工作

| 部分 | 已有实现 | 还需完成的工作 |
| --- | --- | --- |
| H2 接入 | Pingora/BoringSSL TCP/TLS、严格 H2 ALPN、请求/流控/GOAWAY | 目标系统及公网网络行为验收 |
| H3 接入 | quiche UDP、QUIC Retry、定时/发送节奏、H3 请求/流控/GOAWAY | 丢包/重排/MTU 测试；目前关闭主动迁移 |
| 隧道 | DNS/逐候选 ACL/双栈拨号、连接成功后 200、双向 Padding/背压/半关闭/取消、共享空闲计时、全局接收窗口预算 | 故障注入、压力/长时间网络测试、完整运行告警 |
| 网站 | 真实有界静态站点、GET/HEAD/404/ETag、路径及 symlink 限制、两协议共享 handler | 浏览器与参考网站网络行为差分；暂无动态站点、Range 或压缩 |
| 用户配置 | 私有 users.toml、1..256 个用户、逐流认证、失败回网站 | 独立每用户额度、凭据热加载（当前修改后重启网络进程） |
| 证书使用 | 实际 ACME/GTS EAB/Porkbun、原子 CURRENT、双协议 TLS generation 热加载 | 真实域名与公网 GTS/Porkbun 联调 |
| 兼容与稳定性 | 单测、本地真实 CA、官方 Linux 发布版 H2/H3 测试 harness | 更广版本/平台、24h 网络稳定性与站点对照；已执行矩阵见验证记录 |
| 发布运维 | Cargo 构建、锁文件、上游 pin 审计、独立 ACME systemd 模板 | 整合正式服务入口、部署包、服务启动/优雅停止、目标系统验收和必要的运行告警 |

已实现的实验前端可使用本机有效证书启动；替换现用节点前还需上述公网与稳定性验收。多 CA 自动回退、多 SAN/通配符、分布式锁和按需签发属于当前范围外的扩展；它们不是这个单域名单机节点必须先补齐的功能。OCSP stapling 是否需要取决于实际证书和 TLS 运行时，不把它当成所有 GTS 证书的普遍前置条件。

后续推进重点为公网 CA/DNS 联调、目标 VPS 与网络行为差分、故障与长时间稳定性验收。ACME 与 H2/H3 实际网络入口已经接通。

除开发外，最终部署还需要实际域名及 zone、联系人邮箱、Porkbun API 私有凭据、首次注册所需的 GTS EAB、代理用户凭据、网站文件和明确的 Linux 目标系统。实际代理访问需要正确的 A 记录；只在 IPv6 确实可用时配置 AAAA。最终需要公网 TCP/443 与 UDP/443，权限、防火墙和 NAT 均需适配；目前示例的 loopback:8443 只是配置检查起点。

DNS-01 证书申请不需要开放入站 80，也不要求入站 443 已在监听。证书工作进程需要出站 HTTPS、DNS 解析及访问权威 NS 的 UDP/TCP 53、可写私有状态目录、正确系统时间和 CA 信任库。申请证书成功与代理端口可达是两项独立验收。

## 与原 xcaddy 路线的区别

原路线是 `xcaddy + Caddy + klzgrad/forwardproxy`。xcaddy 在构建时把 Go 模块编入一个定制 Caddy 二进制；运行时启动的是 Caddy，不运行 xcaddy。Caddy 负责网站、TLS/ACME、HTTP/QUIC listener 和大部分生命周期，forwardproxy fork 提供代理和 Naïve Padding。

| 项目 | 原 Caddy/xcaddy 路线 | 当前 moon-naive |
| --- | --- | --- |
| 构建入口 | xcaddy，Go 构建工具链 | Cargo/Rust；原生依赖另需 C/C++/Clang/CMake 等 |
| 运行程序 | 定制 caddy | moon-naive 配置工具、独立 moon-naive-acme、实验前端 moon-naive-net |
| 配置 | Caddyfile 或 Caddy JSON | 主配置与用户/DNS/EAB 均为严格 TOML，不解析 Caddyfile |
| HTTP/TLS/QUIC | Caddy 的 Go 实现及其 QUIC 依赖 | 真实 Pingora H2、BoringSSL、Cloudflare quiche H3 |
| Naïve 功能 | klzgrad/forwardproxy 中的实现 | Rust 认证/分流/Padding/门禁、双协议网络 adapter |
| 网站与续期接线 | Caddy 已有完整基础设施 | 共享静态站点、独立 ACME、观察 CURRENT 后热更新双协议握手 |
| DNS 扩展 | 通常由 Caddy DNS provider 模块提供，按需编入 | 原生 Porkbun/Cloudflare provider，不使用 shell DNS hook |
| 当前成熟度 | 原路线是已有可部署实现 | 尚在开发与集成阶段，未证明能替换原节点 |

原项目 naiveproxy/README 的构建命令为：

```sh
xcaddy build --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@naive
```

这是对原路线的说明，不是 moon-naive 的构建步骤。固定版本 forwardproxy 的发布 workflow 还给 Caddy 应用了 sing-quic/BBRv1 补丁，因此 README 的简单构建和其发布产物也不应视为逐项相同。moon-naive 没有承诺复制这些拥塞控制补丁。

切换语言和依赖栈不会自动保留 Caddy 的 TLS、H2、QUIC 指纹，也没有“因为使用 BoringSSL 就具有 Chromium 完整网络行为”的结论。当前目标是兼容官方客户端的 H2/H3 与 legacy Padding 路径，并验证正常网站行为；不承诺逐包等同 Caddy。H1、Fast Open、0-RTT 的禁用约束继续有效。

## 源码目录与固定依赖

当前工作目录为 `/workspace/naive-pingora-resume/moon-naive`，源码包解压后顶层目录也是 `moon-naive/`。保留同级上游布局：

```text
moon-naive-workspace/
  moon-naive/           本项目，两个 Cargo workspace
    Cargo.toml
    crates/
    xtask/
    native/Cargo.toml
  pingora/           Cargo 原生路径依赖
  quiche/            Cargo 原生路径依赖
  instant-acme/      Cargo 原生路径依赖
  boringssl/         调研源码及 pin 审计
  naiveproxy/        兼容参考及 pin 审计
  forwardproxy/      原服务端参考及 pin 审计
```

源码包只包含本项目，不把六个上游仓库或构建产物打入包。原生构建直接依赖其中的 pingora、quiche、instant-acme；`xtask verify` 和 `audit-native` 还要求其余三个审查仓库存在、HEAD 与下表一致且工作区干净。普通根 workspace 的 `cargo build/test` 不需要编译这些原生库；不要把原生目录随意移到其他层级。

| 仓库 | origin | 固定 commit |
| --- | --- | --- |
| pingora | https://github.com/cloudflare/pingora.git | `4487f7b2ab50f159e4a2cf4f6a6b813f61bb6e19` |
| quiche | https://github.com/cloudflare/quiche.git | `925b225825e2188f8e58e359114150500557bf61` |
| instant-acme | https://github.com/djc/instant-acme.git | `4a9b80fdc22f23ab39b78dfd20ff5d4c92938e52` |
| boringssl | https://github.com/google/boringssl.git | `5b83e5d1abf0ae0033ae52ab579d906b67633b2c` |
| naiveproxy | https://github.com/klzgrad/naiveproxy.git | `0539676ac91d9607caa00869b709e66643b91ac5` |
| forwardproxy | https://github.com/klzgrad/forwardproxy.git | `c096d6a00cb28e019cc1995b04bdc6a9311d8024` |

已有原交接包的对应上游时可继续使用，不要重复覆盖。全新机器先在 moon-naive-workspace 下 git clone 表中的仓库，再逐个 `git -C <仓库> checkout --detach <commit>`；不要直接用其当前 main 替代 pin。

实际构建的 BoringSSL 来自 `boring-sys = 5.2.0` crate 自带源码及构建补丁，并不是直接编译同级调研用 boringssl/。`boring`、`boring-sys` 固定 5.2.0，`tokio-boring` 固定 5.0.0。仅保留 BoringSSL/quiche，`audit-native` 拒绝额外 TLS 引擎；`rustls-pki-types` 本身不执行 TLS。网站引擎、反代配置及 BBR 预检见 [WEBSITE.md](WEBSITE.md)。

## Linux 构建要求

当前实测为 Debian 13 / Linux x86_64，Rust/Cargo 1.89.0、GCC 14.2、CMake 3.31.6、libclang 19。manifest MSRV 为 Rust 1.89；其他架构/系统仍需独立原生构建与验收，未证明跨目标可直接复制二进制。

需要 Rust/Cargo、git、C/C++ 编译器、Clang/libclang、CMake、Perl、pkg-config 与系统 CA；Ninja 可用作构建工具。Debian/Ubuntu 上常见的准备方式如下，Rust 使用 rustup 单独安装：

```sh
sudo apt-get update
sudo apt-get install build-essential clang libclang-dev cmake ninja-build perl pkg-config git ca-certificates
rustup toolchain install 1.89.0 --profile minimal --component rustfmt,clippy
```

以下命令假定当前选择的 Rust 至少为 1.89；若使用上述独立 toolchain，可将 `cargo` 写成 `cargo +1.89.0`。找不到 libclang 时按本机实际 LLVM 版本设置 LIBCLANG_PATH；不要照搬其他架构的 GCC include 路径。构建需要 crates.io 和上游源码可用，或预先准备相同 lockfile 对应的缓存。

Cargo 会驱动原生构建，不需要 xcaddy、Caddy 服务进程或生产用 Go 工具链；这不等于只安装 rustc 就能编译，也不等于产物是跨发行版通用的全静态二进制。部署前以目标系统构建/验证，并检查 `ldd` 依赖。Go 仅用于显式运行 Pebble 测试时构建测试 CA，日常证书管理不需要 Go。

## 构建当前三个产物

从 moon-naive/ 目录执行：

```sh
cargo build --workspace --release --locked
cargo build --manifest-path native/Cargo.toml --release --locked --bin moon-naive-acme --bin moon-naive-net
```

| 产物 | 当前位置 | 当前用途 |
| --- | --- | --- |
| moon-naive | `target/release/moon-naive` | 配置校验、框架状态；serve 明确拒绝启动 |
| moon-naive-acme | `native/target/release/moon-naive-acme` | 实际签发/续期/恢复/证书状态 CLI |
| moon-naive-net | `native/target/release/moon-naive-net` | 真实 H2/H3 实验前端；需要已安装有效证书 |
| xtask | `target/release/xtask` | 开发验证与模型 soak，不是服务进程 |

根 workspace 包含 moon-naive-core、moon-naive-control、moon-naive 和 xtask；native 是独立 workspace，包名 moon-naive-native。分开是为了让协议/控制面核心能快速测试，同时把 BoringSSL/Pingora/quiche 的工具链和编译成本隔离。根目录只运行一次 `cargo build` 不会构建 moon-naive-acme。目前没有一个已经整合好数据面和 ACME 的生产服务二进制。

## 现在可以执行的操作

先使用推荐配置，不要把 Caddyfile 直接传给 moon-naive：

```sh
./target/release/moon-naive --help
./target/release/moon-naive check-config config.porkbun-gts.example.toml
./target/release/moon-naive status
./native/target/release/moon-naive-acme --help
./native/target/release/moon-naive-acme check-ca config.porkbun-gts.example.toml
```

`check-config` 检查 TOML 结构与策略，不读取私有文件、不验证站点存在、不下单；`moon-naive status` 是框架能力说明，不是服务健康探测。`check-ca` 使用正常 TLS/主机名验证，只读取 GTS directory，不注册账户、不写 DNS，也不需要先有 Porkbun/EAB 文件。不要把这些成功当作代理可用。

实际证书管理的主机路径为：

```text
/etc/moon-naive/config.toml
/etc/moon-naive/porkbun.toml       0600 TOML，apikey + secretapikey
/etc/moon-naive/gts-eab.toml       0600 TOML，key_id + b64_mac_key
/var/lib/moon-naive/                私有状态目录，运行用户可写
/srv/moon-naive/site/index.html   文件网站入口，按请求异步读取；files=false 时可省略
/etc/moon-naive/users.toml        0600 TOML，[[users]] 数组表
```

私有凭据文件禁止软链接，状态目录 0700、其中密钥/journal 0600。配置示例见 [CONFIGURATION.md](../CONFIGURATION.md)。使用实际 domain、dns_zone、contact，确保权威 NS 是 Porkbun，并按 [ACME.md](ACME.md) 取得对应环境的 GTS EAB。ACME 不读取 users.toml 或 site_root，可以先独立申请证书。

接受 GTS 条款后设置 `accept_terms = true`，先使用 staging EAB 验证完整签发与恢复；再停止 worker，改 environment 为 production、换成 production EAB。`.dev` 的浏览器访问需要受信任的生产证书，staging 仅用于测试。两环境的 EAB 不能混用；首次成功后账户持久化，续期不需要重新生成 EAB。若已有 CAA 限制，应允许 pki.goog。

在已准备好私有文件、运行用户与可写 state_dir 的主机执行：

```sh
./native/target/release/moon-naive-acme run /etc/moon-naive/config.toml
```

证书就绪后，在另一个进程启动网络前端（ACME worker 保持常驻以自动续期）：

```sh
./native/target/release/moon-naive-net run /etc/moon-naive/config.toml
```

该命令在启动前检查私有用户文件、站点和当前证书，TCP/UDP 两个绑定都成功后才运行；收到 SIGTERM/SIGINT 后按 graceful_timeout_secs 排空。网络进程每 5 秒检查 CURRENT，证书轮换同时发布新的 H2/H3 TLS 上下文，旧连接保留已有上下文。

| ACME 命令 | 行为 |
| --- | --- |
| `run <配置>` | 常驻，自动申请、续期、故障退避、重启恢复；可能创建 CA 账户/订单并写入和清理 TXT |
| `once <配置>` | 执行当前调度允许的一次协调，不强制提前续期；未取得有效证书或进入重试会非零退出 |
| `status <配置>` | 本地重新验证当前证书，不联系 CA/DNS；可能创建/锁定本地证书存储目录 |
| `cleanup <配置>` | 仅重试 journal 中自己的 TXT 清理，不创建 CA 订单；仍需要 DNS 凭据 |
| `check-ca <配置>` | 只读 HTTPS directory 检查，无 CA 账户或 DNS 写入 |
| `import-eab <gcloud JSON> <私有 TOML>` | 本地验证/转换，不访问网络，不覆盖现有目标 |

`once` 不是代替常驻 run 的自动续期服务。state_dir 保存账户私钥、EAB 绑定账户身份、订单、重试和清理记录，不能每次运行都清空；需要持久化与私有备份。

`deploy/moon-naive-acme.service` 是尚未安装的 systemd 模板，使用用户/组 moon-naive、程序 `/usr/local/bin/moon-naive-acme`、配置 `/etc/moon-naive/config.toml`、状态 `/var/lib/moon-naive`。操作者需准备匹配的用户、权限和程序后再安装启用。它只运行证书工作进程，不运行代理。当前没有可用的 moon-naive 主代理服务 unit。

执行 `./target/release/moon-naive serve` 会因完整生产验收尚未完成而非零退出，即使证书已经签出也不会开放端口。当前可运行的实验入口是独立构建的 `moon-naive-net run`。

## 验证方式与证据边界

```sh
cargo run --release --locked -p xtask -- verify
cargo run --release --locked -p xtask -- audit-native
cargo clippy --manifest-path native/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path native/Cargo.toml --locked
```

普通 native test 会显式跳过两个外部 Pebble 测试和一个官方客户端测试。要运行完整矩阵，先按 ACME.md 准备 Pebble v2.7.0 和 challtestsrv，将 PEBBLE_BIN、CHALLTESTSRV_BIN、PEBBLE_SOURCE 设置为本机路径；另外按最新验证记录准备未修改的官方 naive，设置 NAIVE_BIN 为其绝对路径，再执行：

```sh
cargo test --manifest-path native/Cargo.toml --locked -- --include-ignored --nocapture
cargo test --manifest-path native/Cargo.toml --release --locked -- --include-ignored --nocapture
```

官方版本/协议矩阵与下载 SHA-256 见 [MOON-NAIVE-VERIFICATION.md](MOON-NAIVE-VERIFICATION.md)，后续 TLS 1.3 修正及强制版本回归见 [SERVER-ARCHITECTURE-AND-PLAN.md](SERVER-ARCHITECTURE-AND-PLAN.md)。当前 native 每个 profile 为 29 项（含当前官方客户端用例）和两个 Pebble 集成测试，根 workspace 保留各 39 项证据。仅运行 CA 测试可使用 `cargo test --manifest-path native/Cargo.toml --locked --test acme_pebble -- --ignored --nocapture`，此时不要求 NAIVE_BIN。本地 CA 通过不代表 Porkbun/GTS 公网签发通过，短时数据传输不代表 24h 稳定性。

## 更名范围与旧状态迁移

| 原名称 | 当前名称 |
| --- | --- |
| 源码目录 server | moon-naive |
| 源码目录 pinaive | moon-naive |
| naived | moon-naive |
| pinaive / pinaive-acme / pinaive-net | moon-naive / moon-naive-acme / moon-naive-net |
| naived-acme | moon-naive-acme |
| naive-core / naive-control / naive-native-seams | moon-naive-core / moon-naive-control / moon-naive-native |
| deploy/naived-acme.service | deploy/moon-naive-acme.service |
| /etc/naived、/var/lib/naived、/srv/naived | 示例默认改为 /etc/moon-naive、/var/lib/moon-naive、/srv/moon-naive |

Cargo manifest、两个 lockfile、Rust imports、集成测试的二进制名、帮助文本、模板与当前操作文档同步更新。上游 NaïveProxy/Pingora/quiche 等不更名、不修改。旧验证日志和历史证据保留当时的名字，避免篡改已执行命令记录。

旧 TOML 的绝对路径并不要求必须包含 moon-naive，因此已存在的 `/var/lib/naived` 仍可作为显式 state_dir 使用。若先前签过证书，可保留原 state_dir；若要迁移，先停 worker、私有备份，再整体迁移目录并设置运行用户权限，保留账户/订单/cleanup journal 和 certificates/CURRENT。不要只复制 chain.pem 或新建空状态来“完成更名”；已消耗的 GTS EAB 不能替代丢失的账户状态。旧 lease 自身持久化了 marker，更名不会改变已有 marker 或清理匹配方式。此会话没有修改任何 VPS 的用户、目录或运行服务。

从 pinaive 的用户/Porkbun/EAB JSON、Cloudflare 纯文本迁移到 TOML 的具体格式见 [CONFIGURATION.md](../CONFIGURATION.md)。路径可以保留，内容必须转换；内部 journal 格式保持兼容。

---

<a id="design"></a>

## 原文件：docs/history/DESIGN.md

# H2/H3-only Naïve Rust 项目框架

2026-10-21 更新：用户已确认沿用原服务端兼容性，无需服务端 Chromium net/。本轮共享入口、资源配置与网站行为架构见 [ARCHITECTURE.md](ARCHITECTURE.md)；本文件继续说明原有领域核心与硬性约束。

后续同日已实现真实 ACME 工作进程，最新状态见 [ACME.md](ACME.md)。下文最初框架阶段的“真实驱动尚未实现”属于历史状态；当前仍未实现的是公开 listener 及其证书接线。

状态：用户 2026-10-14 要求直接建立框架并校验；本文件覆盖上一轮 FEASIBILITY 中允许 H1、提前 200 和推迟 H3 的建议。本轮交付可编译的领域核心、控制面状态机、配置检查工具、测试工具以及独立原生依赖接缝，不冒充已经可公网部署的完整代理。

## 不可变要求

- Rust/Cargo 构建；不依赖 Caddy、xcaddy 或 Go 服务端。BoringSSL 本身含 C/C++，Cargo 原生依赖构建仍需要 C/C++ 工具链，不是仅有 rustc 就够。
- 对外业务只提供 TCP/TLS/H2 与 UDP/QUIC/H3；没有 H1 listener/路由、无 ALPN/H1 fallback，两个协议都属于最终范围。
- 无服务端 Fast Open：认证、DNS、ACL、TCP connect 全部成功以后才能返回 CONNECT 200；失败在 200 前返回普通失败，不提前假定成功。
- 官方 Naïve 客户端缓存 padding 后可能自行提前发送 DATA。服务器无法通过现有协议强制关闭客户端这个内部优化。保持兼容的方法是有界暂存/背压，连接就绪前不向目标转发、不回 200；禁用 TLS/QUIC 0-RTT 是另一项独立约束。
- ACME 必須自动签发/续期/安装/失败重试，使用 DNS-01，不为 HTTP-01 暗开 H1/80。DNS API 的出站 HTTP 版本不等于公开 listener 的版本；公开 H1 始终关闭。
- ACME 失败不替换有效证书；首次无证书时不开放业务 listener。证书和私钥原子成组更新，现存连接保留旧快照。
- 测试工具使用 Rust；本轮无 VPS 登录、无 CA/DNS 写入、无生产凭据、无公网 listener。

## 构成

1. `moon-naive-core`：严格 TOML 配置、H2/H3 ALPN 策略、逐流认证、authority/出站 IP 检查、Naïve framing、CONNECT 建连门禁、RAII 资源额度。
2. `moon-naive-control`：续期调度、单任务防重入、有上限退避/Retry-After、异步 issuer/validator/store 接口、原子证书 generation 存储。真实 ACME 网络驱动和证书密码学验证不使用 mock 替代上线。
3. `moon-naive`：当前提供 `check-config` 和 `status`；`serve` 明确拒绝，直到真实 adapters 和上线验收接通。不能以空循环或模拟签发声称节点已运行。
4. `xtask`：Rust 验证入口和确定性长循环核心测试。核心 soak 不等于真实网络稳定性测试。
5. `native/`：独立 Cargo workspace，连接本地固定版本 Pingora、quiche、instant-acme 和同一份 boring 5。与手机上的轻量框架测试隔离，原生构建应在 Linux VPS 完成。

## 新的源码发现

- quiche commit `925b225825e2188f8e58e359114150500557bf61`，`quiche/Cargo.toml` 版本 0.30.0：默认 `boringssl-boring-crate`，允许 boring >=4.19,<6；boring-sys 的 links 约束可帮助它与 Pingora 的 boring 5 使用同一份库。仍需 Cargo.lock/依赖图和真实 Linux 链接证明，不能只读注释就宣布无冲突。
- instant-acme commit `4a9b80fdc22f23ab39b78dfd20ff5d4c92938e52`，版本 0.9.0：`Account::builder(Box<dyn HttpClient>, &'static CryptoProvider)`；HTTP 和签名 provider 均可替换。禁用默认 hyper-rustls/aws-lc 特性，计划提供 BoringSSL HTTP/crypto adapter，避免默认引入其他 TLS 实现。不是沿用旧版本 builder 的示例。
- Pingora H2-only ALPN callback 不能单独解决未提供 ALPN 的客户端：连接入口还须核对协商结果为 h2，拒绝进入框架默认 H1 fallback。

## 数据面

H2/H3 adapter -> `ingress::dispatch` 逐流认证/网站字段清理/普通 CONNECT 校验 -> authority -> 额度 -> DNS -> 每个候选 IP 的 ACL -> connect -> 200/Padding -> 两个独立方向的 codec/pump。CONNECT 目标 TCP 不加服务端 TLS。`TransportProfile` 为 H2/H3 提供共同资源策略；仅保留 BoringSSL/quiche。

未认证请求使用共同 Pingora 网站引擎，不根据 CONNECT authority 做 DNS/拨号或泄露代理认证错误。网站可解析管理员固定配置的上游域名并使用 H1/H2 连接池，客户端目标不能成为反代地址；配置与资源边界见 WEBSITE.md。公开网站仅支持 H2/H3，与提供 H1 的网站存在可观察差异，不宣称与 Caddy 指纹相同。

每流早到数据和队列有上限；达到上限停止读取，由流控背压。框架门禁在调用者违反边界时返回错误，native adapter 负责在超限前停止拉取 DATA。发送/读取分别持有状态，取消不能导致已发送字节重复。半关闭、RST、GOAWAY、QUIC STOP_SENDING/RESET_STREAM 都列入 adapter 验收。

## 证书控制面

DNS-01：恢复 ACME account/order -> 获取 challenge -> 幂等创建 TXT -> 检查权威传播 -> 通知 CA -> 按 Retry-After 轮询 -> finalize CSR -> 获取 chain -> 校验域名/有效期/key match/链 -> fsync generation -> 原子 CURRENT -> 更新证书快照 -> 删除自己创建的 TXT。

禁止 shell DNS hooks；使用 Rust provider。DNS token 仅授权必要 zone/TXT，不覆盖已有 TXT 集合。遇到 cleanup 失败要持久化待清理记录，不能无穷新建订单。account/order、单 writer 租约、ARI、DNS cleanup journal 和生产 CA 限流是后续真实 driver 的必需项，当前接口不能代替它们。

调度器时间由调用方注入，使用秒级 Unix 时间用于续期；网络 timeout 应使用单调时钟。续期提前量为配置窗口与证书总生命周期三分之一的较小者，避免短期证书刚签发就再次续期；ARI 可让真实驱动进一步调整。ARI/随机抖动由后续真实驱动集成，当前基础调度器使用确定性时序，不宣称已完成 CA 全部调度策略。失败保留旧快照并告警；过期不继续自称 ready。

磁盘 CURRENT 是唯一提交点。generation 文件全部写完/fsync 才 rename 指针；失败前保留旧 CURRENT，失败后不删除可能已提交的新 generation。本轮已把目录锁改为 kernel 文件锁，进程退出自动释放；旧版目录锁仍需显式迁移，不自动猜测删除。该方案针对单机单 writer，不能充当分布式 ACME 锁。

## 验收层次

- 本轮：fmt、clippy、debug/release 单测、配置正反例、确定性 wire vectors、拆包/粘包、证书切换/失败保持、续期重试、并发额度和模型 soak。
- Linux 原生构建：一个 boring-sys、无意外 TLS 后端，H2/H3 配置构造、严格 ALPN、证书真实签名/匹配校验。
- 集成：官方 Naïve H2/H3、普通浏览器、提前 DATA 但延迟 200、跨协议网站回落、目标先发 banner、上传/下载/半关闭/取消。
- ACME：Pebble/staging DNS-01 全链路、重启恢复、CA 429/网络断开/权限错误、TXT cleanup、续期和证书热换。
- 稳定性：至少一次受限环境 24h soak；采样 RSS/fd/task、双向吞吐、错误率、证书代数；网络丢包/延迟/MTU/连接迁移、重复 reload、磁盘满、断电提交点。记录基线与峰值，不能仅以进程未崩溃判通过。

只有上述实际完成的项目才能在状态页标为 passed；`serve` 的 fail-closed 闸门不得因为核心单测通过而移除。

---

<a id="moon-naive-verification"></a>

## 原文件：docs/history/MOON-NAIVE-VERIFICATION.md

# moon-naive / TOML / 服务端适配验证（2026-10-22）

此为本日 TOML/网络适配阶段记录。后续架构审查发现 H2 旧版 TLS helper 禁用了 TLS 1.3，已修正并增加强制 TLS 1.2/1.3 的真实握手回归；新增结果见 [服务端架构与优化方案](SERVER-ARCHITECTURE-AND-PLAN.md)。下表保留该阶段原始测试数量。

平台：本会话 Debian 13、Linux x86_64、Rust/Cargo 1.89.0、GCC 14.2、CMake 3.31.6、libclang 19。所有前端、目标 TCP 服务及测试 CA 均仅绑定 loopback 随机端口。未部署 VPS、创建公网 CA 账户或修改公网 DNS。

## 本轮实测

| 检查 | 结果 |
| --- | --- |
| 根与 native fmt | 通过 |
| 根与 native all-targets clippy，-D warnings | 通过 |
| 根 workspace Debug / Release | 各 39 项通过（core 26、control 13） |
| native Debug / Release | 各 28 项通过，含 1 个官方发布客户端用例 |
| 真实 Pebble CA Debug / Release | 各 2 项通过，显式 include-ignored |
| 相邻发布版 -3 与较早 150 版 | 各额外执行官方用例，协议范围见下表 |
| 六上游 pin/干净度、原生依赖图 | 通过；TLS/ACME 密码学使用 boring/boring-sys 5.2.0、tokio-boring 5.0.0，无额外 TLS 引擎；core 认证摘要仍用 Rust sha2/subtle |
| Release 产物 | moon-naive、moon-naive-acme、moon-naive-net 构建通过 |
| CLI | 推荐 GTS/Porkbun TOML 通过结构/策略检查；帮助和状态使用新名称；serve 仍非零且不开端口 |
| EAB 导入 CLI | 私有模拟 gcloud 导出转 TOML 成功，输出权限 0600；拒绝重复覆盖，无网络访问 |

每个 profile 基础回归的 69 项来自不同层次（39 + 28 + 2），不是 69 个独立网络互操作场景。相邻版和 150 版另行复用同一个官方用例执行，不扩大领域单测数量。

## 官方未修改客户端矩阵

从 klzgrad/naiveproxy 官方 GitHub Releases 下载 Linux x64 归档，SHA-256 与发布资产 digest 逐项匹配。未重编译/修改客户端，没有关闭证书或主机名校验。SSL_CERT_FILE 仅指向每次测试临时生成的本地 CA。

| 官方 release | Debug H2 | Debug H3 | Release H2 | Release H3 |
| --- | --- | --- | --- | --- |
| v154.0.8037.49-4 | 通过 | 通过 | 通过 | 通过 |
| v154.0.8037.49-3 | 通过 | 通过 | 通过 | 通过 |
| v150.0.7871.63-1 | 通过 | 本地根限制，未验收 | 通过 | 未验收 |

154 的两个 release 使用同一 Chromium 主版本，不能算成两个 Chromium 主版本的 H3 覆盖。150 版 H3 实际尝试在 TLS 验证阶段终止：NetLog 的 cert_status 为 0、is_issued_by_known_root 为 false，客户端发送 certificate_unknown。官方 [-3 发布说明](https://github.com/klzgrad/naiveproxy/releases/tag/v154.0.8037.49-3)明确修复 QUIC verifier 载入本地受信根。150 版 H3 后续需要公网受信证书重新测试；未据此修改生产证书验证或增加跳过验证开关。

每个通过的协议覆盖：SOCKS5 驱动真实 naive 进程、两个 origin 流复用一条 H2/QUIC 连接、每流 1 / 4,096 / 300,000 字节的双向逐字节对拍、legacy Padding 首八记录到原始流的切换、错误密码不产生目标拨号、服务停止后的资源回收。使用不同 TCP/UDP 端口，quic 测试不能回退到所测 H2 listener。

测试专用目标地址替换只存在于 cfg(test)，不进入正式二进制；真实 DNS/IP ACL 另由现有系统解析与拒绝测试验证。因此此矩阵证明本地客户端/前端互操作，不证明公网路由、DNS provider 或任意实际目标可达。

下载归档摘要：

```text
naiveproxy-v154.0.8037.49-4-linux-x64.tar.xz
9d765620b90f7c60eb40c7c68b2f82537757cc52a8693dee7a00f8ba8b13dfd0
naiveproxy-v154.0.8037.49-3-linux-x64.tar.xz
a6c47404f7a76d07d984af08ebe70b0a7456f52be4f40ba2245745f8cd93b02c
naiveproxy-v150.0.7871.63-1-linux-x64.tar.xz
0c4f506ce66a7881892fd6932b542c53fc06ac2351987756096c61e753c687bf
```

## 新增与保留的网络回归

- 严格 TOML：用户 JSON、未知项、重复用户名、空用户表、弱密码被拒绝；Porkbun/EAB/Cloudflare 使用私有 TOML。TOML 错误不回显秘密原文。EAB 导入校验 key ID/MAC、权限、原子无覆盖发布；运行时拒绝直接加载 EAB JSON。
- 共享头部校验：TE 只允许 trailers；Host 与 authority 不得歧义；Content-Length 必须为有界数字且所有重复/逗号分隔值一致；禁止 hop headers、非法名称和换行等值。
- H2/H3 空闲时限：单向上传和下载分别持续超过两倍测试 idle timeout，均保持正常；无进展则取消。H3 用独立站点请求保持连接活跃，单独验证流级超时。
- 慢速接收：H2 使用 4 KiB 流窗口、8 KiB 连接窗口并延迟归还信用；H3 暂停后以小块消费。分别对拍 512 KiB Padding 数据，验证偏移/短写和额度释放；覆盖请求 FIN 早于 H3 拨号完成的路径。
- 保留严格 ALPN、认证失败无出站、真实连接失败无早到 200、手工独立 Padding wire、半关闭、流 reset/socket 取消、候选拨号回退、私网/metadata/self-loop、MAC Retry、网站路径校验、实际双协议证书轮换与坏 CURRENT 回退测试。
- 真实 Pebble DNS-01 含要求 EAB 和不要求 EAB 两条路径，覆盖实际签发、重启/订单恢复、再次签发、ARI、DNS 失败保留旧证书、持久退避和缺失 EAB 时账户恢复；不是模拟签发器。

## 复现

保留 [BUILD-AND-USE.md](BUILD-AND-USE.md) 中的同级上游布局和固定 commits。原生工具链按本机设置 libclang、CMake 等路径，不能直接复制其他架构的 include 路径。

```sh
cargo run --release --locked -p xtask -- verify
cargo run --release --locked -p xtask -- audit-native
cargo clippy --manifest-path native/Cargo.toml --all-targets --locked -- -D warnings
```

完整测试须先设置 PEBBLE_BIN、CHALLTESTSRV_BIN、PEBBLE_SOURCE、NAIVE_BIN 四个环境变量（均为本机绝对路径）。NAIVE_BIN 可选上表 -4 或 -3；NAIVE_TEST_PROTOCOLS 默认 both：

```sh
cargo test --manifest-path native/Cargo.toml --locked -- --include-ignored --nocapture
cargo test --manifest-path native/Cargo.toml --release --locked -- --include-ignored --nocapture
```

替换 NAIVE_BIN 后单跑官方矩阵：

```sh
cargo test --manifest-path native/Cargo.toml --locked --lib official_naive -- --ignored --nocapture
cargo test --manifest-path native/Cargo.toml --release --locked --lib official_naive -- --ignored --nocapture
```

150 版本地只能设置 NAIVE_TEST_PROTOCOLS=https 验收 H2。普通 native test 明确跳过官方用例和两个外部 CA 测试；ignored 不计作通过。测试本身不会下载二进制。

## 原始记录与剩余边界

本轮文本记录在 reports/moon-naive-*，包括 root-verify、native-debug、native-release、native-clippy、native-build、audit、official-adjacent-debug/release、official-v150-h2-debug/release、cli、cli-import、gate 和 ldd。旧名称报告保留原内容。内部 journal 仍是 JSON，以兼容账户/订单/清理状态；它不是用户编辑的配置格式。

尚未完成：公网 GTS/Porkbun 签发与部署、150 及更广客户端 H3 的公网证书矩阵、参考 forwardproxy/普通网站网络行为差分、丢包/重排/MTU/网络切换、目标系统压力与 24h 稳定性。moon-naive serve 保留验收闸门，实验前端为 moon-naive-net run。源码包不含上游仓库、官方客户端二进制、target、真实私钥或部署状态。

---

<a id="network-verification"></a>

## 原文件：docs/history/NETWORK-VERIFICATION.md

# 真实网络栈验证（2026-10-22）

此为 pinaive 更名前的阶段记录，保留当时的命令和结果；moon-naive/TOML 与后续网络回归以 [MOON-NAIVE-VERIFICATION.md](MOON-NAIVE-VERIFICATION.md) 为准。

平台为本会话 Linux x86_64 / Debian 13、Rust/Cargo 1.89.0、GCC 14.2、CMake 3.31.6、libclang 19。真实网络测试只绑定 loopback，未部署 VPS、未创建公网 CA 账户或写入公网 DNS。

| 检查 | 当前实测 |
| --- | --- |
| 根 fmt / native fmt | 通过 |
| 根 clippy all-targets，-D warnings | 通过 |
| 根 Debug / Release | 每个 profile 39 项（core 26 + control 13），0 failed |
| native clippy all-targets，-D warnings | 通过 |
| native Debug / Release | 每个 profile 20 单测 + 2 个显式启用 Pebble 集成，0 failed、0 ignored |
| 全部合计 | 每个 profile 61 项，不包括零测试的 CLI harness/doc-test |
| 新增网络验证 | 8 项，包含六个前端/启动/取消/热加载测试、一个候选拨号测试和一个 Retry token 测试 |
| Release 构建 | pinaive-net 与 pinaive-acme 实际构建成功；根 pinaive / xtask 构建成功 |
| 新 CLI | Release pinaive-net --help 实际执行，根 status 显示 experimental via pinaive-net，production_ready=false |
| 依赖图与 pin | 通过；六个上游仓库固定 commit 且干净，TLS 后端仍只有 boring/boring-sys 5.2.0 |
| 公网证书 / 官方 Naïve / 24h 网络稳定性 | 未执行 |

新增直接依赖 h2 和 pingora-http，二者已经存在于原生依赖图，未切换 TLS 实现。网络和控制面编解码、私钥、证书仍使用同一 BoringSSL。构建来自 Cargo 固定依赖及路径仓库；不编入 Caddy 或 xcaddy。

## 实际网络覆盖

- 实际 TCP/TLS/H2 和 UDP/QUIC/H3，客户端信任临时 CA 并检查 proxy.example.test 身份；H1 和无 ALPN 路径被拒绝。
- 真实站点 GET/HEAD，普通响应不含 Padding；URL 编码穿越拒绝。错误凭据、未结束的 CONNECT 请求进入普通网站错误路径，不触发目标解析/拨号。
- H2/H3 两种入口都完成 CONNECT 到实际 TCP echo 服务，先发送早到 DATA，目标连接后获得 200；失败连接均返回 502。
- 带/不带数据 Padding 的双向回传。H3 的 300,000 字节 payload 超过初始窗口和应用队列，输入 wire 手工构造，覆盖前八条记录与原始尾部；输出逐字节对拍。
- 目标只在收到上传 EOF 后回传，证明单向 FIN 后另一方向能继续。
- H2 实际系统 localhost 解析后拒绝私网目标，literal/mapped/metadata/self 策略沿用核心检查；H3 也验证共享私网拒绝路径。
- RST/RESET_STREAM/STOP_SENDING 取消真实隧道后，目标连接关闭、活跃流和隧道额度归零。
- 轮换证书与密钥、原子提交 CURRENT，等待实际轮询：H2/H3 新握手证书 serial 从 2 变为 3，旧 H2/H3 连接继续正常请求。损坏 CURRENT 后新握手仍使用旧的有效 serial 3。
- 拒绝非私有用户文件发生在 bind 前；普通生产配置仍拒绝 port 0，随机 port 0 仅用于测试构造。
- Retry token 绑定源地址/端口和 CID；篡改、不同来源、不同 CID、已过期且 MAC 正确的 token 均拒绝。
- 真实 TCP 候选连接失败后回退到可用候选；代码限制两个并行尝试并在成功/取消后释放其余任务。

网络测试包含 cfg(test) 的 loopback 目标替换，因为正式 ACL 应拒绝 loopback。这个替换不属于正式程序的配置或功能。既测试了实际目标 socket/数据流，也独立测试了正式 ACL 的拒绝路径；不能把 loopback 回传写成真实公网 DNS 和远程目标验收。

## 执行命令

```text
cargo run --release --locked -p xtask -- verify
cargo run --release --locked -p xtask -- audit-native
cargo test --manifest-path native/Cargo.toml --locked -- --include-ignored --nocapture
cargo test --manifest-path native/Cargo.toml --release --locked -- --include-ignored --nocapture
cargo clippy --manifest-path native/Cargo.toml --all-targets --locked -- -D warnings
cargo build --manifest-path native/Cargo.toml --release --locked --bin pinaive-net --bin pinaive-acme
native/target/release/pinaive-net --help
```

测试设置了 PEBBLE_BIN、CHALLTESTSRV_BIN、PEBBLE_SOURCE，使用已固定的 Pebble v2.7.0。原有普通和强制 EAB 账户的真实签发/续期、ARI、故障保留、订单恢复、EAB 文件移除后账户找回均通过回归。

## 证据

- reports/verification-1792630541043345799-6583.txt、network-root-verify-2026-10-22.txt。
- reports/native-graph-1792630541528864136-8230.txt、network-audit-2026-10-22.txt。
- reports/network-debug-2026-10-22.txt、network-release-2026-10-22.txt。
- reports/network-clippy-2026-10-22.txt、network-build-2026-10-22.txt。
- reports/network-cli-2026-10-22.txt、network-status-2026-10-22.txt、network-ldd-2026-10-22.txt。

此处的 H2 客户端是 h2 harness，H3 客户端是 quiche harness，不是未修改官方 Naïve 可执行文件。未完成官方当前/旧稳定客户端矩阵、与固定 forwardproxy/纯网站基线的网络差分、真实丢包/MTU/IPv6/长时间负载、公网部署或系统服务安装。生产 pinaive serve 闸门继续保留，实验程序为 pinaive-net；不以这 61 项代替上线验收。

---

<a id="network"></a>

## 原文件：docs/history/NETWORK.md

# moon-naive 实验性网络前端（2026-10-22）

当前只保留 Pingora/BoringSSL + quiche，并接入完整 Pingora 网站反代引擎。QUIC BBRv2 / Linux TCP BBR 与 CURRENT 优化保留，Rustls/Quinn 已移除；网站配置及本轮验证见 [WEBSITE.md](WEBSITE.md) 与 [WEBSITE-VERIFICATION.md](WEBSITE-VERIFICATION.md)。

实验网络入口为 `moon-naive-net run <config.toml>`，使用真实 Pingora H2 / quiche H3。已在 loopback 完成 TLS/QUIC、网站、CONNECT、Padding、半关闭、取消回收、证书热更新、单向活动与慢速读取测试，并接入未修改官方发布客户端的互操作 harness。**参考服务端网络行为差分、公网与 24h 稳定性验收仍未完成；尚未发布为生产节点。** 根 CLI 的 `moon-naive serve` 保留生产验收闸门，最新矩阵见 [MOON-NAIVE-VERIFICATION.md](MOON-NAIVE-VERIFICATION.md)。

## 参考作者实现的边界

参考固定版本 [klzgrad/forwardproxy 的 forwardproxy.go](https://github.com/klzgrad/forwardproxy/blob/c096d6a00cb28e019cc1995b04bdc6a9311d8024/forwardproxy.go)，没有修改上游源码。

| 作者代码 | moon-naive 实现 |
| --- | --- |
| ServeHTTP：逐请求认证、普通请求/错误凭据交给后续网站 | H2/H3 共同调用 ingress::dispatch；网站仅获得清理后的请求，错误凭据无目标解析/拨号 |
| H2/H3：同一请求体和响应流承担双向传输 | Pingora HttpSession 与 quiche H3 流分别驱动，复用相同认证和 egress |
| 首个 Padding 头非空启用 legacy framing | 保留此条件；仅 padding-type-request 不启用，不增加私有协商 |
| 成功 CONNECT 始终带 Padding 响应头 | 30..61 字符，前 16 字符和其余 `~` 的分布与参考算法一致，包括未启用数据填充的隧道 |
| 每方向前八条记录填充，之后原始流 | 复用已验证 codec；记录边界不依赖 HTTP DATA 帧，短写保留同一编码结果与 offset |
| dualStream / CloseWrite | 上传 EOF 关闭目标写方向；下载继续，下载 EOF 关闭响应方向；RST/reset/超时取消相应任务和 socket |
| 参考服务端先回 200 再拨号 | 按用户约束调整为目标 TCP 连接成功后才生成 200；失败返回 403/502/504，无提前 200 |

当前读取块固定为 16 KiB，并非复制 Go bufferPool 的全部读取长度行为；TLS/H2/H3 栈、关闭 Fast Open 和 0-RTT 也不同。协议语义对齐不等于逐包/时间分布相同，更不构成“更隐蔽”的实验证据。

## 实现组成

- `native/src/net/h2.rs`：Pingora L4/TLS 与 H2 handshake/HttpSession；严格 h2 ALPN，无 H1/h2c fallback；配置 H2 窗口/流数/header 上限，连接 GOAWAY 和限时退出。
- `native/src/net/h3.rs`：真实 UDP/QUIC 路由、超时和发送节奏、H3 控制流与请求流；带 MAC 的 Retry token 绑定源 IP/端口、原始 CID、服务端 CID 和 60 秒时限；地址验证后才分配连接。
- `native/src/net/egress.rs`：真实系统解析、逐候选 IP ACL、直接拨已检查 IP；最多 32 个候选、两条并行连接尝试、250 ms 错开并交替地址族，成功或取消后回收其余尝试。DNS 与连接共同受 connect_timeout 约束。
- `native/src/net/site/`：完整 Pingora HttpProxy、固定上游路由/连接池、流式反代、ServeDir 文件/Range/条件请求和 gzip；H2 直接进入，H3 通过有界内存 H2 桥共享。详见 [WEBSITE.md](WEBSITE.md)。
- `native/src/net/tls.rs`：从现有 ACME 证书存储读取 CURRENT，验证 SAN/链/私钥/有效期后同时构造 H2/H3 上下文；一个共享 generation 发布，5 秒轮询更新；坏更新保留旧有效上下文，过期后拒绝新握手。H2 使用 Mozilla v5 策略明确支持 TLS 1.2/1.3，已通过强制版本的实际握手测试；H3 使用 QUIC TLS 1.3。
- `native/src/bin/moon-naive-net.rs`：显式实验入口、双监听启动、SIGINT/SIGTERM 与限时退出；不打印请求/凭据/原始第三方错误。

H3 保持 0-RTT 关闭、只接受 h3；尚未实现额外 CID 路由，因此不启用主动迁移。当前不自动发布 Alt-Svc，没有把“本机 UDP 已绑定”当成“公网 UDP 已验证可达”。

## 构建与启动

沿用 BUILD-AND-USE.md 的 Linux 工具链、同级固定版本上游与两个 workspace：

```sh
cargo build --workspace --release --locked
cargo build --manifest-path native/Cargo.toml --release --locked --bin moon-naive-acme --bin moon-naive-net
./native/target/release/moon-naive-net --help
```

准备以下文件，路径可通过 TOML 调整：

```text
/etc/moon-naive/config.toml
/etc/moon-naive/users.toml          0600 普通文件
/srv/moon-naive/site/index.html
/var/lib/moon-naive/certificates/CURRENT
```

`users.toml` 支持 1..256 个不重名用户，密码至少 16 字节，建议使用随机高熵密码。示意内容（权限 0600）：

```toml
[[users]]
username = "alice"
password = "replace-with-a-unique-random-password"
```

启动前使用现有 `moon-naive-acme run` 取得证书；GTS/Porkbun 凭据仍按 ACME.md 配置。网络进程不需要读取 Porkbun/EAB 密钥，只读取用户文件、站点和证书状态。没有有效 CURRENT、用户文件不私有、没有 index.html、任一监听绑定失败时，启动失败，不留下另一半前端运行。

```sh
./target/release/moon-naive check-config /etc/moon-naive/config.toml
./native/target/release/moon-naive-acme status /etc/moon-naive/config.toml
./native/target/release/moon-naive-net run /etc/moon-naive/config.toml
```

示例配置默认仍是 `127.0.0.1:8443` 的 TCP/UDP；若已有本地程序占用该端口，需改用空闲端口。更改到公网地址、配置系统服务与替换现有节点应在完成验收后按目标 VPS 操作。本轮没有部署 VPS 或开放公网端口。当前 systemd 模板仍仅覆盖 ACME，没有安装任何服务。

网络进程启动时加载用户和网站配置，修改后需重启；文件内容按请求异步读取。证书由独立 ACME 工作进程继续更新，网络进程自动观察 CURRENT。浏览器或正常客户端使用需要 production 证书；不会因为 .dev 或 GTS staging 而跳过证书验证。

## 资源边界

- max_connections 同时约束 TCP/TLS 和 QUIC 连接；max_streams 是单连接流上限，同时作为全局活跃隧道上限；全局请求池为其两倍，为网站保留请求容量。尚无独立每用户配额配置。
- 新增 limits.max_total_receive_bytes，默认 67108864（64 MiB），按共享 TransportProfile 的连接接收窗口为每个连接预留额度，H2/H3 共用；超过额度拒绝新连接。默认窗口 16 MiB 时最多预留四个连接，即使 max_connections 设置为 128。提高该值会增加接收内存预算，不能当成吞吐调优结论。
- 此预算限制传输接收窗口之和，不是进程 RSS 上限。另有有界请求头、应用读写块、H3 两格通道、TLS/QUIC 状态和网站快照。所有缓冲仍需通过目标机压力测试测量。
- 连接尚未成功时不消费 CONNECT DATA，以 min(max_early_data_bytes, stream_window) 的初始信用约束早到数据；H2 维持该保守窗口，H3 自动增长最多到共享 stream_window，连接窗口也有明确上限。
- H3 不把 TCP 拨号、文件读取或 fsync 放在 UDP 事件循环中；流级 task 与 driver 之间只通过有界队列传递已编码块。发送短写只前进 offset，不重新编码。
- 双向隧道共享一个 idle deadline。成功读取/写入实际字节会更新活动时刻，持续单向上传或下载可以超过 idle_timeout_secs；两个方向均无进展才取消。H2 逐次发送窗口授信和 TCP 短写都计入进展；空 DATA 帧不延长隧道寿命。
- H3 保存拨号尚未完成时收到的 FIN，创建 TCP bridge 时继承半关闭；已经结束的请求方向不会因重新保留队列 sender 而等待到超时。
- 普通请求和 CONNECT 共用头部边界：禁止连接级 headers、非法 TE、歧义 Host，以及不合法/互相矛盾的 Content-Length；重复但相同的长度按 RFC 9110 接受。H2 库层与 H3 的非法报文可分别以协议级拒绝处理，不宣称错误包逐字相同。
- 窗口、连接数和流数上限不依据认证结果切换，站点与隧道用相同公开传输配置。
- 网站按流发送文件/反代正文，移除旧静态快照大小限制；文件系统目录由可信管理员维护。网站请求体、上游时限、连接池、DNS、内部桥窗口和通道均有限制，资源范围见 WEBSITE.md。
- 私网、metadata、mapped IPv6、配置监听地址、节点域名与启动时解析到的节点地址不能作为出站目标。特殊 NAT/多地址部署仍需复核 self-loop/egress 防火墙规则，不能只靠域名一次解析替代部署策略。

## 本轮网络验证

测试前端和目标 TCP 服务均绑定 loopback 随机端口；本地签名 CA 仅写入临时目录，客户端正常验证该 CA 和 proxy.example.test 身份，没有生产可用的关闭校验或允许私网目标开关。测试专用 loopback 拨号替换仅在 cfg(test) 下存在，正式二进制不包含它。

覆盖：

- 实际 H2 TLS 与 H3 QUIC/Retry/HTTPS 身份验证。
- 网站 GET/HEAD、普通响应不含 Padding、编码路径穿越拒绝。
- 认证失败进入网站，无出站拨号；每条 CONNECT 独立认证，连接复用不授予后续请求认证状态。
- 带/不带 Padding 的实际 TCP 回传；H3 客户端手工构造独立 wire，覆盖第八条后的原始流；300,000 字节超过初始接收信用与队列容量。
- 客户端可先发送 DATA，服务器仍在目标连接成功后返回 200；真实连接失败在 H2/H3 返回 502。
- H2/H3 目标写方向半关闭后仍可接收完整回传。
- H1/无 ALPN 拒绝；实际系统 localhost 解析后拒绝私网候选；H3 同样执行共享 ACL。
- 两种协议的流重置取消真实目标 socket，活跃请求和隧道额度回到零。
- 更新磁盘证书后，实际 H2/H3 新握手的证书 serial 从 2 变为 3，原连接继续；损坏 CURRENT 后保留 serial 3。
- Retry token 篡改、来源端口/CID 不符、过期拒绝；候选地址失败后实际拨号回退。
- 用户文件权限错误在绑定前拒绝。
- 持续上传、持续下载均运行超过 2 倍测试 idle timeout；静默隧道被回收，H3 另用站点请求保持连接活跃以验证流级时限。
- H2 4 KiB 接收窗口、延迟归还信用；H3 暂停后按小块消费，完整校验 512 KiB Padding 数据及额度释放。

执行方法：

```sh
cargo test --manifest-path native/Cargo.toml --locked --lib net:: -- --nocapture
```

以上常规测试使用独立 h2/quiche harness；另外可显式运行官方客户端测试：

```sh
NAIVE_BIN=/absolute/path/to/official/naive cargo test --manifest-path native/Cargo.toml --locked --lib official_naive -- --ignored --nocapture
```

它通过 SOCKS5 驱动官方进程，默认分别测试 https 与 quic，两条 origin 流须复用同一条传输连接；错误密码不得触发出站。前端 TCP/UDP 使用不同随机端口，防止 quic 测试悄悄回退至 H2。以 SSL_CERT_FILE 信任临时 CA，仍验证链及主机名。仅需要单个协议时可设置 NAIVE_TEST_PROTOCOLS=https 或 quic，默认 both；报告中必须写明实际协议。

官方客户端测试不会自行下载二进制，默认明确 ignored。已执行版本、下载 SHA-256、本地 CA 限制与 Debug/Release/Pebble 回归见 [MOON-NAIVE-VERIFICATION.md](MOON-NAIVE-VERIFICATION.md)。旧阶段证据见 NETWORK-VERIFICATION.md；这些短时网络测试不代表 24h 稳定性。

---

<a id="readme-pre-integration"></a>

## 原文件：docs/history/README-pre-integration.md

# moon-naive — H2/H3-only Naïve Rust 实验服务端

**当前具备自动证书管理器和真实 H2/H3 实验前端，已有官方 Naïve 客户端的本地互操作证据；公网与生产稳定性验收尚未完成。**

当前仅保留 **BoringSSL/quiche**，已移除 Rustls/Quinn 可选后端。网站使用完整 Pingora HttpProxy，提供固定上游路由、H1/H2 连接池、流式反代、文件/Range/条件请求与 gzip；H2/H3 共享同一引擎。支持 quiche BBRv2 和 Linux 每 socket TCP BBR。配置、架构和边界见 [WEBSITE.md](WEBSITE.md)，本轮验证见 [WEBSITE-VERIFICATION.md](WEBSITE-VERIFICATION.md)。原有 Padding、16 KiB 目标读取块、尾部复制和随机数调用保留。Caddy+作者插件对照见 [SERVER-ARCHITECTURE-AND-PLAN.md](SERVER-ARCHITECTURE-AND-PLAN.md)。

网络栈说明见 [NETWORK.md](NETWORK.md)：`moon-naive-net run` 提供真实 Pingora H2 / quiche H3、共享认证与 DNS/ACL/拨号、网站、双向 Padding/半关闭、取消回收和双协议证书热更新。本轮继续统一请求校验，修正持续单向传输的空闲计时，并增加慢速接收和官方客户端互操作测试。最新验证见 [MOON-NAIVE-VERIFICATION.md](MOON-NAIVE-VERIFICATION.md)。

项目现名 **moon-naive**（曾用名 naived、pinaive），包括目录、Cargo 包、命令和部署模板。主配置、代理用户、Porkbun、GTS EAB 与备用 Cloudflare 凭据均使用 **TOML**，格式与旧配置迁移见 [配置说明](../CONFIGURATION.md)。构建和操作步骤见 [构建与使用说明](BUILD-AND-USE.md)。

ACME 实现与使用方式见 [docs/ACME.md](ACME.md)：`moon-naive-acme run` 自动申请/续期/恢复，使用 BoringSSL、instant-acme 和原生 DNS API。按用户的 `.dev` 域名要求，支持 **Porkbun DNS + Google Trust Services（GTS）及 EAB**，推荐配置为 [config.porkbun-gts.example.toml](../../config.porkbun-gts.example.toml)。已通过要求 EAB 的真实本地 Pebble CA 的签发、续期与账户恢复；公网签发仍需实际域名与凭据。仍支持 Let's Encrypt + Cloudflare，其私有凭据也须使用 TOML。

2026-10-21 架构设计背景见 [docs/ARCHITECTURE.md](ARCHITECTURE.md)：服务端采用 Pingora + BoringSSL + quiche，以官方 Naïve H2/H3 为兼容基线，不要求嵌入 Chromium net/。历史阶段报告保留原命令、名称和当时的验收范围。

**最终目标与 Chromium 集成边界见 [docs/REQUIREMENTS.md](REQUIREMENTS.md)**：必须交付兼容官方 Naïve 客户端的真实服务端，优先考虑抗识别需求；不能以框架通过测试或使用 BoringSSL 代替完整客户端互操作与网络行为验证。

按用户最新要求锁定：**仅 H2/H3、关闭 H1、关闭服务端 Fast Open/0-RTT、自动 ACME DNS-01、Cargo 构建，不使用 Caddy/xcaddy。**

## 已实现的框架代码

- 严格 TOML schema：未知项、H1、Fast Open、0-RTT、HTTP-01、关闭 H2/H3/ACME、无界/无效缓冲参数均拒绝。
- H2/H3 ALPN 选择策略（包括拒绝无 ALPN）、逐流 Basic 认证与网站分流、authority 解析、保守 IP ACL、RAII 并发额度。
- `ingress::dispatch` 统一认证后的普通 CONNECT 边界，网站请求去除代理专用字段；`padding::response_header` 生成参考服务端的 30..61 字节响应头。
- `TransportProfile` 统一推导 H2/H3 超时、流数、窗口与连接接收预算；双向隧道共享活动时刻，持续单向传输不会触发另一方向的读超时。
- Naïve 前八条记录的双向通用 codec，流式拆分/合并和第八条边界正确处理；随机 padding 值由调用者提供。
- CONNECT 建连门禁：TCP connect 成功前禁止生成成功响应，允许客户端早到 DATA 的有界暂存。
- ACME 控制面核心：续期时刻、失败退避、Retry-After、取消恢复、签发/验证/安装接口；不确定磁盘提交会停止重签，要求恢复校验。
- Unix 证书 generation 事务：私有权限、fsync、原子 CURRENT、单 writer 文件锁；成功持久化后才发布内存快照，已有 Arc 保留旧证书。
- 实际 ACME 账户/订单/密钥 journal、自动 DNS-01、权威 TXT 检查、清理恢复、ARI/抖动/Retry-After、BoringSSL SAN/chain/key/有效期/用途校验、独立常驻工作进程。证书与管理器单 writer 已使用 kernel 文件锁，崩溃后自动释放。
- Rust `xtask` 验证器：真实退出码、命令限时、CLI 字节对拍、配置反例、fail-closed 检查、上游 revision/干净度检查、原生 TLS 依赖审计、确定性模型 soak。

## 尚未实现，不能冒充已通过

- 官方客户端更广泛版本/系统覆盖、参考 forwardproxy/同栈网站网络行为差分、目标 VPS 验收。已执行的本地官方发布版矩阵见最新验证记录。
- 公网 Porkbun / Cloudflare DNS 及 GTS / Let's Encrypt staging 与 production 的实际联调；当前已实现对应适配并用本地真实 CA/兼容 API 验证，尚无公网凭据。
- 正式生产入口与部署集成、独立每用户额度、完整告警；多 CA 自动回退、多 SAN/通配符、按需签发和分布式锁。H2/H3 实际握手热加载已有本地网络证据；OCSP 需按实际证书与运行时要求评估。
- 丢包/重排/MTU 等网络故障注入和 24h 稳定性验证。ACME 功能背景见 [docs/ACME-VERIFICATION.md](ACME-VERIFICATION.md)。

因此 `moon-naive serve` **明确退出非零，不开端口**。实验入口是另行构建的 `moon-naive-net`；`moon-naive-acme` 是独立 CA/DNS 工作进程。测试用 loopback 拨号替换仅在 cfg(test) 中存在，正式前端没有允许私网目标的测试开关。

## 目录

```text
Cargo.toml / Cargo.lock
config.example.toml
config.porkbun-gts.example.toml 推荐的 Porkbun + Google Trust Services 配置
examples/secrets/*.example.toml 私有 TOML 配置的占位示例
crates/core/       配置、协议、安全策略、codec、额度/建连状态
crates/control/    续期控制器、磁盘事务、证书快照
crates/daemon/     配置检查/状态 CLI，生产验收前保留启动闸门
xtask/            Rust 验证与模型 soak
native/           独立原生依赖 workspace + Cargo.lock + API 接缝
native/src/acme/  真实 ACME/HTTP/密码学/DNS/证书管理实现
native/src/net/   真实 H2/H3 实验前端、共享拨号、网站与 TLS generation
native/src/bin/moon-naive-net.rs 实验网络入口
native/src/bin/moon-naive-acme.rs 独立自动证书管理工作进程
deploy/moon-naive-acme.service 未安装的 systemd 模板
docs/ARCHITECTURE.md 本轮源码审查、架构决策和网络行为验收方案
docs/DESIGN.md     最新约束、架构与关键取舍
docs/WORK.md       本轮任务清单
docs/ACCEPTANCE.md 真实上线验收项
tests/fixtures/   CLI 字节基准
reports/          每次验证的唯一名称报告（不进版本管理）
```

## 已有验证证据

更名后的验证见 [docs/VERIFICATION-2026-10-22.md](VERIFICATION-2026-10-22.md)。ACME 功能验证背景见 [docs/ACME-VERIFICATION.md](ACME-VERIFICATION.md)，架构阶段记录见 [docs/VERIFICATION-2026-10-21.md](VERIFICATION-2026-10-21.md)。旧记录保留当时的命令与名称；不代替当前构建或网络证据。

## 本地构建与检查

以下是独立命令，不需要 shell 脚本：

```text
cd ~/moon-naive-workspace/moon-naive
cargo build --workspace --release --locked
./target/release/moon-naive check-config config.example.toml
./target/release/moon-naive status
cargo run --release --locked -p xtask -- verify
cargo run --release --locked -p xtask -- audit-native
cargo run --release --locked -p xtask -- soak 100000
```

`check-config` 只检查结构/策略：**不读取凭据、不验证 DNS provider 已实现、不申请证书、不开放端口**。示例使用 loopback 高端口和 ACME staging，`accept_terms = false`；生产 CA 必须显式同意条款。

核心测试只依赖轻量 Rust crates。本轮核心 workspace 已在 Linux x86_64 / Rust 1.89.0 重新测试；原生依赖有独立编译与工具链门槛，结果见验证记录。

## 原生依赖路线

`native/Cargo.toml` 直接引用本地仓库，并固定 `boring = boring-sys = 5.2.0`。`audit-native` 检查 normal 依赖图，拒绝 Rustls/Quinn/ring/OpenSSL/AWS-LC 等额外 TLS/crypto 引擎；`rustls-pki-types` 只是证书/key 数据类型。

Linux 原生检查与实际证书管理器构建：

```text
cargo check --manifest-path native/Cargo.toml --locked
cargo test --manifest-path native/Cargo.toml --locked
cargo build --manifest-path native/Cargo.toml --release --locked
./native/target/release/moon-naive-acme --help
./native/target/release/moon-naive-net --help
```

需要 Rust/Clang/C++/CMake/原生依赖对应的构建工具；**Cargo 构建不等于 BoringSSL 变成纯 Rust**。不需要 xcaddy 或 Caddy。当前 native 可生成独立实验前端，最终发布入口与上线验收尚未完成，运行步骤和边界见 NETWORK.md。

上游路径依赖本身不记录 commit，因此 `xtask` 显式校验六个 Git HEAD 与干净工作区；更新时必须同时更新 pin、lockfile、依赖审计与互操作测试。不会自动跟踪 main。

## 必须了解的取舍

1. 不提前回 200，但不能通过服务端配置阻止官方 Naïve 客户端自行提前发 DATA；强行把早到 DATA 当错误会破坏复用后的客户端连接。本项目选择有界缓冲/背压，禁止提前确认与转发。
2. 关闭 H1 包括站点回落；没有 ALPN 的连接也必须拒绝。不能直接使用 Pingora 默认 H1 fallback。
3. 默认 DNS-01，不暗开 80/H1。推荐 Porkbun + GTS，需要 Porkbun 私有 TOML 和首次注册用 EAB TOML；gcloud JSON 导出可用 import-eab 转换。仍支持 Cloudflare + Let's Encrypt。尚未执行公网 CA/DNS 写入。
4. 新版 kernel 文件锁随进程退出自动释放，锁文件保留；旧版目录锁不自动删除，需明确迁移。CURRENT 后的 fsync 失败属于不确定提交，不得盲目重签。
5. 单元测试、模型 soak 与真实节点稳定性是三种不同证据；未跑网络验收就不能宣称生产稳定或与 Caddy 抗识别能力相同。
6. 当前磁盘 Store 接口是同步的。接入运行时需把 ACME/证书 fsync 放在独立控制面执行器/阻塞池，不能阻塞数据面 Tokio worker；state 根目录及父目录必须可信且不允许其他用户写入。

---

<a id="readme"></a>

## 原文件：docs/history/README.md

# 历史记录

此目录保留整合前各阶段的实现、分析和验证证据。旧名称 pinaive、独立 moon-naive-net/moon-naive-acme、双 workspace、Rustls/Quinn feature 和生产入口闸门均属于历史状态。

当前入口、构建、配置和验收范围以项目 [README](../../README.md)、[安装说明](../INSTALL.md) 和 [本次验证](../VERIFICATION.md) 为准。历史测试结果不自动计作本次发布验证。

---

<a id="requirements"></a>

## 原文件：docs/history/REQUIREMENTS.md

# 用户目标澄清与架构决策边界

此记录补充 DESIGN.md；与旧文档对项目目的的描述不同时，以此处用户明确需求为准。它不表示未完成的功能已实现。

## 用户明确要求

- 交付真正兼容官方 NaïveProxy 客户端的服务端，而非只重构/建立框架。必须以未修改官方客户端的真实 H2/H3 互操作作为验收依据。
- 用户最新明确“目前仅需修改服务端即可”。当前实施与优化仅针对 moon-naive 服务端，以未修改官方客户端为兼容基线；不把新客户端、私有协商或两端同时改协议作为前置条件。此前客户端实验意向不属于当前实施范围。
- 不依赖 Caddy/xcaddy，也不使用 Caddyfile；有明确的其他配置方式。现有框架选择 TOML，不是要求零配置。
- 保留 Chromium 技术栈的价值，不能把项目降格为仅实现 CONNECT 的自定义代理。
- 最高目标是尽量保持正常浏览器/网站通信特征、降低被识别和封锁的风险；Rust 语言、性能和编译便利性不能代替这一目标的验证。
- 既有要求继续有效：公开接入仅 H2/H3，关闭 H1、服务端 Fast Open/0-RTT；ACME 自动管理及稳定性验证。
- 最新要求仅保留 BoringSSL/quiche，删除 Rustls/Quinn 冗余分支；保留 QUIC/TCP BBR，网站使用成熟文件、路由、压缩和 Pingora 反代。Padding 前八条/后续原始流和现有读取/随机数路径暂不优化，不用性能结论代替流量行为验证。当前实现与限制见 WEBSITE.md。
- 用户已购买 .dev 域名，并备有带 IPv4 的 VPS；已明确 DNS 服务商为 Porkbun、签发方为 Google Trust Services，具体域名、VPS 系统和私有凭据未提供。

## 必须准确说明

- 官方推荐部署的 Naïve 客户端重用 Chromium 网络栈，而 Caddy 服务端不使用 Chromium。但 naive 可执行文件自身也支持客户端/服务端模式，服务端模式同样使用其 Chromium C++ 网络设施；该模式的 HTTP 监听不等于现成的公网 TLS/H2/H3 网站前端。不能笼统说“只有客户端有 Chromium”。
- 服务端需要扮演正常网站服务器，而非另一个浏览器；同用 Chromium/BoringSSL 不自动提高隐蔽性。自定义随机化、填充或新 headers 可能形成独有分布，必须以浏览器/普通站点及官方基线对照，不能根据使用技术栈名称判断。
- Pingora + boring + quiche 不等于 Chromium net/。BoringSSL 是 Chromium 使用的密码库，但单独采用它不能复现完整客户端或服务端网络行为。
- quiche（Cloudflare）与 Chromium 使用的 QUICHE（Google）不是同一个项目，不得混称。
- 当前 moon-naive 已有领域核心、原生 ACME/DNS 和真实 H2/H3 实验前端，网站/隧道/证书接线已在本地网络测试；已接入未修改官方 Linux 发布客户端矩阵，具体版本和限制见 MOON-NAIVE-VERIFICATION.md。参考行为差分、公网与 24h 稳定性及 VPS 验收仍未完成，不能称为已发布的生产服务端。配置统一 TOML，具体见 CONFIGURATION.md / NETWORK.md。
- .dev 的浏览器 HSTS 预加载行为不是代理抗识别能力；域名后缀/证书不能保证不被封锁。IP、域名、SNI（未协商适用的 ECH 时）与流量模式等仍有风险。
- H2/H3-only、不同服务端协议实现以及关闭提前 200 会改变可观察行为，需要在用户指定约束内评估；不能把它们宣传为必然增强隐蔽性。
- 不承诺无法识别、不会封锁，也不拿本地模型测试替代真实网络/协议对照。

## 2026-10-21 已确认的架构范围

用户已提供完整 server 源码，并确认“服务端兼容性按照原有服务端兼容性即可”，要求以尽可能强的伪装性优化架构。因此继续 Pingora + BoringSSL + Cloudflare quiche 路线，不要求服务端嵌入 Chromium net/，不引入 Google QUICHE/C++ net 集成。

沿用官方客户端 H2/H3 与 legacy Padding 兼容基线。H1、服务端 Fast Open、TLS/QUIC 0-RTT 的原有禁用约束继续有效，故不声称覆盖参考服务端全部协议行为。客户端扩展不属于当前实施范围；本轮不引入私有协议。服务端组件比较与后续方案见 SERVER-ARCHITECTURE-AND-PLAN.md。

本轮优化的具体边界、已实现与待实现部分以及行为对照门槛见 [ARCHITECTURE.md](ARCHITECTURE.md)。降低识别风险是优化目标；没有网络证据前，不作效果结论。

---

<a id="server-architecture-and-plan"></a>

## 原文件：docs/history/SERVER-ARCHITECTURE-AND-PLAN.md

# moon-naive 服务端架构、Caddy 对照与优化方案

日期：2026-10-22。范围按用户最新要求限定为服务端；未修改官方 Naïve 客户端，以已有 H2/H3、Basic 认证和 legacy Padding 保持兼容。本文明确区分当前实现、此次修复和后续建议。

后续已按用户最新要求仅保留 BoringSSL/quiche，删除 Rustls/Quinn 分支，并将网站接入完整 Pingora HttpProxy。保留显式 QUIC/TCP BBR、CURRENT 未变化时跳过 TLS 重建，以及原有 Padding/随机数行为。当前配置及验证见 [WEBSITE.md](WEBSITE.md) 和 [WEBSITE-VERIFICATION.md](WEBSITE-VERIFICATION.md)；文末 TLS 修复证据保留其原阶段范围。

## 当前实际架构

```mermaid
flowchart TB
    Client["官方 Naïve 客户端 / 普通浏览器"]
    H2["TCP → BoringSSL TLS → Pingora / h2"]
    H3["UDP → quiche QUIC + BoringSSL → H3"]
    Dispatch["共享请求校验、逐流认证与分流"]
    Site["Pingora HttpProxy：固定路由 / 上游池 / 流式反代 / 文件 / 压缩"]
    Tunnel["Tunnel：额度 → DNS / ACL → TCP 拨号"]
    Pump["连接成功后 200 → Padding / 双向背压 / FIN / 取消"]
    Origin["目标 TCP 服务"]
    Acme["独立 moon-naive-acme：GTS EAB / ACME DNS-01 / Porkbun"]
    Store["私有状态：账户 / 订单 / TXT 清理 / 证书 generation / CURRENT"]
    TLS["验证并构造 H2 / H3 TLS generation，共同发布"]
    Client --> H2
    Client --> H3
    H2 --> Dispatch
    H3 --> Dispatch
    Dispatch --> Site
    Dispatch --> Tunnel
    Tunnel --> Pump --> Origin
    Acme --> Store --> TLS
    TLS -.-> H2
    TLS -.-> H3
```

moon-naive-net 是当前真实网络实验进程，moon-naive-acme 是独立证书进程，根 moon-naive 是配置/状态 CLI，生产 serve 闸门仍保留。两个工作进程用已验证的磁盘 CURRENT 交接证书；网络进程不需要读取 Porkbun/EAB 密钥。主配置及运行凭据为 TOML。

| 层 | 当前源码与组件 | 职责 |
| --- | --- | --- |
| 纯协议核心 | crates/core | 配置、认证、CONNECT 分流、authority/IP 策略、Padding、额度和传输配置 |
| 证书控制核心 | crates/control | 续期/失败调度、证书事务、CURRENT、证书快照 |
| 网络适配 | native/src/net | Pingora H2、quiche H3、DNS/拨号、网站、双向转发、TLS generation |
| 实际 ACME | native/src/acme | instant-acme、BoringSSL JWS/验证、HTTPS、Porkbun/Cloudflare、DNS-01、持久恢复 |
| 工具与验收 | crates/daemon、xtask、native/tests | CLI、依赖审计、领域回归、官方发布客户端和真实 Pebble CA 测试 |

Pingora 提供 TLS/L4、H2 HttpSession 和完整反向代理引擎。H2 网站请求直接进入 HttpProxy，H3 网站请求经有界内存 H2 桥进入同一引擎；公开 H3 仍由 quiche 驱动。Naïve CONNECT 保持独立双向数据路径。

## 与 Caddy + 作者插件对照

原服务端大致为：Go TLS / HTTP2 与 QUIC/H3 → Caddy HTTP handler 链 → 作者 forwardproxy 的认证/CONNECT/Padding，普通网站与证书自动化由 Caddy/CertMagic 等提供。xcaddy 是构建工具，不参与请求运行。

此处按本地固定的 klzgrad/forwardproxy commit c096d6a00cb28e019cc1995b04bdc6a9311d8024 比较。其 go.mod 中的旧依赖声明不能代表发布包的实际版本；当前发布工作流读取 CADDY_VERSION=v2.11.7，并应用 caddy-sing-quic-bbrv1.patch。

| 维度 | Caddy + 作者 forwardproxy | 当前 moon-naive |
| --- | --- | --- |
| 公开 TLS | Go TLS 体系；通常支持 TLS 1.2/1.3 | BoringSSL；本轮修复后 H2 明确支持 TLS 1.2/1.3，QUIC 使用 TLS 1.3 |
| H2/H3 | Caddy 的 Go HTTP 栈与 QUIC 实现 | Pingora/h2 + Cloudflare quiche，两种 adapter 复用业务核心 |
| QUIC 拥塞控制 | 作者当前发布包替换 sagernet QUIC 并加 sing-quic BBRv1；普通 xcaddy 构建未必含该补丁 | 旧配置保留 CUBIC；可显式选 quiche BBRv2，和作者的实现不同 |
| Naïve 兼容 | 作者实现认证、Padding、CONNECT Fast Open 等 | 已对齐官方客户端 H2/H3 legacy Padding 基线；按用户要求关闭 H1、Fast Open、0-RTT |
| CONNECT 成功时机 | 固定作者源码先 flush 200，再拨号 | TCP 目标连接成功后才回 200；这会改变时序，不能称为与作者逐包相同 |
| 认证失败 | probe_resistance 等配置控制是否交给网站 handler，否则可以返回 407 | 逐流判断；失败进入共同网站分支，无目标 DNS/拨号 |
| 网站 | 完整网站路由、文件、压缩、反代等成熟基础设施 | ServeDir 文件/Range/条件请求、Pingora gzip、固定前缀路由、H1/H2 上游池和流式反代；功能范围小于 Caddy |
| 自动证书 | CertMagic/ACME 与 DNS provider 模块，已有广泛生产经验 | instant-acme + BoringSSL + 原生 DNS API；本地 CA 恢复/续期已测，公网联调待做 |
| 运行资源 | Go goroutine、GC 与成熟生命周期管理 | Tokio task、RAII 和显式预算；仍需测量 RSS、任务数、队列和公平性 |
| 构建/维护 | xcaddy/Go；完整产品能力与插件生态 | Cargo 加 C/C++/CMake/libclang；功能更聚焦，但自有网络集成维护责任更大 |
| 当前成熟度 | 可部署的成熟路线 | 已有本地真实互操作证据的实验服务端，公网/差分/24h 验收未完成 |

采用 Rust/BoringSSL 不能单凭语言或库名称推出性能、可识别性优于 Caddy。Go 的 AES/ChaCha 也有优化；客户端与服务器的协议状态机、窗口、调度、网站语义同样影响结果。

## BoringSSL 已用到的部分

- H2 TLS 握手和记录加解密；H3 TLS 1.3、密钥派生与 QUIC 密码学接入。
- 证书链/SAN/用途/有效期、私钥匹配验证。
- ACME ES256/P-256、PKCS#8/JWK、SHA-256、EAB HMAC 和随机数。
- QUIC Retry 的随机数/HMAC、响应 Padding 随机值等。

boring/boring-sys 固定 5.2.0，tokio-boring 固定 5.0.0，Pingora、quiche 和 ACME 共用这一依赖路线。core 认证摘要使用 Rust sha2/subtle；它不构成第二套 TLS 引擎，没有必要为了“统一”把简单摘要全部改为 FFI。项目含 BoringSSL C/C++，不能称为完全纯 Rust。

### 此次已修复：H2 意外关闭 TLS 1.3

native/src/net/tls.rs 原先调用 SslAcceptor::mozilla_intermediate。boring 5.2 的该旧 v4 helper 明确设置 NO_TLSV1_3；之后设置 min_proto_version=TLS1_2 不会清掉它。已有 ALPN/载荷测试可以通过 TLS 1.2，所以没有覆盖这个错误。

本轮先新增真实回归，用同一受信本地 CA 强制 TLS 1.2 和 TLS 1.3，完成 H2 GET。修复前 TLS 1.3 得到 TLSV1_ALERT_PROTOCOL_VERSION；随后改用 mozilla_intermediate_v5，明确 min=TLS1_2、max=TLS1_3。保持公开 H2-only、禁用 0-RTT 的约束，未修改客户端或上游源码。

## 建议实施顺序

### 第一阶段：保留组件，先修配置和资源策略

1. TLS 1.3 配置错误已修。继续用正常密码套件/签名算法与硬件特性协商，维持现有客户端支持；记录实际 TLS 版本、协商结果、握手 CPU/字节和恢复率。
2. 统一 TLS 策略和 generation 工厂，保留 H2/H3 必须不同的协议约束。**后续已完成**：先读取 CURRENT 标识，只在 generation 变化时做完整证书验证和构造，避免未变时重复读私钥/重建上下文。此前重复构造并不发布，不能误称其每五秒切断恢复会话。
3. 对正常 1-RTT 会话恢复补验收，分别检查 H2/H3 ticket 生命周期、实际换证/重启与失败恢复。库可能已有默认 ticket 行为，当前缺少项目级明确策略和证据，不能直接写成完全未实现。自动轮换的库默认通常优于写死 ticket key；只有确有跨进程恢复需求才管理加密私有 keyring，按服务身份/协议隔离。恢复可以减少 CPU 和证书传输，但不需要启用 0-RTT。
4. 拆分初始窗口、最大窗口、应用队列与全局接收授信预算；按目标 RTT/带宽和内存确定值。当前默认连接窗口 16 MiB、共享预算 64 MiB，会把两协议连接合计限制在约 4 条，早于 max_connections=128。启动状态应显示有效容量。已公告的 QUIC/H2 接收信用不能当成可任意收回的预算，不能只统计当前 Vec 长度就解除限制。
5. 补齐服务级聚合指标与故障阶段、优雅停止和必要告警。仅本地管理接口开放指标，不将调试接口或目标/密码/原始认证头放进公共网站。第四阶段列出的网站语义工作在本阶段同步推进，优先于大规模吞吐调优。

上述优化不改变客户端协议。ArcSwap 可用于读多写少的不可变快照，但应先解决重复构造；现有 RwLock 只在获取/发布 generation 时短暂使用，不能未经测量就认定其为主瓶颈。

### 第二阶段：H3 调度与 UDP IO

当前一个 h3::serve task 遍历所有 QUIC 连接/流、处理定时器并逐包发送，正确性边界较清楚，但多连接负载由一个调度任务承担。发送路径还会频繁分配 1350 字节 Vec。

两条可行路线：

| 路线 | 做法 | 取舍 |
| --- | --- | --- |
| A：保留现有 quiche driver | 接收/按 CID 路由、每连接或分片 worker、有界队列、复用包缓冲、统一定时/公平调度；分步接入 UDP 批处理 | 能保留现有 TLS/额度/流状态语义，迁移小；需持续维护路由和 IO 细节 |
| B：tokio-quiche PoC | 复用 Cloudflare 异步连接 worker、H3Driver、CID router、缓冲及 UDP 优化，业务仍用现有认证/ACL/codec | 可减少自写底层维护；接口、依赖、证书热更新和资源控制须先实测，不能直接替换 |

本地 pin 的 tokio-quiche 为 0.20.1，MSRV 1.88，boring 约束 >=4.19,<6，声明层面与本项目 Rust 1.89 / boring 5.2 相容，尚未解析/构建本项目的新集成。其 socket 支持能力探测、GSO/GRO、pacing；datagram-socket 有 sendmmsg/recvmmsg。目标 Linux/内核/NIC 不支持时必须回落普通 IO，并保留正确发送节奏。

迁移门槛尤其包括：tokio-quiche 的自定义 SSL context hook 在 socket 初始化时调用，并非每个新连接都调用；证书 generation 热切换不能靠在该 hook 中重新读 CURRENT 就宣称实现。须验证已有 API 能否承接证书切换、旧连接保留、严格 ALPN、0-RTT 关闭、预算、Retry、FIN/reset 及取消；不满足就继续路线 A。其 README 和 manifest 的默认 feature 描述有差异，应以 manifest/实际依赖图为准，关闭不需要的压缩日志功能，保留 X509 证书，不引入 RPK。

先做 B 的小范围对照原型，通过上述门槛和吞吐/延迟/RSS 测量后再决定是否替换 A。单纯减少源码行数不能证明集成更稳定。

### 第三阶段：协议与应用数据路径

- 以共同的 TunnelService 复用认证后建连、codec 和双向生命周期；adapter 保留 H2/H3 各自窗口信用、FIN/reset/GOAWAY 的职责，不能用普通 AsyncRead/Write 抹去这些差异。
- **按本轮用户要求暂缓** Bytes/BytesMut 尾部复用与 RNG 精简。保留前八条填充、之后原始流、16 KiB 读取块、尾部 Vec 复制与 padded 分支继续取随机字节的现状；以后先做 wire 和真实分布对照再决定，额外 RNG 调用本身不构成抗识别证据。
- 处理短写时保留已编码数据与 offset。TLS/QUIC 仍需要加密和协议处理，目标是减少应用复制，不能称为全程内核零拷贝；改变读取批量可能影响包长/时序，需复跑行为对照。
- **后续已接通** quiche CUBIC / BBRv2，配置中显式使用 bbr2，拒绝会混淆版本的 bbr 别名；并分开接通 Linux TCP BBR 与 Quinn BBR。保留未写 transport 的旧配置行为。作用范围和对照矩阵见新文档，不将 BBR 描述为默认更快或更隐蔽。

### 第四阶段：网站与证书运维成熟度

优先补齐共同 SiteService 的 Range、Last-Modified/条件请求、稳定错误页/缓存与一致资源语义；有实际页面需求时再增加压缩或配置好的本地应用后端。H2/H3 普通请求与认证失败必须继续进入同一 handler。

hyper/http/tower-http 可用来实现或复用应用服务语义，经适配器接入；这些库不会自动提供本项目 H3/TLS 前端。不需要为了网页功能启动一套行为不同的公网 TLS 监听。证书工作进程继续隔离，完成真实 Porkbun/GTS staging/production、重启/换证和 24h 网络验收后再评估解除生产入口闸门。

## 组件选择

| 组件 | 建议 |
| --- | --- |
| Pingora + h2 | 保留，当前真实路径和兼容证据可复用；先不重写为另一 H2 栈 |
| boring + tokio-boring + quiche | 保留，TLS/QUIC/ACME 依赖审计和策略集中管理 |
| tokio-quiche / datagram-socket | 优先验证的 H3 调度/UDP 候选，满足热更新与额度语义后再集成 |
| bytes / tokio-util | 缓冲、取消和计时边界；收益由复制/调度剖析验证 |
| arc-swap | 可选快照发布优化，不能替代持久化事务和证书验证 |
| hickory-resolver | 若 DNS 延迟成为瓶颈，再引入尊重 TTL 的有界缓存；每次命中仍检查 IP ACL/self-loop |
| tracing / metrics | 服务级可观测性，控制标签基数并去除秘密/目标内容 |
| io_uring / 全局 allocator 更换 | 后置，先测 Tokio/复制/UDP 瓶颈，避免不必要地牵动整个运行时 |

PQC/混合密钥交换可在现有官方客户端、所 pin BoringSSL 构建和算法协商都支持时另测握手大小、CPU、MTU；不是当前优先项。ECH 需要客户端现有能力、DNS 发布和服务端密钥配置协同，不能由换库单独获得。BoringSSL 也不会改变客户端 ClientHello，或把 Cloudflare quiche 变成 Chromium 的 Google QUICHE。

## 性能和网站行为验收

比较对象固定为：实际使用版本的 Caddy+作者插件（标注是否含 BBR 补丁）、moon-naive、使用相同 Rust TLS/H2/H3 前端且关闭代理功能的纯网站对照。控制硬件、证书算法、页面内容、流数、窗口、RTT/丢包、拥塞控制和 0-RTT/Fast Open 策略。

采集 TLS 握手 CPU/字节/恢复率、首字节与小流 p95/p99、单流和多流吞吐、重传、RSS/fd/task、队列/预算回收；对比正常网站 TLS/H2 SETTINGS/QUIC 参数与关闭、错误和缓存语义。较大窗口、BBR、批量合包都可能改变网络行为，吞吐增长不自动代表识别风险下降。

## 此次修复的验证记录

本节为此前 TLS 修复阶段的测试和 reports/server-tls-* 记录。当时新增强制 TLS 1.2/1.3 的真实 H2 网站测试，先复现协议版本失败再验证修复，未在该阶段启用 BBR 或替换 H3 driver。后续已接通的 BBR、可选后端和取消修复请参阅当前 transport 文档。

| 本次检查 | 实测结果 |
| --- | --- |
| 修复前强制版本回归 | TLS 1.3 失败，TLSV1_ALERT_PROTOCOL_VERSION；保留复现报告 |
| 修复后 native Debug / Release | 各 29 项通过，包含强制 TLS 1.2/1.3 和当前官方客户端用例 |
| 实际 Pebble CA Debug / Release | 各 2 项通过，显式执行外部用例 |
| 官方客户端 -4 | Debug / Release 的 H2/H3 通过 |
| 相邻 -3、较早 150 | Release 再验 -3 H2/H3、150 H2 均通过；150 H3 的本地根限制仍见前阶段记录 |
| native all-targets clippy | -D warnings 通过 |
| Release 实验网络/ACME 产物 | 构建通过 |

以上为 TLS 修复阶段证据，当时根 workspace 未修改、沿用 Debug/Release 各 39 项。后续 transport 配置/可选依赖/证书读取优化已更新根和 native workspace，当前验证见 TRANSPORT-VERIFICATION.md。上游和官方客户端仍未修改，没有测定性能提升或网站行为相似度。

---

<a id="transport-verification"></a>

## 原文件：docs/history/TRANSPORT-VERIFICATION.md

# rustls/Quinn/BBR 验证记录

历史验证记录：本文件对应已归档的双后端阶段。当前代码按用户要求移除了 Rustls/Quinn，以下 feature、配置和命令已不适用；当前说明及验收见 [WEBSITE.md](WEBSITE.md) 和 [WEBSITE-VERIFICATION.md](WEBSITE-VERIFICATION.md)。保留历史结果以便追溯，不作为当前构建证据。

## 环境与版本

- Linux 6.18.55 x86_64，Rust/Cargo 1.89.0。
- 实际内核 tcp_available_congestion_control 为 `reno bbr`，系统原有默认是 `bbr`；本轮未写 sysctl/qdisc，也未运行模块加载命令。
- boring/boring-sys 5.2.0、tokio-boring 5.0.0；本地 pin 的 Pingora / quiche 0.30.0 / instant-acme 0.9.0。
- 可选 rustls 0.23.46 / tokio-rustls 0.26.6 / Quinn 0.11.12 / quinn-proto 0.11.19 / h3 0.0.8 / ring 0.17.14，依赖图审计固定 provider。
- 官方未修改 Linux 客户端：v154.0.8037.49-4、相邻 -3，以及较早 v150.0.7871.63-1。客户端文件 SHA256 见本节后表。
- 本地真实 Pebble / challtestsrv；测试 TLS 使用私有临时 CA，正常验证 CA 与域名，未关闭校验。

## 最终矩阵

| 构建/配置 | Debug | Release | 证据文件 |
| --- | --- | --- | --- |
| 根 workspace | 40 项通过 | 40 项通过 | reports/transport-root-verify.txt |
| 默认构建，quiche BBRv2 + TCP BBR | 33 项通过 | 33 项通过 | reports/transport-default-{debug,release}.txt |
| rustls-quinn feature，Quinn BBR + TCP BBR | 34 项通过 | 34 项通过 | reports/transport-rustls-{debug,release}.txt |
| 实际 Pebble 自动签发/恢复/续期/EAB 两用例 | 两种构建各 2 项通过 | 两种构建各 2 项通过 | 同上完整测试报告的 acme_pebble 部分 |
| native all-targets clippy -D warnings | 两种构建通过 | — | reports/transport-{default,rustls}-clippy.txt |
| Release 网络与 ACME 产物 | — | 两种构建通过 | reports/transport-{default,rustls}-build.txt |
| fmt、两个依赖审计、固定上游 pin/干净度 | 通过 | — | reports/transport-fmt.txt、transport-audit-*.txt |

33/34 项的计数包含显式启用的官方客户端用例，不把 ignored 当作通过。实验构建多出的一个测试直接断言真实 Quinn 连接的控制器为 Bbr，并验证取消监测不消费排队数据、FIN/ACK 与 reset 的区别。ACME 在两种构建下仍使用原有 BoringSSL 路线，未改成 rustls ACME。

| 附加检查 | 实际范围与结果 |
| --- | --- |
| 官方 -4 | 上表 Debug/Release 两后端均通过 H2/H3、legacy Padding、同连接多流复用与错误凭据无拨号 |
| 官方 -3 | Release 两后端 H2/H3 通过；reports/transport-{default,rustls}-official-adjacent.txt |
| 官方 150 | Release 两后端 H2 通过；reports/transport-{default,rustls}-official-previous-h2.txt |
| CUBIC 对照 | 两后端 Release 各运行真实 H3 TLS/站点/认证/Padding/流控/半关闭用例及两个早到 DATA 用例，共 3 项通过；不是全套重新跑 CUBIC |
| TCP BBR | 真实接收 socket 从 reno 切到 bbr 后读回；真实 Egress::dial 返回 socket 读回 bbr，主矩阵明确设置测试环境变量以实际执行 |
| CLI 正例 | 默认 GTS 的 boring-quiche/bbr2/bbr，旧配置的 boring-quiche/cubic/system，以及实验 GTS 的 rustls-quinn/bbr/bbr 均通过预检 |
| CLI 反例 | 不带 feature 的真实 Release 二进制选择 rustls-quinn 时非零退出，明确说明缺少 feature |
| 配置反例 | quiche+bbr、Quinn+bbr2、未知算法/后端/字段拒绝；原有禁用 H1/Fast Open/0-RTT 约束保留 |

v150 的 H3 在此前基线有本地根信任限制，见 MOON-NAIVE-VERIFICATION.md；本轮没有补齐公网受信证书测试，不能据此声称两个不同 Chromium 主版本的 H3 均已通过。

实际 Release 产物分别保存在当前工作区：

```text
/workspace/moon-naive-transport-artifacts/boring-quiche/moon-naive-net
/workspace/moon-naive-transport-artifacts/boring-quiche/moon-naive-acme
/workspace/moon-naive-transport-artifacts/rustls-quinn/moon-naive-net
/workspace/moon-naive-transport-artifacts/rustls-quinn/moon-naive-acme
```

构建大小和网络二进制 SHA256 在 reports/transport-binary-sizes.txt / transport-binaries.sha256。它们是本机 Linux 构建产物，源码包不包含二进制、target 或上游仓库；同级依赖 clone/pin 步骤见 BUILD-AND-USE.md。

## 新增回归先失败、再修复

早到 DATA + 延迟 30 秒拨号期间 reset 的测试，在原 quiche adapter 下未能于两秒内归还应用请求/隧道额度。CUBIC 与 BBRv2 均重现，失败报告有意保留：

```text
reports/transport-quiche-admission-before-fix-cubic.txt
reports/transport-quiche-admission-before-fix-bbr2.txt
```

原有 h3::poll 在未读 Data 状态下可能不报告后来的重置；现通过发送侧 STOP 检查与接收终态零字节检查补齐。不是通过增加 DATA 消费或增大窗口解决。最终两后端分别测试单独 STOP_SENDING、单独 RESET_STREAM、双向 reset、空/非空早到 DATA + 正常 FIN；取消后无拨号、应用额度归零，正常 FIN 后目标完整接收并回传响应。

完整矩阵同时回归强制 TLS 1.2/1.3 H2、严格 ALPN、站点/认证失败回落、实际目标连接成功前无 200、私网 ACL、Padding 八条边界、慢速读取、小接收窗口、单向持续活动/静默到期和 H2/H3 换证。

## Padding 未变证明

与上一份 moon-naive-server-src-2026-10-22.tar.xz 中的源码比较，以下两文件 cmp 完全相同：

```text
e2f243e24de9a516289770637627e3070cdd06a4ce6130e6a508c326adf3976b  crates/core/src/codec.rs
95337882434c46f897dd5971da23f8c45254bb28e859dab862b1396c6857eecf  crates/core/src/padding.rs
```

未修改原有目标读取 CHUNK=16 KiB、尾部 Vec 复制或 padded 分支中的随机数调用。Quinn 使用同一 H3 bridge，不另写不同的 Encoder/Decoder/RNG 路径。源码/协议语义相同仍不意味着 TLS/QUIC 包化与时序相同。

## 复跑

先按 BUILD-AND-USE.md 准备固定同级上游和 Linux 原生工具链，并设置实际外部测试程序路径：

```sh
export NAIVE_BIN=/absolute/path/to/unmodified/naive
export PEBBLE_BIN=/absolute/path/to/pebble
export CHALLTESTSRV_BIN=/absolute/path/to/pebble-challtestsrv
export PEBBLE_SOURCE=/absolute/path/to/pebble-source
export MOON_NAIVE_TEST_TCP_CONGESTION=bbr
export MOON_NAIVE_TEST_QUIC_CONGESTION=bbr2
cargo test --manifest-path native/Cargo.toml --locked -- --include-ignored --test-threads=2
cargo test --manifest-path native/Cargo.toml --locked --release -- --include-ignored --test-threads=2

export MOON_NAIVE_TEST_BACKEND=rustls-quinn
export MOON_NAIVE_TEST_QUIC_CONGESTION=bbr
cargo test --manifest-path native/Cargo.toml --locked --features rustls-quinn -- --include-ignored --test-threads=2
cargo test --manifest-path native/Cargo.toml --locked --release --features rustls-quinn -- --include-ignored --test-threads=2
```

这些 MOON_NAIVE_TEST_* 开关只用于 cfg(test) fixture，不改变正式运行配置或生产 IP ACL。每个矩阵启动独立 test 进程，测试内不修改全局环境变量。换回默认矩阵时 unset MOON_NAIVE_TEST_BACKEND；无需 BBR 的 CI 可单独运行 CUBIC/system，但不能将其写作 BBR 内核验证。附加客户端分别设置 NAIVE_BIN；v150 H2 设置 NAIVE_TEST_PROTOCOLS=https。实际使用的 CMake/libclang 配置与上一阶段相同。

## 外部程序 SHA256

| 文件 | SHA256 |
| --- | --- |
| naive v154.0.8037.49-4 | 9fba072aceb445d0401bb26273584726c479f5c4bc7f911aebf293c90136b044 |
| naive v154.0.8037.49-3 | e03a46e63923bb05a442f643f0544958ebf1bbee7bd31a5663561eac74bf6c93 |
| naive v150.0.7871.63-1 | baea1e9b9f8dd879a6374110bd7bdca80c2ecbdca8debc4f84f784a8739eaea7 |
| pebble | 5bb2ad542964dfd897b2a2d177f39e99eb0342dc0e9137116c1cbb3058c9315d |
| challtestsrv | 10e0092323cbd61b14e344bc784186258853655d7d27b9dfee0ed787f3dbe877 |

没有执行吞吐/CPU/RSS 公平性基准、正常网站/作者 Caddy 的流量差分、真实 GFW 路径或 24h 稳定性验收。这些用例的运行时含固定等待，不应拿来推断性能优劣。`moon-naive serve` 仍保持生产验收闸门；本轮互操作结果不构成抗识别效果证明。

---

<a id="verification-2026-10-21"></a>

## 原文件：docs/history/VERIFICATION-2026-10-21.md

# 当前验证：架构优化（2026-10-21）

2026-10-22 项目已更名 pinaive。本文和原始日志保留当时名称，当前命令和验证见 [BUILD-AND-USE.md](BUILD-AND-USE.md)、[VERIFICATION-2026-10-22.md](VERIFICATION-2026-10-22.md)。

本文件记录前一阶段架构优化时点；同日后续 ACME 实施已完成原生 Release 工作进程和真实本地 CA 测试，最新证据见 [ACME-VERIFICATION.md](ACME-VERIFICATION.md)。

原始交接包中的 Termux 测试属于历史记录。本文件记录本轮从用户源码包恢复后的实际验证，不将领域测试计作网络互操作。

## 环境与输入

- Linux x86_64，Rust/Cargo 1.89.0，GCC 14.2.0。
- native 使用 CMake 3.31.6、系统 libclang 19。
- 固定版本上游六仓已恢复，`xtask verify` 核对 HEAD 与干净度通过，未修改上游源码。
- 根 Cargo.lock 未改变；native/Cargo.lock 仅为新增本地 naive-core 依赖加入其轻量依赖，没有升级已有原生包。

## 结果

| 检查 | 结果 | 证据 / 范围 |
| --- | --- | --- |
| 原始代码恢复后的 Debug 单测 | 30 通过 | 改动前重跑，不沿用旧 target |
| 根/native 格式、根 clippy `-D warnings` | 通过 | `xtask verify` |
| 当前 Debug 单测 | 37 通过 | core 24 + control 13 |
| 当前 Release 单测 | 37 通过 | core 24 + control 13 |
| 根 workspace Release 构建 | 通过 | 含 naived 与 xtask |
| CLI golden 字节对拍、H1 配置反例、serve fail-closed | 通过 | 实际执行 CLI，未打开 listener |
| native normal 依赖图 | 通过 | 单一 boring/boring-sys 5.2.0；无 rustls/OpenSSL/AWS-LC/ring TLS 实现 |
| native Debug test 编译/链接 | 通过 | 实际执行 1 个 quiche/BoringSSL 配置构造测试 |
| native check | 通过 | 同一工具链环境，实际编译 Pingora/quiche/boring 接缝 |
| native Release 构建 | 未执行 | 不将 Debug 链接视为 Release 验证 |
| 核心模型 soak | 通过 | 100,000 轮，511,510,083 payload bytes，最终 permits=0，1511 ms |
| 官方 Naïve H2/H3 互操作 | 未执行 | listener/driver 尚未实现 |
| 网站行为差分、真实 ACME、24h 网络 soak | 未执行 | 见 ARCHITECTURE/ACCEPTANCE 的后续门槛 |

`openssl-macros`、`openssl-probe` 和 `rustls-pki-types` 是过程宏/环境探测/数据类型，不是另一个 TLS 引擎。依赖图与 native 测试证明本轮接缝能解析、编译和运行配置构造；没有生产二进制和真实握手时，不外推其网络行为。

## 本轮新增测试覆盖

- 缺失、错误、重复认证，连同畸形目标/扩展参数，走清理后的相同网站请求边界。
- preamble GET 保留网站语义；同一连接下一流仍须认证。
- 已认证 ordinary CONNECT 的 scheme/path/protocol 边界；legacy 首值 Padding 与不启用新版本协商。
- 非 UTF-8 认证失败回落；无关网站 header 原始字节不改变。
- Padding 独立字节向量、所有长度映射；共享配置窗口推导和数值溢出拒绝。
- native 使用真实 boring 上下文构造 quiche Config；没有模拟 QUIC driver。

## 复现

已有正常原生工具链时：

```text
cargo run --release --locked -p xtask -- verify
cargo run --release --locked -p xtask -- audit-native
cargo run --release --locked -p xtask -- soak 100000
cargo check --manifest-path native/Cargo.toml --locked
cargo test --manifest-path native/Cargo.toml --locked
```

上游路径与 pin 见原交接包 REPRODUCE.md 和 xtask。源码包不包含上游仓库或 target。

本次环境起初没有 CMake，且 libclang 缺少内建头文件，native check 因构建环境失败。系统包安装权限不可用；已在项目外安装用户目录 CMake，并为该会话的 bindgen 指定现有 GCC 头文件路径后完成 native test。没有修改原生依赖来跳过构建或关闭校验。复现该特定会话的环境选择为：

```text
PATH=/workspace/naive-build-tools/cmake-3.31.6-linux-x86_64/bin:$PATH
LIBCLANG_PATH=/usr/lib/llvm-19/lib
BINDGEN_EXTRA_CLANG_ARGS=-isystem /usr/lib/gcc/x86_64-linux-gnu/14/include
```

最后一项是一个完整环境变量值，需按所用 shell 正确引用；常规机器应安装完整的 CMake/C++/libclang 开发工具链，不照抄本会话的绝对路径。

## 证据文件

- `reports/verification-1792582945446860105-8815.txt`：根验证。
- `reports/native-graph-1792582877607535370-5772.txt`：依赖解析快照。
- `reports/model-soak-1792582879151089111-5769.txt`：模型 soak。
- `reports/native-debug-2026-10-21.txt`：实际 native test 输出。
- `reports/native-check-2026-10-21.txt`：修复工具链环境后的 native check。

前两份自动报告中的 `native compilation=not performed` 表示对应 xtask 命令本身不编译 native；本轮另外执行的 native test 以独立记录为准。

---

<a id="verification-2026-10-22"></a>

## 原文件：docs/history/VERIFICATION-2026-10-22.md

# pinaive 更名与构建复验（2026-10-22）

源码工作目录已由 server/ 更名为 pinaive/；主 CLI 为 pinaive，独立 ACME CLI 为 pinaive-acme，内部包为 pinaive-core / pinaive-control / pinaive-native。没有升级第三方依赖；与前一轮源码包比较，两个 Cargo.lock 的差异仅为本地包名和对应引用。

平台：Debian 13 / Linux x86_64；Rust/Cargo 1.89.0、GCC 14.2、CMake 3.31.6、libclang 19。Go 1.24.2 与 Pebble v2.7.0 仅用于本地 CA 测试。

| 检查 | 实测结果 |
| --- | --- |
| 根 workspace fmt/clippy/Debug/Release/build | 通过；core 25 + control 13，每个 profile 38 项 |
| native fmt/clippy all-targets，-D warnings | 通过 |
| native Debug | 12 单测 + 2 个显式启用的真实本地 Pebble CA 集成通过 |
| native Release | 12 单测 + 2 个显式启用的真实本地 Pebble CA 集成通过 |
| 两个 workspace 合计 | 每个 profile 52 项，0 failed，集成 0 ignored |
| renamed Release 产物 | target/release/pinaive、native/target/release/pinaive-acme 实际构建并执行 |
| renamed CLI | pinaive --help/status/check-config 与 pinaive-acme --help 通过；集成测试实际执行 pinaive-acme status/once |
| 主服务闸门 | pinaive serve 明确非零，不开端口；CLI golden 对拍、H1 反例仍通过 |
| 配置 | 新 /etc/pinaive、/var/lib/pinaive 路径；Porkbun/GTS 示例通过结构检查，选择正确 GTS staging 目录 |
| CA 只读检查 | 更名后 Release pinaive-acme 成功读取 GTS staging directory，正常 TLS 验证，无账户/DNS 写入 |
| normal 依赖图 | 单一 boring/boring-sys 5.2.0，无额外 rustls/OpenSSL/AWS-LC/ring 实现 |
| 上游审计 | 六个固定 commit 与工作区干净度通过，上游代码未修改 |
| native 运行库 | 本机 ldd 为 libstdc++、libgcc_s、libm、libc 和 Linux loader；没有动态 libssl/libcrypto，不能称为跨发行版通用的全静态产物 |
| 公网 Porkbun/GTS 签发、代理互操作、24h 网络稳定性 | 未执行；本次没有真实凭据、没有连接 VPS，也没有实现公开 listener |

本地 Pebble 覆盖普通账户与强制 EAB 账户两条路径：实际 HTTPS/JWS/CSR/DNS-01 签发、ARI、重启、续期、DNS 故障保留旧证书、持久化退避/订单恢复，以及移除 EAB 文件后续期和按原 account key 找回账户。Porkbun 测试使用本地兼容 API，不能代替真实 Porkbun 公网 API 验收。

## 执行命令

```text
cargo run --release --locked -p xtask -- verify
cargo run --release --locked -p xtask -- audit-native
cargo clippy --manifest-path native/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path native/Cargo.toml --locked -- --include-ignored --nocapture
cargo test --manifest-path native/Cargo.toml --release --locked -- --include-ignored --nocapture
cargo build --manifest-path native/Cargo.toml --release --locked --bin pinaive-acme
native/target/release/pinaive-acme check-ca config.porkbun-gts.example.toml
```

实际测试设置了 PEBBLE_BIN、CHALLTESTSRV_BIN、PEBBLE_SOURCE；原生构建使用本会话的 CMake 路径、LIBCLANG_PATH=/usr/lib/llvm-19/lib、GCC 14 系统 include 提示。它们是本机工具选择，不是其他 Linux 系统必须照抄的路径。

## 证据文件

- reports/verification-1792628460317883062-3331.txt、pinaive-root-verify-2026-10-22.txt。
- reports/native-graph-1792628495108019080-3661.txt、pinaive-audit-2026-10-22.txt。
- reports/pinaive-native-clippy-2026-10-22.txt。
- reports/pinaive-native-debug-2026-10-22.txt、pinaive-native-release-2026-10-22.txt。
- reports/pinaive-native-build-2026-10-22.txt。
- reports/pinaive-cli-help-2026-10-22.txt、pinaive-config-check-2026-10-22.txt、pinaive-status-2026-10-22.txt、pinaive-acme-help-2026-10-22.txt。
- reports/pinaive-check-ca-2026-10-22.txt、pinaive-native-ldd-2026-10-22.txt。

先前 naived 时代的报告保留原名和输出，不把历史结果改写为当前命令。当前使用说明见 BUILD-AND-USE.md；未完成功能见该文件的可用性表和 ACCEPTANCE.md。

---

<a id="verification-rc1"></a>

## 原文件：docs/history/VERIFICATION-rc1.md

# 0.1.0-rc.1 验证记录

日期：2026-10-22。主机 Linux x86_64，静态构建使用 Rust 1.89.0、Alpine 3.22、GCC 14.2、CMake、libclang 19。上游 Git pins 与 BoringSSL 版本见 RELEASING.md。

| 项目 | 结果 | 本地 reports/ 日志 |
| --- | --- | --- |
| musl workspace all-targets check | 通过 | release-musl-check-second.txt |
| Debug 静态测试 | 85 项通过，0 ignored | release-debug-build.jsonl、release-debug-tests.txt |
| Release 静态构建/测试 | 构建通过；85 项通过，0 ignored | release-musl-build-final.txt、release-tests-build.jsonl、release-tests.txt |
| Rust fmt / clippy | 本项目五包 fmt 通过；musl workspace all-targets 和 host xtask clippy 均无警告 | release-musl-clippy-final.txt、release-xtask-clippy-final.txt |
| 单一 TLS/QUIC 依赖图与 Git pins | 通过 | release-audit.txt |
| ELF 静态链接 | static PIE；无 INTERP 或 NEEDED | xtask dist 同时强制检查 |
| Alpine 3.22 / Debian 12 / Arch Linux base | 普通用户、只读容器、无 capability 下运行通过 | release-platform-smoke-final.txt、platform-smoke 日志 |
| systemd / OpenRC 文件 | systemd-analyze verify 和 OpenRC sh -n 通过 | 本地语法与单元验证，不等于开机部署 |
| 核心确定性压力模型 | 100,000 轮通过，511,510,083 payload 字节对拍，结束时 active permits=0 | release-model-soak.txt、model-soak 日志 |

85 项包含 control 13、core 29、native 单元/网络 39、真实 Pebble 2、真实 CLI 集成 2。官方客户端为未修改 Linux v154.0.8037.49-4；测试显式启用 H2/H3 互操作和 BBR。Pebble 用例现在直接覆盖集成 runtime：DNS present 尚未完成时 TCP/UDP 未绑定，签发验证后实际 H2 网站可用，再验证停止、恢复、续期和 EAB 账户找回。CLI 测试通过真实子进程验证首次 CA 请求途中 SIGTERM 的退出与清理。

Debug/Release 测试程序均由 Alpine musl 工具链构建，再由 Rust xtask 在具备官方客户端/Pebble 工具的 Linux x86_64 主机实际执行；各模式均为 85 passed、0 failed、0 ignored。发行版容器运行的是同一静态服务端，检查版本、TOML 结构和实际 socket BBR 设置/读回；另挂载宿主 CA bundle，以正常 TLS 验证只读访问 GTS staging directory。没有创建账户/订单或更改 DNS。容器共享宿主内核，不代表各 VPS 内核均提供 BBR。systemd 单元验证只将 ExecStart 替换为工作区内实际二进制路径；没有安装或启动宿主服务。

压力模型检验核心预算与字节状态机，不是公网网络压测。`reports/` 保留本地日志，不装入发布包；包内包含此记录、构建信息、依赖/许可证清单和校验和。构建中暴露的 musl host build script/libclang 加载问题已通过独立 Rust wrapper 解决；最终检查没有剩余编译或测试失败。

普通网站新增功能和原有 Padding/半关闭/慢读/取消/热更新均保留网络回归。指纹没有与 Caddy 的同条件抓包对照，不能据此宣称抗识别改善。公网 CA/DNS、完整发行版开机服务和目标 VPS 长期验收未执行，见 ACCEPTANCE.md。

---

<a id="verification"></a>

## 原文件：docs/history/VERIFICATION.md

# 框架实际验证记录

日期：2026-10-14。环境：Termux / aarch64-linux-android，Rust/Cargo 1.99.0。

## 通过的检查

- 根 workspace 与 native 接缝 `cargo fmt --check`。
- 根 workspace `cargo clippy --workspace --all-targets --locked -- -D warnings`。
- Debug 单测：**30 passed，0 failed**（核心 17、控制面 13）。
- Release 单测：**30 passed，0 failed**，相同 30 个用例，不虚报成 60 个独立测试。
- 根 workspace Release 构建；生成 `target/release/naived` 和 `target/release/xtask`。
- 配置 CLI stdout 与 golden fixture **逐字节相同**。
- H1=true 配置的实际 CLI 执行返回非零。
- `naived serve` 实际返回非零并明确 fail-closed，没有启动 listener。
- 六个参考仓库的 Git HEAD 与记录一致，工作区干净。
- 原生 normal 依赖图审计：共用 `boring 5.2.0` / `boring-sys 5.2.0`，没有混入 rustls、hyper-rustls、OpenSSL、AWS-LC 或 ring 实现。

完整验证报告：
`../reports/verification-1791982432502231366-32326.txt`

原生图审计报告：
`../reports/native-graph-1791982446238361828-7508.txt`

## 核心模型连续验证

执行 `target/release/xtask soak 100000`：

- 循环：100,000。
- 实际逐字节比较 payload：511,510,083 bytes。
- 每轮含 10 次编码、随机化但可重现的输入长度/填充/分块，以及第 8 条记录后的原始流。
- 同时检查 permit 回收、续期失败后旧证书有效性与过期判定。
- 结束 active permits = 0，结果 passed。
- 本次实测耗时 1912 ms；这仅是本地内存模型执行时间，**不是网络吞吐/延迟基准**。

报告：`../reports/model-soak-1791982444974952366-7504.txt`。

## 调试记录

1. Rust 1.99 把 AtomicUsize::fetch_update 标记为 deprecated，导致 `-D warnings` 失败。改为明确的 compare_exchange_weak 循环，不用 allow 掩盖，也不为了更名引入高于预期 MSRV 的 API。额度并发测试重新通过。
2. 首次 Release 构建在执行 proc-macro2 build script 前遇到 `Text file busy (os error 26)`，并未执行该脚本。检查时未发现残留 cargo/rustc 编译进程，lsof 因 Android 挂载权限有可见性限制。随后以 `CARGO_BUILD_JOBS=1` 完整重跑验证成功；未完全证实内核/文件系统层根因，不将它伪称为已修复的源码 bug。没有改全局 Cargo 配置，也没有删缓存。

## 明确未验证

- `native/` 的 Linux 编译和链接，H2/H3 listener 的实际运行。
- BoringSSL ACME HTTP/JWS、DNS provider、真实 SAN/key/chain 校验。
- 真实 DNS TXT 写入、CA 签发、续期和重启恢复。
- 官方 Naïve 客户端互操作、网站防探测差分、真实网络故障注入。
- 24 小时 VPS 网络 soak、RSS/fd/task 长期曲线及实际生产部署。
- 声明的 Rust 1.89 MSRV；目前只有 1.99 实测。

这些未完成项在 [ACCEPTANCE.md](../ACCEPTANCE.md) 单独列出；本记录仅证明项目框架与核心逻辑的上述检查通过。

---

<a id="website-verification"></a>

## 原文件：docs/history/WEBSITE-VERIFICATION.md

# BoringSSL/quiche 与 Pingora 网站验证

日期：2026-10-22。恢复中断任务时先审查工作树，保留既有重命名、TOML、ACME、传输资源/取消与证书热更新修改，补完尚未接线的网站模块。未修改六个固定上游仓库，没有部署或执行公网 CA/DNS 写入。

## 最终实现

- 删除 Rustls/Quinn adapter、feature、依赖和示例，严格配置拒绝旧 `transport.backend`；保留 BoringSSL/quiche、QUIC CUBIC/BBRv2、Linux 每 socket TCP BBR。
- 完整 Pingora HttpProxy 承担网站反代；H2 直接进入，H3 经复用的有界内存 H2 桥进入同一引擎。固定上游路由、池隔离、验证 HTTPS/H2、流式背压、有限连接失败回退及请求体上限。
- ServeDir 提供流式文件、Range、Last-Modified 条件请求，补充弱 ETag；If-None-Match 优先于 If-Modified-Since。文件变更无需重启，目录仍由可信管理员维护。
- gzip、逐跳字段/代理凭据清理、从实际对端生成转发头；保留多值 Set-Cookie 和正常响应 trailers，禁用 SSE/Range/no-transform 的动态压缩。
- 修复 H3 错误凭据 CONNECT 的内部 authority 转换和空请求结束标记；前缀移除保留转义、query 和重复斜杠。原有 Naïve codec、Padding 记录规则、16 KiB 目标读取块、尾部复制/RNG 不变。

配置与架构见 [WEBSITE.md](WEBSITE.md)，可合并 [网站配置片段](../../examples/website.example.toml)。构建仍使用两个 Cargo workspace；原生工具链与上游 pins 见 [BUILD-AND-USE.md](BUILD-AND-USE.md)。

## 已执行结果

环境为 Linux x86_64、Rust/Cargo 1.89.0、GCC 14、CMake 3.31.6、libclang 19。本机已有 TCP BBR；没有修改 sysctl、qdisc 或加载模块。

| 检查 | 结果 | 原始日志，位于本地 reports/ |
| --- | --- | --- |
| 根 workspace check、fmt、clippy -D warnings、Release build、CLI 字节对拍/配置拒绝/生产闸门 | 通过 | website-workspace-check.txt、website-xtask-verify.txt |
| 根 workspace Debug / Release 测试 | 各 42 项通过（control 13、core 29） | website-xtask-verify.txt |
| native all-targets check / clippy -D warnings、fmt | 通过 | website-native-check-final.txt、website-native-clippy-current.txt |
| native Debug，BBRv2 + TCP BBR | 单元/网络 37 + Pebble 2 项通过，0 ignored | website-native-debug-final.txt |
| native Release，BBRv2 + TCP BBR | 单元/网络 37 + Pebble 2 项通过，0 ignored | website-native-release-final.txt |
| 最终网站边界补测，Debug / Release | 各 5 项通过 | website-edge-regression.txt、website-release-edge-regression.txt |
| 默认 CUBIC/system 网络回归 | 22 项通过，1 项官方客户端测试按默认 ignored | website-cubic-regression.txt |
| BoringSSL 单一路线 normal 依赖审计、六个上游 revision/干净度 | 通过 | website-audit-native.txt、native-graph-*.txt |
| 原生网络/ACME Release 产物 | 两个二进制构建通过 | website-native-build-final.txt |
| GTS 配置预检、bbr2/bbr 与 cubic/system 传输预检 | 通过，未开放业务 listener | website-gts-config.txt、website-{gts,default}-transport.txt |
| 确定性模型 soak | 100,000 轮、511,510,083 字节对拍，额度归零 | website-soak.txt、model-soak-*.txt |

以上 37 项包含实际启用的未修改官方 Linux `v154.0.8037.49-4` 客户端 H2/H3 互操作，不把 ignored 算作通过。两个 Pebble 集成测试显式启用，覆盖普通账户和 EAB、签发、重启、续期、账户恢复及 DNS 故障保留旧证书。常规 `cargo test` 默认仍忽略这些需要外部测试程序的用例。

网站测试实际经过 BoringSSL H2/quiche H3 网络前端与 loopback origins，覆盖：

- 文件 200/HEAD、206 Range、304 ETag、条件请求优先级、gzip 解码对拍、在线文件修改、symlink/编码穿越拒绝，以及超过旧 4 MiB 限制的文件。
- H1 上游的 512 KiB/300,000 字节 POST 回传、跨公开 H2/H3 复用同一上游池、原始转义/query/重复斜杠、多值 Cookie、代理字段/客户端伪造转发头清理、SSE/no-transform。
- HTTPS H2 上游的正常 CA/名称验证、独立 Host、池复用、响应 trailers；错误名称在发送 HTTP 前失败，不能复用另一池的已验证连接。
- 失败连接切换到健康 origin、显式 Content-Length 与未知长度流式正文超限均返回 413、POST 不重放、纯反代启动无需站点文件、未知 Host/未命中路由回落。
- H2 reset 和 H3 STOP_SENDING/RESET_STREAM 取消等待响应的上游连接，活跃请求/额度归零。

## 复现

按 BUILD-AND-USE.md 准备原生编译环境，然后：

```sh
cargo run --release --locked -p xtask -- verify
cargo run --release --locked -p xtask -- audit-native
cargo run --release --locked -p xtask -- soak 100000
cargo check --manifest-path native/Cargo.toml --all-targets --locked
cargo clippy --manifest-path native/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path native/Cargo.toml --locked
```

要复现完整外部集成矩阵，显式设置本机已有测试程序的绝对路径，不会由测试自行下载：

```sh
export NAIVE_BIN=/absolute/path/to/official/naive
export PEBBLE_BIN=/absolute/path/to/pebble
export CHALLTESTSRV_BIN=/absolute/path/to/pebble-challtestsrv
export PEBBLE_SOURCE=/absolute/path/to/pebble-source
export MOON_NAIVE_TEST_QUIC_CONGESTION=bbr2
export MOON_NAIVE_TEST_TCP_CONGESTION=bbr
cargo test --manifest-path native/Cargo.toml --locked -- --include-ignored --test-threads=2
cargo test --manifest-path native/Cargo.toml --release --locked -- --include-ignored --test-threads=2
```

`cargo fmt` 原生部分只运行 `cargo fmt --manifest-path native/Cargo.toml --package moon-naive-native -- --check`，避免格式化同级固定上游。

## 尚待完成

- 公网 Porkbun/GTS staging/production 签发、目标 VPS 部署、与参考 Caddy/作者插件的网络行为差分、故障注入及 24 小时稳定性/吞吐/RSS 测量未执行。当前结果不能证明降低 GFW 识别率或性能优于 Caddy。
- H3 网站内存桥未转发 1xx 信息响应；固定版本 Pingora 标准 H2 Session 不转发请求 trailers。响应 trailers 已验证。依赖请求 trailers 的应用、WebSocket/扩展 CONNECT、Caddy 全部 handler/插件功能不在当前能力范围。
- 公网普通 H1、Fast Open 和 0-RTT 继续关闭；旧版 Naïve 150 的 H3 本地根信任限制仍需用公网受信证书验证，未把历史 H2 结果充作其 H3 证据。
- 生产 `moon-naive serve` 仍按原验收规则 fail-closed；实际实验入口为 `moon-naive-net run`。没有安装服务或替换现有节点。

当前编译、静态检查与上述已执行测试均通过，没有遗留编译错误或失败测试。历史中间失败日志保留用于追溯，最终结果以上表为准。

---

<a id="website"></a>

## 原文件：docs/history/WEBSITE.md

# BoringSSL/quiche 与 Pingora 网站引擎

当前服务端只保留 BoringSSL/quiche。`native` 不再有 Rustls/Quinn feature、adapter 或配置示例；旧配置需要删除 `transport.backend`，`quic_congestion` 只接受 `cubic`、`bbr2`，`tcp_congestion` 接受 `system`、`bbr`。省略配置分别使用 CUBIC、系统 TCP 算法。`rustls-pki-types` 是 instant-acme 所需的证书数据类型，不执行 TLS。

```text
TCP → BoringSSL → Pingora H2 ──┐
                              ├→ 共享校验/逐流认证
UDP → BoringSSL/quiche H3 ─────┘       ├→ CONNECT → DNS/ACL/拨号 → 原有 Padding/双向转发
                                     └→ 网站 → Pingora HttpProxy
                                                  ├→ 最长前缀路由 → 上游 H1/H2 连接池
                                                  └→ tower-http ServeDir → 文件流
独立 ACME → 已验证证书 generation / CURRENT → H2/H3 热更新
```

H2 网站请求直接将 Pingora HttpSession 交给完整 HttpProxy。H3 网站请求通过惰性创建、可复用的内存 H2 连接进入同一 HttpProxy；没有新增 TCP 端口或公开 H1 listener。内存管道容量 64 KiB，流级通道容量两格，适配层仍按最多 16 KiB 消费请求数据；H2 流和连接窗口另有限制。这会增加 H3 网站适配开销，尚未以压测证明性能提升。Naïve 隧道不经过此桥，codec、前八条 Padding、目标读取块和随机数调用保持原样。

## 文件、路由和压缩

主配置可直接合并 [website.example.toml](../../examples/website.example.toml)。省略 `[website]` 时继续从 `site_root` 提供网站；文件按请求异步读取，修改内容无需重启。配置和代理用户修改需要重启。

- `files = true` 时启动检查真实目录和普通 `index.html`。使用 ServeDir 提供 GET/HEAD、目录 index/重定向、MIME、单 Range、Last-Modified/If-Modified-Since；增加弱 ETag/If-None-Match 与静态缓存时间。
- 拒绝编码路径穿越、控制字符、反斜杠和符号链接；隐藏文件不提供，`.well-known` 目录例外。目录及其父目录必须由可信管理员维护，路径预检查与随后打开文件并非无竞态隔离机制。
- 去掉旧快照的单文件 4 MiB/总正文 32 MiB 限制，大文件按流发送。没有自动目录列表、模板执行或动态配置 API。
- 路由按字面路径最长前缀匹配，不进行百分号解码；`/api/` 不匹配 `/api`。`strip_prefix` 后保证以 `/` 开头，保留原始转义和 query。未匹配时回落到文件；`files = false` 时返回 404，允许纯反代站点。
- Pingora 响应模块提供协商后的流式 gzip；等级 0 关闭，允许 0..6。Range/206、HEAD、SSE 和上游 `Cache-Control: no-transform` 不做动态压缩，已有 Content-Encoding 不二次编码。未增加响应缓存或 Brotli 压缩服务。

## 反代边界

每个命名池有 1..16 个固定 HTTP/HTTPS origins，最多 32 池、128 条路由。origin 只接受 scheme/authority，不接受账号、路径、query。客户端 authority、CONNECT 目标、请求头都不能成为反代目标。网站 Host 必须匹配配置域名；错误凭据的 CONNECT 交给相同网站引擎并返回 405，不转为任意目标反代。

Pingora 负责上游连接池、HTTP/1.1 keepalive、HTTPS ALPN 后的 H2 复用及流式双向背压。TLS 始终校验证书与主机名；`tls_server_name`、`host_header`、`ca_file` 分别用于 SNI/校验名称、上游 Host 和私有 CA。没有跳过验证开关。CA bundle 最大 1 MiB。不同池使用不同连接分组，避免同一地址的不同信任策略误用连接。

DNS 异步解析并限制为最多 32 个地址，缓存有效期由 `dns_ttl_secs` 配置。连接/读/写/空闲池有独立时限；轮询 origins，连接失败后被动冷却 5 秒。仅 GET/HEAD/OPTIONS 的连接失败允许有限回退，最多两次尝试，不主动重放 POST/上传正文。未提供主动健康探测、负载权重或熔断控制面。

默认最多 64 MiB 请求体，可配置至 1 GiB；预先检查 Content-Length，并在流式读取时再次计数。代理专用认证/Padding 字段不传给网站或上游；清除客户端自报的 Forwarded/X-Forwarded-*，用真实传输对端生成 X-Forwarded-For，并生成 https scheme 和网站 Host。当前没有可信前置代理列表，若套在 CDN 后会记录 CDN 地址。普通应用 Authorization/Cookie 保持 HTTP 语义，响应保留多值 Set-Cookie，移除逐跳字段及上游 Alt-Svc，避免宣告未验证的另一协议/端口。

管理员配置的私有上游可以使用 loopback，和 Naïve 出站 ACL 分开；会拒绝明显回指节点监听器的地址。NAT、别名和多网卡的间接自环仍需部署时核对。可转发响应 trailers；固定版本 Pingora 的标准 H2 Session 不向上游转发请求 trailers，依赖此能力的应用需要另行适配。暂不支持公开 H1、WebSocket/扩展 CONNECT、完整 Caddy handler/插件生态或自动复制 Caddy 的网络指纹；H3 内存桥目前也没有转发 1xx 信息响应。

## BBR 与构建

```toml
[transport]
quic_congestion = "bbr2"
tcp_congestion = "bbr"
```

quiche 在用户态使用 BBRv2；TCP BBR 由 Linux 提供，按 socket 应用于入站 H2、Naïve 出站和 Pingora 网站上游，设置后读回。不修改全局 sysctl/qdisc，不加载内核模块；内核不支持时预检失败，需在部署机准备 BBR 或显式选 `system`。两种 BBR 不共享控制器。改变拥塞控制不等于已提高抗识别性。

沿用 [BUILD-AND-USE.md](BUILD-AND-USE.md) 的工具链与固定上游：

```sh
cargo build --workspace --release --locked
cargo build --manifest-path native/Cargo.toml --release --locked --bin moon-naive-acme --bin moon-naive-net
cargo run --release --locked -p xtask -- audit-native
./native/target/release/moon-naive-net check-transport config.porkbun-gts.example.toml
./native/target/release/moon-naive-net run /etc/moon-naive/config.toml
```

Porkbun/GTS ACME、TOML 凭据和证书存储兼容性保持不变。实验入口仍是 `moon-naive-net`，正式 `moon-naive serve` 保留原生产验收闸门；公网签发、参考服务端网络行为差分、目标 VPS 性能与长期稳定性需要继续验收。测试与结果见 [WEBSITE-VERIFICATION.md](WEBSITE-VERIFICATION.md)。

---

<a id="work"></a>

## 原文件：docs/history/WORK.md

# 框架实施与验收记录

## 2026-10-22 BoringSSL/quiche 与 Pingora 网站续作

- 按用户最新要求移除 Rustls/Quinn adapter、feature、依赖与配置；恢复单一路线依赖审计。下方双后端阶段是历史记录。
- 加入严格 TOML 网站配置和完整 Pingora HttpProxy：H2 直接进入，H3 使用有界内存 H2 桥，共享路由、连接池、文件、压缩和请求头处理。
- 文件改为 ServeDir 异步流式发送，增加 Range/条件请求；反代支持固定多 origin、TLS 校验、受限失败回退、正文上限和头部清理。
- 保持 Naïve codec、Padding、目标读取块/RNG 及 ACME 存储格式；CURRENT 优化和 quiche 取消修复保留。当前说明及测试见 WEBSITE.md、WEBSITE-VERIFICATION.md。

## 2026-10-22 rustls/Quinn/BBR 分步改造

- 新增严格 [transport]：默认仍 boring-quiche/cubic/system，GTS 推荐示例显式选 quiche BBRv2 + TCP bbr；可选 rustls-quinn feature 使用 rustls/ring H2 与 Quinn/h3，复用业务/网站/目标桥接及 codec。
- BBR 使用用户态 QUIC 与 Linux 每 socket TCP 两条独立配置，不修改全局 sysctl/qdisc；TCP 设置后读回，内核不可用或后端 feature 缺失时明确拒绝启动。当前环境真实内核 socket 和 Quinn Bbr 控制器已验证。
- CURRENT 未变时跳过私钥/证书重读和 TLS 构造；只对变化后的 generation 完整验证、原子发布。两后端换证/旧连接/坏更新路径回归。
- 根据用户最新要求，暂停 Padding 尾部缓冲复用及 RNG 精简；未修改编码器、前八条规则、16 KiB 目标读取块和原有随机数调用。
- 新增真实早到 DATA + 延迟拨号 + reset 的取消/额度回收回归；Quinn adapter 单独验证不读 DATA 的 STOP_SENDING/RESET_STREAM 监测及正常 FIN/ACK 半关闭。
- 新测试先重现原 quiche adapter 在早到 DATA 排队时遗漏取消的边界，CUBIC 和 BBRv2 均失败；修复为传输终态/零字节检查，分别验证 STOP_SENDING、RESET_STREAM 和正常早到 FIN，不改变 Padding 或批量大小。
- 该历史阶段曾使用显式实验 feature 及双后端审计，完成矩阵见 TRANSPORT-VERIFICATION.md；后续已按用户要求移除，当前只保留 BoringSSL/quiche。

## 2026-10-22 服务端架构对照与 TLS 修正

- 当前范围按用户最新要求限定为服务端，未修改官方客户端或引入私有协商；架构、Caddy/作者插件对照和后续方案见 SERVER-ARCHITECTURE-AND-PLAN.md。
- 源码审查发现 boring 5.2 旧 mozilla_intermediate helper 显式关闭 TLS 1.3，已先用强制版本的真实 H2 测试复现协议版本失败，再改用 mozilla_intermediate_v5 并明确 TLS 1.2..1.3。
- 修复后 native Debug/Release 各 29 项及两个 Pebble 集成用例通过；当前官方发布版 H2/H3 与相邻发布版/较早版本的已验证协议回归通过，native clippy 与 Release 构建通过。
- QUIC 调度、窗口预算、ticket/恢复、缓冲减少复制和网站语义仍是分阶段方案；未据此宣称性能或抗识别效果已提升。

## 2026-10-22 moon-naive / TOML / 网络适配续作

- 将项目目录、Cargo 包/依赖/import、两个 lockfile、命令、模板和当前操作路径从 pinaive 统一更名为 moon-naive；上游仓库及历史原始报告保留。
- 主配置、用户、Porkbun、GTS EAB、备用 Cloudflare 的运行配置均采用严格 TOML；增加私有示例和不回显秘密的解析器，CLI import-eab 可本地转换私有 gcloud 导出并拒绝覆盖。
- ACME 账户/订单 journal 与证书 generation 格式不变，既有 namespace 和 lease marker 可恢复；迁移说明明确不能丢弃 state_dir。
- H2/H3 共用请求头语法、TE/Content-Length/Host 检查；共享双向活动计时，持续单向上传/下载不会被另一方向读超时中断，部分写入进展也被记录。
- H3 保留拨号前 FIN，桥接任务继承半关闭；慢速读取按偏移发送已编码 Padding 数据。
- 根 Debug/Release 各 39 项；native Debug/Release 各 28 项（含当前官方发布客户端）及两个真实 Pebble 测试通过；fmt、clippy、原生依赖审计和三个产物构建通过。
- 官方未修改 Linux v154.0.8037.49-4/-3 的 H2/H3，及 v150.0.7871.63-1 的 H2 均在 Debug/Release 通过；更早版本 H3 因客户端不接受本地测试根而未完成，等待公网受信证书。不是两个不同 Chromium 主版本 H3 都已通过。
- 未执行公网 GTS/Porkbun 签发/写入、VPS 部署、参考网络行为差分或 24h 网络验收。当前命令仍为 moon-naive-net run，完整证据见 MOON-NAIVE-VERIFICATION.md。

## 2026-10-22 真实网络栈

- 参考固定版本 forwardproxy 的 ServeHTTP / dualStream / flushingIoCopy，保留 legacy Padding 与逐请求认证，按用户要求先连接目标再回 200。
- 新增 native/src/net 和 pinaive-net：真实 Pingora H2、quiche UDP/H3、共享 DNS/ACL/候选拨号、私有用户加载、静态站点、半关闭、取消与有界资源、H2/H3 TLS generation 热更新。
- max_total_receive_bytes 默认 64 MiB，在 H2/H3 之间共享窗口预算；初始信用约束早到 DATA，H3 采用 MAC Retry、CID/地址/时限绑定，0-RTT 和主动迁移关闭。
- 本地网络验证与完整 ACME 回归见 NETWORK-VERIFICATION.md；未运行官方 Naïve、公网节点或 24h 稳定性验收，生产 serve 闸门保留。

## 2026-10-22 项目更名与可用性说明

- 用户要求项目更名 pinaive，已统一主二进制 pinaive、ACME 二进制 pinaive-acme、pinaive-core/control/native 包、配置路径与 systemd 模板；源码目录从 server 移至 pinaive。
- 保留上游 NaïveProxy、Pingora、quiche 等原有名字，不修改固定版本上游仓库；历史验证报告保留当时名称。
- 增加 BUILD-AND-USE.md：逐项列出实际节点尚缺的工作、Caddy/xcaddy 对比、两个 Cargo workspace 的构建产物、Porkbun/GTS 使用与状态迁移。
- 当前验证见 VERIFICATION-2026-10-22.md；本次没有接通代理 listener、没有部署 VPS 或执行公网 CA/DNS 写入。

## 2026-10-21 Porkbun + Google Trust Services

- 用户指定 Porkbun 注册的 .dev 域名，签发方选择 Google Trust Services；推荐配置新增 config.porkbun-gts.example.toml，不替换原有配置兼容性。
- GTS staging/production directory 选择、私有 EAB JSON、持久化账户 key 的 EAB JWS bootstrap、注册响应丢失时按原 key 找回，均已接入现有 Manager。
- 原生 Porkbun v3 DNS provider：registry NS 委派确认、相对 TXT 名称、notes 所有权、Idempotency-Key、权威 DNS 可见性与按 ID 清理；不自动切换 NS 或 CA。
- GTS 测试根仅用于默认 staging 签发证书，production 和 provider HTTPS 隔离。
- 最新验证结果见 ACME-VERIFICATION.md；真实公网 Porkbun/GTS 仍需操作者私有凭据，没有执行公网账户创建或 DNS 写入。

## 2026-10-21 ACME 实施

- 增加 native/src/acme 的 BoringSSL ES256/JWK/HMAC、验证 HTTPS 客户端、Cloudflare provider、权威 TXT 检查、持久化账户/订单/清理 journal、自动管理器和独立 CLI。
- 首次签发、ARI、自动续期、重启恢复、失败保留旧证书、持久化 Retry-After/退避、真实 SAN/key/chain/有效期/用途验证和原子安装已实现。
- manager 与证书写入改用 kernel 文件锁；新进程退出后无需猜测删除旧锁，旧版目录锁单独迁移。
- 实际 Pebble CA/DNS-01 和本地 Cloudflare API 故障用例已执行；尚无公网域名/凭据，因此公网 staging/production 未执行。
- 使用与当前证据见 ACME.md、ACME-VERIFICATION.md；公开 listener 仍未实现。

## 2026-10-21 架构优化

- 用户确认沿用原服务端兼容性，解除“是否集成服务端 Chromium net/”的架构疑问。
- 已增加共享 ingress 分流、网站请求字段清理、普通 CONNECT 校验、兼容响应 Padding 生成器与 TransportProfile；H3 配置接缝引用共享资源值。
- 已更新 REQUIREMENTS/DESIGN，新增 ARCHITECTURE：真实网站优先、认证前后协议设置一致、统一证书 generation、资源隔离、同栈网站和参考服务端差分。
- 本轮未实现网络 adapter、网站文件服务、真实 ACME 或客户端扩展；`serve` 保持 fail-closed。
- 当前验证见 `VERIFICATION-2026-10-21.md`；原有记录保留如下。

## 原始框架实施记录

Goal：建立能用 Cargo 编译、可离线测试的 H2/H3-only Naïve 项目骨架，明确真实网络 adapter 的接入边界。
Spec：[DESIGN.md](DESIGN.md)。本轮已获用户“先去做、完成再告知”授权，不部署真实服务。

## 文件与步骤

- [x] `Cargo.toml`、四个 crate manifest：建立核心/控制面/CLI/Rust 验证工具的单向依赖。
- [x] `crates/core/src/{config,policy,auth,codec,tunnel,limits}.rs`：协议、安全策略及有界状态。测试必须包括 `00 03 02 61 62 63 00 00` wire vector、前 8 帧切换、未知配置项、H1/Fast Open/0-RTT 拒绝、认证先于 authority、200 必须在 connect 后。
- [x] `crates/control/src/{renewal,controller,store,snapshot}.rs`：注入时钟的自动续期调度、真实驱动接口、原子 generation，测试旧证书保留/并发写拒绝/Retry-After/错误候选。
- [x] `crates/daemon/src/main.rs`：配置检查和状态；未完成真实 adapter 时 `serve` 退出非零。
- [x] `xtask/src/main.rs`：运行 fmt/clippy/test/release/check-config、反例与模型 soak，生成验证记录；任一失败使总命令失败。
- [x] `native/`：固定上游来源、实际依赖解析、H2/H3 配置与 ACME provider 接口接缝。记录是否已编译，禁止以 metadata 代替链接验收。
- [x] `README.md`、`docs/ACCEPTANCE.md`：区分已实现状态与未完成网络功能，列出 Linux/ACME/24h 验收。

## 验证命令

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test --workspace --release --locked
cargo build --workspace --release --locked
cargo run --release --locked -p xtask -- verify
cargo run --release --locked -p xtask -- soak 100000
```

原生 workspace 单独在 Linux 执行 `cargo check --manifest-path native/Cargo.toml --locked` 和构建/测试。框架不需要执行任何 shell/Python/Node 脚本。

实测结果见 [VERIFICATION.md](VERIFICATION.md)。本轮清单完成不等于 ACCEPTANCE.md 中的 Linux 原生/真实 ACME/网络上线项目完成。

---

## 原文件：docs/INSTALL.md（已并入 VPS-GUIDE.md）

# 安装与运行

发布目标为 `x86_64-unknown-linux-musl`，服务端二进制不依赖发行版的 glibc、musl 动态加载器或 libstdc++。系统仍须有 CA 根证书、DNS 配置和正常 TCP/UDP 网络。Alpine、Debian、Arch 使用同一个 x86_64 包；内核 BBR 支持由宿主内核决定。

## 准备

校验下载的 `.tar.gz.sha256` 并解压。包内另有 SHA256SUMS，可校验解压后的文件。发行版基础包：

```sh
# Debian
apt-get install ca-certificates
# Alpine
apk add ca-certificates openrc libcap-utils
# Arch Linux
pacman -S ca-certificates
```

需要开放配置中的 TCP 与 UDP 端口，默认生产示例均为 443。DNS-01 本身不需要 80；生产示例启用了 80→HTTPS 跳转，需同时开放 TCP 80，或删除 `listener.http_redirect`。为实际域名准备 A/AAAA、Porkbun API access、Google Trust Services production EAB；首次测试使用 staging 及独立 staging EAB。

Debian/Arch 创建服务用户：

```sh
useradd --system --user-group --home-dir /var/lib/moon-naive --shell /bin/false moon-naive
```

Alpine 创建服务用户：

```sh
addgroup -S moon-naive
adduser -S -D -H -h /var/lib/moon-naive -s /bin/false -G moon-naive moon-naive
```

若用户已存在，保留该用户与现有私有状态。以下命令在新安装、以 root 身份执行；升级参见末节，不要覆盖已有配置：

```sh
install -m 0755 moon-naive /usr/local/bin/moon-naive
install -d -m 0750 -o root -g moon-naive /etc/moon-naive
install -d -m 0700 -o moon-naive -g moon-naive /var/lib/moon-naive
install -d -m 0755 /srv/moon-naive/site
install -m 0644 site/index.html site/style.css /srv/moon-naive/site/
install -m 0600 -o moon-naive -g moon-naive config.production.example.toml /etc/moon-naive/config.toml
```

填写真实 domain、dns_zone、contact、Porkbun 与 EAB 凭据，设置代理用户和密码。密码至少 16 字节，建议用密码管理器生成 32 字符以上随机值。示例文件是占位内容；网站也应换成你实际维护的页面或固定上游。接受相应 CA 条款后设置 `accept_terms = true`。

配置示例显式启用 TCP BBR。`moon-naive check-transport` 会实际创建测试 socket、设置并读回 BBR；不支持时在部署机准备内核 BBR，或显式改为 `tcp_congestion = "system"`。程序不会更改全局 sysctl/qdisc。

```sh
/usr/local/bin/moon-naive check-config /etc/moon-naive/config.toml
/usr/local/bin/moon-naive check-transport /etc/moon-naive/config.toml
```

本地完整检查应以服务用户运行，确认其有权访问凭据、网站、上游 CA 和状态目录。Debian/Arch 示例：

```sh
runuser -u moon-naive -- /usr/local/bin/moon-naive check /etc/moon-naive/config.toml
```

Alpine 示例：

```sh
su -s /bin/sh moon-naive -c '/usr/local/bin/moon-naive check /etc/moon-naive/config.toml'
```

检查不访问 CA/DNS API，不监听端口；首次会初始化私有状态目录和锁。`certificate_ready=false` 在首次申请前正常，服务启动后会自动取证。

`check` 使用控制面的单写锁，适合启动前执行；运行中的服务使用 `check-config` 和 `status` 检查，不启动第二个控制面。

## Debian/Arch：systemd

```sh
install -m 0644 deploy/moon-naive.service /etc/systemd/system/moon-naive.service
systemctl daemon-reload
systemctl enable --now moon-naive
journalctl -u moon-naive -f
```

单元用 CAP_NET_BIND_SERVICE 绑定 443，进程使用普通用户。首次证书未就绪时为 activating，`event=certificate_wait` 明确表示未监听；签发和全部配置监听成功后发 READY。`event=acme_tick` 的 phase/退避时间可诊断 CA/DNS 故障，不记录请求、密码或原始第三方错误。

## Alpine：OpenRC

OpenRC 单元以普通用户运行，绑定 443 需给二进制文件设置相应能力；替换二进制后重新执行 setcap：

```sh
setcap cap_net_bind_service=+ep /usr/local/bin/moon-naive
install -d -m 0700 -o moon-naive -g moon-naive /var/log/moon-naive
install -m 0755 deploy/moon-naive.openrc /etc/init.d/moon-naive
rc-update add moon-naive default
rc-service moon-naive start
tail -f /var/log/moon-naive/server.log
```

OpenRC 的 running 表示进程存活；证书/全部监听就绪以日志 `event=server_ready` 为准。也可使用大于 1023 的 TCP/UDP 端口，此时无需文件 capability。

## 客户端与运行状态

官方 Naïve 客户端继续使用标准 HTTPS 或 QUIC 代理 URL，例如 `https://alice:PASSWORD@proxy.example.dev:443` 或 `quic://alice:PASSWORD@proxy.example.dev:443`；若用户名/密码有保留字符需 URL 编码。不要将真实密码放入共享日志或聊天。

```sh
moon-naive status /etc/moon-naive/config.toml
```

此命令本地检查证书，不证明服务进程在运行。进程状态看 systemd/OpenRC，连通性使用实际官方客户端与网站 GET 验证。生产示例支持 H1/H2/H3 网站，网站响应自动提供 Alt-Svc。H1 CONNECT 返回普通错误页面且不拨号；代理入口限 H2/H3。

## 升级和旧版迁移

先停止旧版 moon-naive-net 和独立 ACME 服务，保留并备份整个私有 `state_dir`、配置和凭据。替换程序与服务文件，旧 `transport.backend` 字段需删除；依次运行 check-config/check，再启动新的单一服务。证书与 ACME journal 格式保持兼容，无需重新注册已有账户或清空 CURRENT。

不要同时运行新 `serve` 和旧 ACME worker。配置/用户/上游池变更需要重启；网站文件即时生效，证书自动热更新。停止时默认排空最多 300 秒，随后清理控制面；systemd 停止时限默认 360 秒。公开 CA/DNS、目标 VPS 长期负载和网络行为仍需按实际部署验收。


---

<a id="verification-before-rc3"></a>

## RC3 重建前的验证记录（历史快照）

以下按当时状态保留，旧产物路径可能已清理；当前结果以 VERIFICATION.md 为准。

# 16条Padding协商与ECH文件热加载（2026-10-25）

Debug workspace全套125 passed、0 failed、0 ignored（core34、control13、native74、Pebble2、CLI2），包含原版Naive互通。Clippy提示测试布尔条件可简化，修正后all-targets -D warnings通过，并重新编译执行16条H2/H3互通测试通过。fmt/diff检查通过。日志reports/padding16-*。

新私有协商token moon-naive-16只在已认证普通CONNECT且非空Padding时接受；明确200确认。旧客户端保持8条，普通网站/认证失败路径不暴露协商能力。H2/H3真实测试等待确认后上传独立构造的16条记录及原始尾部，验证300KB往返、下载解码计数16。core新增碎片测试，native新增协商/未知token/重复offer测试。

ECH维护循环每5秒检测三个文件内容摘要，验证后替换TCP/QUIC共享Generation，错误保留原Generation。测试直接调用维护循环使用的refresh路径，确认坏文件保留原对象、同证书代次下内容改变会重载、无变化不重载、旧H3继续服务、新H3仍接受ECH。该测试使用密钥文件注释变化，不是实际更换HPKE密钥并执行完整客户端retry的验收；真实多实例密钥轮换和Naive ECH+16联合验收仍未完成。

路径/public_name修改仍需重启；未加入自动DNS发布或自动生成新轮换密钥。无性能/DPI测量。本轮只更新源码与本地待推送副本，未重建Release发布包、未推送GitHub；原版客户端不会自动启用16条。

---

# Padding 长度变化与 ECH 网站兼容（2026-10-25）

完整 Debug workspace 122 passed、0 failed、0 ignored；Clippy all-targets -D warnings、fmt、diff检查通过。日志 reports/echpad-*。

前八条下载数据读取预算固定为16117字节（16384-9-3-255），独立于随机padding；满读编码长度16120..16375，避免以前的互补预算消除满读长度变化。枚举256种填充长度检查该关系、H2帧头余量及分片解码。短读、八条后直通、线格式及首部策略保持不变。ECH与非ECH使用同一策略。

ECH测试扩展为真实网站请求：H2的ECH/非ECH及公开名称，正确凭据和无凭据均走固定反代且无Padding响应头；ECH H3访问主域名/公开名称；公开名称H1访问；公开名称明文跳转保留其域名和实际TLS端口，未知Host返回404；代理目标拨号计数为0。WebSocket别名复用固定源站校验，但未新增其公开名称专门互操作测试。

首轮新增跳转断言遗漏fixture的8443端口，收到正确308但断言失败，已修正为读取配置端口并重跑全套；保留reports/echpad-first-tests.log。不将其记为产品跳转失败。

没有新增配置字段或更改客户端。公开名称仍需有效证书、源站适配；自动证书/DNS/轮换及真实Naive客户端ECH闭环尚未完成。无抓包/DPI识别率或新吞吐结论。未重建Release发布包；源码和本地待推送副本同步，GitHub未推送。

---

# 多连接资源与代码整合（2026-10-25）

完整 Debug workspace 122 passed、0 failed、0 ignored（core33、control13、native72、Pebble2、CLI2），包含官方Naive、Chromium、ECH和ACME。Clippy all-targets -D warnings、fmt、diff检查通过。恢复原有停止的musl构建容器及临时命令后执行，未沿用旧二进制测试结论。日志 reports/consolidate-*。

H2/H3上传统一到TunnelDecoder，前八条后释放scratch，保持输入借用、混合边界、截断检查和背压。新增回归确认第八条后capacity=0、未填充路径不分配scratch、截断仍报错。私有TOML解析并入acme/state.rs，保留原脱敏测试，删除secrets.rs与空native/src/bin目录。

TCP在确认ALPN为H2后才取得接收窗口permit；H1和TLS半握手仍受全局连接预算和10秒TLS期限限制，但不占H2窗口。新增真实测试耗尽窗口预算后H1仍成功返回网站响应。没有增加默认额度、改变Padding/首部格式或修改客户端。未做新吞吐基准或Release构建；旧发布包不包含本轮源码，GitHub未推送。

连接数、流数、600秒空闲、客户端轮换及Caddy/forwardproxy对照见ARCHITECTURE.md的“多站点连接”部分。默认max_streams=100也是全局隧道预算；64MiB接收预算与16MiB连接预留的组合约允许4条H2/H3连接，不能把max_connections=128解释成实际可建立128个满窗口会话。

---

# 服务端对照与 H1 网站边界（2026-10-24）

完整 Debug workspace 120 passed、0 failed、0 ignored（core 33、control 13、native 70、Pebble 2、CLI 2）。Clippy all-targets -D warnings、fmt、diff 空白检查通过。本轮未编译 Release。

fastopen 加入代理元数据清理；核心测试和真实 H1/H2/H3 固定源站测试确认不泄露。H1 原始首部明确检查 Host 唯一性、HTTP/1.1 必需 Host、无 userinfo、绝对 URI/Host 一致性。新增正反请求覆盖无 Host、userinfo、不同域名/端口，以及一致绝对 URI 的正常网站路径。

首次扩展测试误以为默认端口/大小写等价的不同 authority 字节写法能通过底层 Pingora；实测返回 400，随后将本层检查、测试和文档与既有 Pingora 字节一致规则对齐。保留失败日志 reports/h1review-first-tests.log。最终日志 reports/h1review-tests.log / h1review-clippy.log / h1review-build.log。

完整差异与 H1 路由见 SERVER-COMPARISON.md。部分解析层 400 仍含 Server: Pingora，公开 ECH 名称网站路由、完整自动 ECH 生命周期及同条件流量指纹对照未完成。不把现有测试解释成抗识别测量。客户端本轮未修改。源码和本地服务端待推送副本同步，旧 Release 包未重建，GitHub 未推送。

---

# 小尾块与客户端修改基线（2026-10-24）

当前服务端前八条编码记录预算 16,375 字节，给一个 H2 DATA 帧头预留 9 字节。有效载荷读取范围 16,117..16,372 字节。八条后和未填充读取保持 16 KiB；没有改变格式或随机分布，也没有承诺 TLS/QUIC 一记录一包。

Debug workspace 全套 120 passed、0 failed、0 ignored；包含官方客户端、Chromium、ECH 及 ACME 回归。Clippy all-targets -D warnings、fmt、diff 空白检查通过。全 256 种填充长度的既有回归已补充 wire.len()+9 <=16384 断言。报告 reports/tail-*。

新客户端工作树 /workspace/moon-naive-client 基于上游 d04efe1ea4477c2db24a7d0e2f068b3bee931e45（Chromium 154.0.8037.49），原检出保留。客户端只调整已有 100..200 字节主动分片的尾块选择，保留扰动机制。局部生产头文件逻辑覆盖 1..65536 长度及全部允许抽样，g++ ASan/UBSan 通过（reports/client-padding-test.log）。尚未下载该工作树的固定 Clang/GN 工具链，未完整编译修改版客户端；官方客户端互通不等于修改版客户端互通。

本轮未重建 Release 包；旧 dist/reverse-proxy 不包含这次改动。源码及本地待推送服务端副本已同步，没有 GitHub 推送。没有包长分布、DPI 分类或吞吐提升的测量结论。

---

# ECH 实验性服务端接入（2026-10-24）

Debug workspace 全套 120 passed、0 failed、0 ignored（core 33、control 13、native 70、Pebble 2、CLI 2），包含官方客户端、Chromium 和 ACME 回归。Clippy all-targets -D warnings、fmt、git diff --check 通过。初次 Clippy 提示可折叠 if，修正后通过。

新增 ECH 测试使用生成的 X25519 密钥，验证 init/check/dns、拒绝覆盖密钥文件、H2 和 H3 的 ech_accepted、非 ECH H2、公开名称握手及未知配置 ID 握手失败。它没有覆盖真实 Naive 客户端 ECH、DNS HTTPS 自动发现、完整 authenticated retry 重连和真实多证书链部署；这些仍需补充验收。没有做公网抓包/DPI 对照。

公开名称证书、DNS 发布和密钥轮换需人工管理；公开网站别名尚未接入，默认关闭。本轮未重新生成 Release 运行包，dist/reverse-proxy 仍为此前快照。源码和本地待推送副本已更新，未推送 GitHub。日志为 reports/ech-*。

---

# Wiki 对照与上传解码优化（2026-10-24）

当前 Debug workspace 全套 119 passed、0 failed、0 ignored（core 33、control 13、native 69、Pebble 2、CLI 2），显式包含官方客户端和 Chromium 互操作。Clippy all-targets -D warnings 与格式检查通过。新增复用缓冲追加/第八条边界回归；上传初期复用缓冲，之后借用输入。未改变 wire format，未实现客户端新协议或 H1 降级检查。

记录为 reports/wiki-*；本轮只更新源码和本地待推送副本，dist/reverse-proxy 运行包仍是上轮构建，不包含本轮优化。未重新构建 Release，也没有新增指纹或吞吐测量。

---

# 当前验证：初期记录预算与副本更新

前八条下载记录的总预算为 16 KiB；每流预取八个随机长度，后续不再调用填充 RNG/编码器。H2/H3 复用同一实现，legacy 编码格式和上传解码保留。

Debug 全套 **118 passed、0 failed、0 ignored**（core 32、control 13、native 69、Pebble 2、CLI 2），包含官方 Naïve、Chromium、ACME 与安全回归。新增测试遍历所有 256 种填充长度，覆盖满块/短读/空输入/八条后原始数据及分片解码。Clippy -D warnings、fmt 与原生依赖审计通过。当前轮未出现测试失败。

报告前缀为 reports/framing-*。此前仅反代和安全记录属于各自旧快照，不作为当前随机调用或读取尺寸的说明。Cargo.lock 与 core/codec.rs、core/padding.rs 未变；没有新增运行配置字段或源码文件。仍不把本地测试解释为公网 DPI/封锁率改善；未做新方案与纯反代/Caddy 的受控抓包对照。

独立生产 Release 编译、生产 CLI 和 Alpine 3.22 / Debian 12 / Arch 静态运行检查通过。生产二进制 SHA-256 为 `cb49d60ea3c98818ccc7a964baa19e2a8163333e9dee0ac4f8bbe24c005d4d15`；功能全集运行在 Debug，并未运行本轮 Release 测试全集。交付更新覆盖 dist/reverse-proxy 的旧包；本地 moon-naive-publish 同步当前源码，保留其 Git 元数据，不代表 GitHub 远端已推送。

---

# 当前验证：仅反代网站（2026-10-24）

在前述安全加固上移除生产静态文件服务。当前 Debug workspace 全套 **117 passed、0 failed、0 ignored**：core 32、control 13、native 68（含原有微基准）、真实 Pebble 2、CLI 2。官方 Naïve v154、Chromium H3 自动发现/回退显式执行。Clippy all-targets -D warnings、fmt、vendor/原生依赖图审计通过。

报告：reports/reverse-debug-tests-final.log、reverse-debug-artifacts-final.jsonl、reverse-clippy-final.log、reverse-fmt.log、reverse-audit.log。旧 118 项安全记录对应移除文件服务之前；删除一项静态文件专用测试，其他网站/浏览器/ACME 测试改为真实本地 HTTP 源站。新增的 H1 走私/超时/复用上限、H2 reset、H3 握手回收/重放和 TLS 池隔离回归全部保留并通过。

首轮测试发现测试配置表位置变化、同步 fixture 缺少 Tokio runtime、旧纯路由测试意外继承默认 `/` 源站，均已修正。另有一次真实 Pebble DNS 故障恢复返回 RetryScheduled 而非 Installed，随后两轮相应 ACME 测试通过，未放宽断言；保留失败与复跑日志，不将此记录隐藏为从未失败。未定位该次短暂重试的根因。

独立生产 Release 构建通过；实际生产 CLI 的版本/帮助、配置、错误脱敏检查通过。Alpine 3.22、Debian 12、Arch 固定镜像的静态程序版本/配置/BBR 检查均通过（无网络、只读、无 capability）。生产二进制 SHA-256：`7cc7cd5e7a79fcd724c01cc7363036ad7c056c871bc78619bcf376b648a8ba0e`。运行包和源码包输出到 dist/reverse-proxy，各附内部和归档 SHA256SUMS。当前没有运行裁剪后的 Release 测试全集；完整功能测试为 Debug 构建。没有公网 GTS 签发、长期负载、容量型 DDoS 或 GFW 识别率验收。

静态生产字段 site_root、website.files、website.static_cache_secs 已删除，旧配置必须迁移；三个配置模板均提供反代 upstream 和 route，生产示例 `/` 指向 127.0.0.1:8080。内置文件模块和站点资源删除，直接 tower-http/tower-service 依赖及不再需要的锁文件项移除。Padding/codec 和先前性能热点实现保持逐字节不变。

---

# 安全加固验证

日期：2026-10-24。基线为 dist/performance，已有改动保留；本轮输出到 dist/security，包版本仍为 0.1.0-rc.2。下面的性能轮和旧 RC2 记录对应各自快照。

| 检查 | 本轮结果 | 本地 reports/ 记录 |
| --- | --- | --- |
| Debug workspace 编译与完整测试 | 118 passed、0 failed、0 ignored | security-debug-build.log / security-debug-tests.log |
| 安全快照 Release 编译 | 编译通过；未运行该快照 Release 测试，已被后续裁剪取代 | security-release-build.log / security-release-tests.log |
| Clippy all-targets / 五包与修改 vendor 的 fmt / diff 空白 | 通过，Clippy -D warnings | security-clippy.log / security-fmt.log |
| 原生依赖图 / vendor 摘要 | 通过；BoringSSL/quiche，锁文件不变 | security-audit.log |
| 安全快照独立生产构建与平台运行 | 被后续仅反代构建取代，见顶部当前记录 | security-production-build.log / security-production-cli.log / security-platform.log |

118 项由 core 32、control 13、native 69（含原有 3 项微基准）、真实 Pebble 2、CLI 2 组成。网络测试选择 quiche bbr2 / TCP bbr；官方 Naïve v154、Chromium H3 自动发现/回退、真实 Pebble/challtestsrv 的 ignored 测试均显式执行。此次并行编译期间的微基准只作为可运行性回归，不替代下节独立性能测量。

新增 9 项测试验证：省略监听地址默认 443；CGI 元数据别名不参与认证；H1 报文走私/超限/Connection 指定删除字段在源站前拒绝；H1/H2/H3 网站头部清理；缓慢滴入头部不会延长期限；H1 1,000 次复用上限；H2 协议错误 reset 洪泛关闭且其他客户端正常；同 H2/H3 连接重新认证与重复 QUIC 包不重复拨号；H3 未完成握手释放配额；TLS 池复用中的 SNI/CA 隔离与 SAN 优先于 CN。部分场景合并在同一测试，原 trailers 回归额外覆盖 Proxy 和下划线别名。

功能回归保留流式反代、SSE、gRPC、100/103、trailers、WebSocket、Range/压缩、目标拨号后 200、Padding、半关闭、背压、取消、证书热更新与 ACME 恢复。Cargo.lock、core Padding/codec、原子活动计时、分块 CONNECT 读取与 CA 缓存均与性能基线逐字节一致。

新增安全开销集中在网站请求头扫描与连接生命周期，未增加隧道数据的逐包检测。没有新增源码文件或目录。安全公告来源及适用范围见 REVIEW.md，未把 PHP/Node.js 的解释器漏洞说成已由 Rust 反代修复。

仍未完成：真实 Porkbun/GTS 签发、目标 VPS 长期运行、容量型 DDoS、与 Caddy 的同条件指纹/吞吐对照和公网审查识别率测量。Basic 密码失窃仍须轮换；明文 HTTP/SOCKS5 下一跳不提供 TLS。

---

# 代理性能优化验证

日期：2026-10-23。基线是下面精简阶段的 dist/review 源码，另备份于工作区 moon-naive-performance-baseline。保留旧 dist/rc2 和 dist/review；本轮快照使用 dist/performance，包版本仍为 0.1.0-rc.2。

| 检查 | 结果 | 本地 reports/ 记录 |
| --- | --- | --- |
| Debug / Release workspace 编译及完整测试 | 各 109 passed、0 failed、0 ignored（106 项回归及 3 项微基准） | performance-debug-tests.log / performance-release-tests.log |
| 官方客户端及外部互操作 | Naïve v154、Chromium H3 发现/回退、Pebble/challtestsrv 显式执行 | 包含在上述测试中 |
| 新增边界回归 | 虚拟时间空闲到期/双向进展/取消；响应分片/1xx/32 KiB 限制/二进制预读；CA 共享/失败重试/实例隔离；真实 HTTPS 的正确 IP、错误 IP 和不受信任 CA | 原有网络、背压、半关闭和认证测试同时保留 |
| Clippy all-targets / fmt / diff 空白检查 | 通过，Clippy -D warnings | performance-clippy.log / performance-fmt.log |
| 依赖图与 Pingora 摘要 | 通过；仍只启用 BoringSSL/quiche，IP SAN 修复已记入补丁说明和摘要 | performance-audit.log |
| 独立 Release 微基准 | 无并行编译，顺序运行三轮；每轮内部取中位数 | performance-benchmark-1.log 至 performance-benchmark-3.log |
| 独立生产构建 / 实际 CLI | 不含测试特性的 `cargo build --release -p moon-naive` 通过，随后实际 CLI 两项再通过 | performance-production-build.log / performance-production-cli.log |
| 三发行版基本运行 | Alpine 3.22 / Debian 12 / Arch 固定镜像，检查版本、配置、TCP BBR；无网络、只读、无 capability | performance-platform.log |

109 项由 core 30、control 13、native 62（含 3 个微基准）、真实 Pebble 2、CLI 子进程 2 组成。使用 Rust 1.89 / Alpine 3.22 构建 x86_64 musl；协议测试显式选择 quiche bbr2 / TCP bbr，保留 socket 策略读回检查。

独立生产 ELF 无 INTERP、无 NEEDED 共享库依赖；二进制 SHA-256 为 `b534a5abc27bc8248eb27a9dbbd2106ef8b6818ead187760122eaadfb7b76051`。dist/performance 中运行包和源码包各附归档摘要及内部 SHA256SUMS。三发行版检查是静态运行烟测，没有在 VPS 启动 systemd/OpenRC 服务或访问公开 CA。

## 测量方法与结果

Linux 6.18.55、AMD EPYC 9V74、3 个可见 vCPU 的当前工作区；Release 测试程序，顺序运行、无同期编译。每个微基准内保留旧实现对照，测量时使用相同环境和时钟；不是分别测量不同机器上的两个完整服务器。

| 局部操作 | 优化前：三轮中位数范围 | 优化后：三轮中位数范围 | 条件与含义 |
| --- | --- | --- | --- |
| 活动时间更新 | 93–99 ns/次 | 32–35 ns/次 | 每轮 9 批 × 200,000 次；旧 watch 保留一个观察者，新版原子时间戳。约少 65% 的更新耗时；未计入旧版被唤醒任务的调度成本 |
| 上游 CONNECT 响应头读取 | 1.296–1.362 ms | 18.709–23.796 µs | 每轮 31 次、8 KiB 响应头、回环 TCP、TCP_NODELAY；只测响应头读取，不含建连/认证/TLS 握手/公网 RTT |
| 正向 HTTPS 的 CA 获取 | 3.727–3.804 ms/请求 | 231–301 ns/请求 | 每轮 101 次、154 个系统根；旧版读取+解析，新版已初始化缓存。首次加载仍有解析成本，热缓存耗时含计时器开销 |

全部头部已就绪的计数测试中，8 KiB 头部读取由逐字节 8192 次降为 4 次块读取；真实网络分片可能增加调用数。新增预读前缀仍作为隧道原始字节交付，不丢弃、不重新编码。

在有正常 Rust/本地依赖构建环境及系统 CA 的 VPS 上复现：

```sh
cargo test --release --locked -p moon-naive-native benchmark_ -- \
  --ignored --nocapture --test-threads=1
```

这三个基准无需 Naïve/Chromium/Pebble；完整网络回归按 RELEASING.md 提供外部工具。默认 cargo test 跳过微基准；上面的全量验证显式包含它们。

## 变化与验收边界

没有增加文件/目录。Cargo.lock、core Padding/codec、H2/H3 驱动、16 KiB 目标读取缓冲、拥塞控制及 Fast Open/0-RTT 配置与基线逐字节一致。Tokio test-util 仅为开发依赖，用于可重复的虚拟时间测试。Pingora 的 IP 名称校验补丁是本轮额外修复，不宣称整个 vendor 与基线一致。

系统 CA 根更新后重启服务；网站 ACME 证书仍自动续期并热更新。HTTPS 下一跳 TLS context 构建、正向代理多 DNS 候选回退和缓存淘汰策略尚未改动。本地结果没有证明公网吞吐增幅、长期内存稳定性、GFW 识别率下降或超越 Caddy；这些仍需同条件 VPS 测量。

---

# RC2 后审查重构验证

本节对应 2026-10-23 的精简工作树，旧发布包 dist/rc2 未覆盖，包版本暂保持 0.1.0-rc.2。源码快照位于 dist/review，不能把下面旧 RC2 的二进制摘要当作当前工作树的构建摘要。

本轮覆盖根包入口迁移、文档模板合并、共享头部清理及 HTTP/1.0 / WebSocket 边界回归。第一方文件 126→100，目录 29→23；包含 vendor 为文件 573→547、目录 166→160。Cargo.lock、完整 vendor、Padding/codec 和 H2/H3 驱动逐字节不变，旧历史文档与模板均验证保留完整原文。

| 本轮检查 | 结果 | 本地报告 |
| --- | --- | --- |
| Debug / Release workspace 编译与完整测试 | 各 97 passed，0 failed，0 ignored | review-debug-tests.txt / review-release-tests.txt |
| 外部互操作 | 官方 Naïve v154、Chromium H3 发现/回退、Pebble/challtestsrv 显式执行 | 包含在上述 97 项中 |
| 头部清理回归 | HTTP/1.0 普通反代及 H1/H2/H3 WebSocket 的上游断言通过 | native::net::tests::evolution |
| Clippy all-targets / fmt / diff 空白检查 | 通过，Clippy -D warnings | review-clippy.txt / review-fmt.txt |
| 依赖图 / vendor 摘要 | 通过，无后端/锁文件变化 | review-audit.txt |
| 目录清单 / 当前文档链接 | 100 个第一方文件、23 个目录；无失效当前文档文件链接 | review-file-delta.json |

测试使用 Rust 1.89 / Alpine 3.22 构建的 x86_64 musl 程序，真实网络测试选择 quiche bbr2 / TCP bbr。此次未重新执行三发行版部署验收、独立生产构建或公网 CA 签发；下节这些结果仅对应已发布 RC2。源码快照不是新的二进制发布，完整审查见 [REVIEW.md](REVIEW.md)。

---

# 已发布 RC2 的原始验证记录

日期：2026-10-23。保留 RC1 的原始记录于 [HISTORY.md#verification-rc1](HISTORY.md#verification-rc1)。RC2 使用 Rust 1.89.0 / Alpine 3.22 / libclang 19，目标 Linux x86_64 静态 musl；Pingora 的本地协议补丁随源文件清单受 SHA-256 校验。

| 项目 | 本轮结果 | 本地 reports/ 记录 |
| --- | --- | --- |
| Debug workspace 测试 | 97 passed、0 failed、0 ignored | rc2-debug-tests.txt、rc2-debug-artifacts.jsonl |
| 独立生产构建 | `cargo build --release -p moon-naive` 通过；最终二进制再次通过 CLI 2 项与三发行版检查 | rc2-production-build.txt、rc2-platform.txt |
| Release workspace 测试 | 97 passed、0 failed、0 ignored | rc2-release-tests.txt、rc2-release-artifacts.jsonl |
| Alpine / Debian / Arch 静态运行 | 普通用户、只读、无 capability，v1/v2 配置、socket BBR 与只读 GTS directory 通过 | rc2-platform.txt、rc2-platform-v2.txt |
| workspace all-targets Clippy、五包 fmt | 通过，Clippy -D warnings | rc2-clippy.txt、rc2-fmt.txt |
| BoringSSL/quiche 依赖图、Git pins、Pingora 补丁清单 | 通过；不链接 Rustls/Quinn/OpenSSL TLS 后端 | rc2-audit.txt |
| 确定性核心模型 | 100,000 轮，511,510,083 payload 字节，结束 active permits=0 | rc2-soak.txt、model-soak 报告 |
| systemd/OpenRC | 单元验证与 sh -n 通过；未安装或启动宿主服务 | rc2-systemd-verify.txt |

97 项由 core 30、control 13、native 50、真实 Pebble 2、实际 CLI 子进程 2 组成。默认 ignored 的外部测试在本轮显式执行：未修改官方 Naïve v154.0.8037.49-4，Chromium 154.0.8037.57，以及真实 Pebble/challtestsrv。网络测试显式选择 quiche BBRv2 与 TCP bbr，并读回内核 socket 策略。容器共享宿主内核，不证明目标 VPS 一定支持 BBRv2 版 TCP。

## 新增协议与部署回归

- H1 ALPN 与无 ALPN 普通网站；认证/未认证 H1 CONNECT 均返回非成功且有正文，不发代理认证挑战，不解析/拨号 CONNECT 目标。
- 已认证 H2/H3 普通 HTTP POST、流式请求体、凭据剥离与无认证隔离；可选 HTTP/HTTPS/SOCKS5 下一跳握手、认证、IPv6、TLS CA/名称校验、握手后预读字节保留。下一跳尚未返回结果时不发 CONNECT 200，407 失败后不回退直连。
- 固定网站 H1 Upgrade 与 H2/H3 扩展 WebSocket 到 H1 Upgrade，预读数据和半关闭保留；已升级流量不误用普通 HTTP 请求体累计限制；不是任意目标扩展隧道。
- H1/H2/H3 到 H1 上游的双向 trailers（含分段字段）、103 与非法 trailer 剥离；HTTPS H2 上游的 100-continue 等待、103、gRPC 帧和 grpc-status trailers、不额外 gzip、连接复用和取消。
- 规范域名 HTTP 308 跳转保留 path/query，未知 Host/代理请求不跳转；网站生成 Alt-Svc、覆盖上游宣告。
- schema v1→v2 配置合并、0600 权限、无覆盖原子输出、不修改账户/证书状态、秘密 Debug/错误脱敏。

原有认证、前八条 legacy Padding、半关闭、背压、reset、资源回收、热换证和 ACME 恢复测试保留。core/padding.rs 与 core/codec.rs 和本轮开始前快照逐字节一致。

## Chromium 验证的信任边界

测试用临时 CA/叶证书和独立浏览器 profile，以叶 SPKI 限定本地证书例外。Chromium 对 QUIC 另要求公开根：测试通过 `--origin-to-force-quic-on=proxy.example.test:1` 为该测试主机放行未知根，**端口 1 不监听、不访问**。被测 origin 使用随机实际端口，不在强制 QUIC origin 列表中。断言初始导航为 H2，随后请求确实出现 H3；无 UDP 监听的独立场景全部使用 H2。没有更改系统信任库或生产服务器校验，也没有把强制实际 origin 使用 QUIC 冒充 Alt-Svc 自动发现。

这是本地协议发现/回退证据，不是公开 GTS 证书的浏览器验收。实际部署要使用受信任 production 链和可达 UDP 端口。初期测试的失败已定位为 Chromium 的未知根策略；当前回归包含上述显式测试信任设置。

## 发布文件校验

运行包由 `xtask dist` 强制检查 musl ELF 无 INTERP、无 NEEDED 共享库依赖，并记录二进制、Cargo.lock 和 Pingora 清单摘要到 BUILD-INFO.json。源码包完整包含本地 Pingora 补丁及上游公开测试证书夹具，不包含构建缓存和运行凭据。两个包分别提供归档 SHA-256 与内部逐文件 SHA256SUMS。

最终生产二进制 SHA-256：`0d497628c2a47cba33635e0e91bb1faf450fe74f010ab70dcee9945daa5e791a`。

## 仍待部署环境验证

未执行真实 Porkbun/GTS staging/production 签发、目标 VPS systemd/OpenRC 开机/升级演练、24 小时公网负载或与 Caddy 的同条件抓包/识别率差分。代码提供这些部署路径，但本地通过不代表公网全部验收。没有可量化的“比 Go/Caddy 更难识别”结论，详见 [ACCEPTANCE.md](ACCEPTANCE.md) 与 [FINGERPRINTS.md](FINGERPRINTS.md)。


---

## RC3 发布验证

# 0.1.0-rc.3 发布验证（2026-10-25）

本次从当前工作树重建 Linux x86_64 静态 musl 候选版，包含明确协商的十六条 Padding 扩展、ECH 文件热加载和此前反代、安全及连接管理修改。发布资产位于 `dist/release/`；本轮不提交、推送或创建 GitHub Release。

| 检查 | 结果与范围 |
| --- | --- |
| 生产 Release 构建 | Rust 1.89 / Alpine musl，`cargo build --release --offline --locked --target x86_64-unknown-linux-musl -p moon-naive` 通过 |
| Release workspace 测试 | **125 passed，0 failed，0 ignored**；core 34、control 13、native 74、Pebble 2、CLI 2；显式启用外部测试 |
| 网络互通 | 官方 Naïve v154.0.8037.49-4、真实 Chromium、H2/H3、反代/升级协议、认证与 ACL、Padding、ECH 及 Pebble/EAB 回归通过 |
| 静态检查 | workspace all-targets Clippy `-D warnings`、第一方 fmt、Git diff 空白检查通过 |
| 依赖审计 | 固定来源、Pingora vendor 完整哈希清单、BoringSSL/quiche 依赖图审计通过 |
| 发行版运行 | 同一二进制在固定 digest 的 Alpine 3.22、Debian 12、Arch 容器中通过版本、配置及 TCP BBR 检查；普通用户、只读文件系统、无网络运行 |
| CLI / 服务文件 | 三份示例的结构检查通过；生产示例用临时 0600 副本接受条款后检查，随包仍为 `accept_terms=false`。OpenRC shell 语法通过；systemd 校验使用仅替换 ExecStart 为本地构建路径的临时副本，未启动服务 |
| 静态链接 / 包 | `xtask dist` 强制拒绝 ELF INTERP/NEEDED；运行包含部署文件、配置、文档、许可证、依赖清单、BUILD-INFO 和 SHA256SUMS；源码包保留固定 Pingora 补丁 |

本轮全套使用 Release 测试程序；此前同功能 Debug 全套 125 项通过，历史原始记录已移入源码包的 `docs/HISTORY.md#verification-before-rc3`。本地详细日志在 `reports/rc3/`，不随发布包分发；历史测试日志合并保存在 `reports/history.tar.gz`。

生产二进制 SHA-256：

```text
91292f71156bb60747787890887e7477459d07b0ca69e76b337a871ceea6bbf4
```

归档自身的哈希以各 `.tar.gz.sha256` 为准；解压后再执行 `sha256sum -c SHA256SUMS`。构建信息中的二进制和 Cargo.lock 哈希用于核对对应关系。

## 兼容性与尚未验收范围

- 官方客户端仍走八条 legacy Padding；十六条需要支持 `moon-naive-16` 且等待服务端成功确认的客户端。该扩展已做独立 H2/H3 回归，但修改版 Chromium 客户端尚未完成整体构建及联合验收。
- ECH 默认关闭。公开名称证书、DNS HTTPS 记录和密钥轮换仍需人工管理；服务端每五秒验证并热加载现有文件，错误保留旧 generation。热加载回归用文件内容变化触发，并非实际 HPKE 密钥轮换、完整 retry 或多实例验收。
- 未执行真实 Porkbun/GTS 公网写入、目标 VPS systemd/OpenRC 开机与恢复演练、24 小时稳定性测试或新的性能/DPI 对照。发行版容器共享宿主内核，不能替代 VPS 的 BBR 支持验证；TCP 使用内核 BBR，不能等同于 quiche BBRv2。
- 旧发布包和阶段性源码副本在新包校验后清理。当前源码、Git 元数据、独立客户端工作树及必要构建/互通依赖保留；不把缓存或真实凭据装入发布包。


---

## 历史工作记录（原 WORK.md）

> 以下是历史工作记录，旧包路径与“保留旧包”的描述仅代表当时状态。当前发布与清理结果见 [VERIFICATION.md](VERIFICATION.md)。

# RC2 后审查与精简

根包承接 daemon 入口、CLI 测试迁移到根 tests；21 份历史文档与旧安装说明合并，私有凭据/网站模板集中到配置说明，部署入口统一。代理秘密头与转发身份头规则共享，补齐 WebSocket X-Forwarded-Port 清理及 H1/H2/H3 上游断言。原版比较固定作者提交及其发布 workflow，不混淆 go.mod 与实际 Caddy 版本。详细发现和统计见 REVIEW.md，测试证据见 VERIFICATION.md。旧 dist/rc2 保留，本轮源码另存。

# 2026-10-23 RC2 协议与配置整合

保留已有工作树，完成单份 schema v2 私有 TOML 与迁移、H1 网站及有正文的 CONNECT 拒绝、HTTP 308 与 Alt-Svc、H2/H3 通用正向请求、单个 HTTP/HTTPS/SOCKS5 下一跳、固定网站 WebSocket、100/103、双向 trailers 与 gRPC 传输回归。CONNECT 先完成最终目标连接再成功，所有 Fast Open/0-RTT 继续禁用，原有 Padding/codec 不改。

Pingora 从固定 Git 基线转为受校验的随包补丁快照，补齐上述协议接口；Cargo 实际后端仍只有 BoringSSL/quiche。配置、VPS 构建、系统服务、架构、与作者插件/Caddy 对比和逐文件说明同步到 RC2。当前验证结果和未完成的公网验收见 VERIFICATION.md；RC1 原始验证记录另存 HISTORY.md#verification-rc1。

以下为上一阶段原始工作记录，其完成状态仅对应当时版本。

# 2026-10-22 发布整合

本轮目标：说明 BoringSSL/Go 指纹差异，并整合为面向 Alpine、Debian、Arch x86_64 的可发布服务端。之前的实现和测试证据已保留在 HISTORY.md，不重置既有工作树。

已完成代码：单一 Cargo workspace/lockfile、固定 Git 上游、唯一 moon-naive CLI、独立 ACME runtime/线程、首次证书门禁、自动续期与关闭清理、systemd READY 通知、OpenRC/systemd 配置、跨发行版 CA 定位、Rust musl host-build wrapper、Rust xtask 审计/测试运行/发布打包。

已完成验证：静态目标全目标编译和 clippy；Debug/Release 各 85 项测试，包含实际官方 H2/H3、真实 Pebble/EAB 自动首次签发后监听和 SIGTERM 退出；100,000 轮核心确定性模型；Alpine/Debian/Arch 普通用户运行、BBR 与只读 GTS directory；systemd 单元验证和 OpenRC 语法检查。静态二进制、源码、配置、服务文件、许可证与校验和由 Rust xtask 归档，最终结果见 VERIFICATION.md。

未执行公网 DNS/CA 写入、目标 VPS 部署或外部发布；没有修改固定上游。原有 Naïve Padding、目标读取块和 RNG 路径保持不变。指纹分析明确没有性能/抗识别优势的实测结论。


# RC4 验证归档（Moon/2重构前）
# 0.1.0-rc.4 重构与发布验证（2026-10-26）

RC4 在保留当前服务能力的基础上重构隧道缓冲区、压缩编译特性和发布工具。本轮不提交、推送或创建 GitHub Release。当前发布资产在 `dist/rc4/`，RC3 归档保留为对照与回滚基线。

| 检查 | 实际结果 |
| --- | --- |
| Debug workspace | **129 passed、0 failed、0 ignored** |
| Release workspace | **129 passed、0 failed、0 ignored** |
| 测试组成 | core 34、control 13、native 76、CLI 2、Pebble 2、xtask 2；显式启用官方客户端、Chromium 和 ACME 集成测试 |
| Rust 检查 | workspace all-targets 编译、Clippy `-D warnings`、第一方 fmt 与 Git diff 空白检查通过 |
| 生产构建 | Rust 1.89 / musl，`cargo build --release --offline --locked --target x86_64-unknown-linux-musl -p moon-naive` 通过；最终生产文件另存 `target/rc4/moon-naive`，避免被带测试 features 的构建产物替换 |
| 发行版运行 | 同一生产二进制通过固定 digest 的 Alpine 3.22、Debian 12、Arch 容器版本、配置与 TCP BBR 检查；只读文件系统、普通用户、无网络运行 |
| 依赖与发布工具 | 固定依赖及 vendor 哈希审计通过；Rust tar/flate2 归档确定性、目录与程序权限，以及 goblin ELF 检查测试通过 |
| 配置 | 示例结构与传输检查通过；生产示例使用临时 0600 副本接受条款后检查，随包仍保留 `accept_terms=false` |

最终 Debug/Release 全套均在代码收敛后执行。随后执行环境重启，`/tmp` 中的详细编译与测试 stdout 未保留；`reports/rc4/` 保存持久的 xtask 成功摘要、发行版逐项结果、恢复说明与后续打包核验。恢复后生产二进制 SHA-256 完全一致，重新检查 fmt、diff 和依赖审计。没有把编译成功或旧 RC3 测试当作 RC4 测试结果。

## 重构的可确认变化

- H2/H3 下载共用 `TunnelDownload`：直接读入 BytesMut，原地补帧头和 Padding，再冻结为 Bytes 移交。测试确认读取地址就是输出 payload 地址、保留中的数据不会被后续读取改写、取消空读不消耗 Padding 计数。H3 空读复用驱动级接收缓冲。
- 八条 legacy / 明确协商十六条、初期 16,117 字节有效载荷上限、均匀随机长度、短读立即发送、背压和半关闭保持原有规则。不是内核零拷贝，也不保证 HTTP/TLS/QUIC 边界一一对应。
- gzip 改为 Rust miniz_oxide；本地未使用的 Brotli/Zstandard 编码器和缓存头部压缩不进入运行依赖图。源站已编码响应继续透传。Pingora 缓存 API 保留，但本服务不启用对象缓存；未编译序列化后端时明确报错，不另造持久格式。
- 压缩协商处理 q 权重、零/非法权重和 identity 偏好，并在本地编码器不可用时选择可用编码器。H3 回归覆盖浏览器式多编码 offer、gzip;q=0、identity 及有效正文解码。
- 通用本地错误模板不再注入 Server: Pingora；H1 畸形报文回归确认此行为。源站 Server 字段不被伪造为其他服务。
- 发布归档、gzip 和 ELF 检查不再调用 tar/gzip/readelf 子进程。构建与依赖获取仍需 Cargo/Git，发行版安装仍使用系统服务管理器。

静态生产二进制：RC3 **18,308,800** 字节 → RC4 **16,383,520** 字节，减少 **10.52%**。运行/构建选中依赖移除了 alloc-no-stdlib、alloc-stdlib、brotli、brotli-decompressor、jobserver、libz-ng-sys、pkg-config、zstd、zstd-safe、zstd-sys 这十个包名；新增的 Rust 压缩及辅助依赖见随包清单。体积变化不是吞吐或识别率变化的证据。

生产二进制 SHA-256：

```text
69ea42fbb65884fca1f3aef2b46b00914b798ca42315d419479b245332418bad
```

各归档自身的哈希见对应 `.sha256`，解压后用 `sha256sum -c SHA256SUMS` 验证文件。BUILD-INFO.json 记录二进制、Cargo.lock 与 vendor 清单哈希。源码归档包含当前修改，不包含 Git 元数据、构建缓存、真实凭据或运行状态。

## 尚未验收与取舍

- 原版客户端继续使用八条；十六条扩展需要明确协商。修改版 Chromium 客户端整体构建及 ECH+十六条联合验收未完成。
- ECH 默认关闭；公开证书、DNS HTTPS 记录及密钥轮换仍需人工管理。五秒文件热加载不是自动 DNS 发布或完整密钥轮换生命周期。
- 未执行新的端到端吞吐、延迟、RSS、丢包/MTU 或 DPI 对照。Rust gzip 的 CPU、压缩率及输出字节可能与 zlib-ng 不同；需要用实际源站和负载测量。
- 公网 Porkbun/GTS 签发、目标 VPS 服务恢复演练及 24 小时稳定性仍未验收。发行版容器共享宿主内核，不能代替目标 VPS 的 BBR 检查；TCP BBR 由内核决定，不能等同于 quiche BBRv2。

组件选择与不采用第二套网络栈的原因见 [ARCHITECTURE.md](ARCHITECTURE.md#rc4-rust-网络栈与边界)，配置迁移见 [CONFIGURATION.md](CONFIGURATION.md)。


# 0.2.0-dev.1 协议与验证归档（已被有限填充修订取代）

# 上游弱点、Moon/2 协议与客户端构建基线

更新：2026-10-27。当前服务端为 **0.2.0-dev.1**，只实现 Moon/2，明确不兼容官方 Naïve 客户端或旧 moon-naive-16 客户端。RC4 包仍保留用于回退；不能直接用旧客户端验证新代理成功。网站、自动证书和服务启动配置继续使用现有 TOML schema v2；配置 schema 与隧道协议版本是不同概念。

## 已知问题的证据与边界

客户端基线是官方最新稳定标签 `v154.0.8037.49-5`，提交 `d04efe1ea4477c2db24a7d0e2f068b3bee931e45`，Chromium `154.0.8037.49`。服务端对照已从作者 forwardproxy `c096d6a00cb28e019cc1995b04bdc6a9311d8024` 补查至最新标签 `v2.11.7-naive2`（`e747854e78743dba85c039b38ed185fb11d93667`）；原研究工作树保持不变。不能由此宣称审查了所有 Caddy、Go 或插件版本。

| 对象 | 已确认或由源码直接得出的限制 | 本轮处理／仍有限制 |
| --- | --- | --- |
| 客户端证书信任 | 2026-10-22 官方发布说明明确：旧版无法安全抵御使用伪造 eMudhra 证书的 MitM。修复提交 `23953c90e3b9f08f8d0c6ede92ae35f357af6f73` 给 `cert_verify_proc_blocklist.inc` 增加 8 个被阻止的 SPKI | 新拉取源码含修复。不能说最新版仍有这个已修复问题；系统根更新也不能替代客户端 blocklist／撤销策略更新 |
| 双端 Padding | 官方每方向只填前 8 条应用记录，u16 数据长度 + u8 填充长度，0..255 填充；之后裸流。不能掩盖全部长度、突发、方向、长连接和关联特征 | Moon/2 全程有界记录，前16条扩大填充预算，之后仍填充；没有证明 DPI 识别率下降 |
| 客户端 H2 关闭行为 | 官方 README 记录：额外 48..72 字节 END_STREAM DATA 用于掩饰 RST_STREAM，可能引发 WINDOW_UPDATE，新特征是否产生仍不确定 | 服务端不人工制造这类小尾帧。新客户端需要重写关闭策略并实测，不应机械复制旧补丁 |
| 客户端 H1 回退 | H1 隧道缺少 H2/H3 的跨流复用，容易保留目标连接建立和 TLS-in-TLS 的时序结构。这是协议限制，不是 TLS 加密被破解 | 服务器 H1 只服务网站；新客户端只允许 H3→H2 回退，不得回退 H1 代理或直连 |
| 客户端网络栈维护 | 复用 Chromium 不等于完整浏览器行为；需要及时更新 TLS、QUIC、证书策略、HPACK/QPACK 和会话调度。官方已加入真实网站前导请求及旧隧道清理改进 | 保留 Chromium 构建基线及前导机制作为参考。重写全部为普通 Rust TLS 客户端会丢失这一优势 |
| 原服务端认证 | Basic 依赖外层 TLS 保密；一旦在终止端、错误日志或受信 MitM 处泄露，凭据可跨连接使用。正常 TLS 密文重放会被 TLS 拒绝，不能混为一谈 | Moon/2 用 TLS exporter + 流 ID + 请求语义的 HMAC；逐流验证，成功响应也有独立证明 |
| 原服务端隧道空闲 | `v2.11.7-naive2` 修复认证 H2/H3 CONNECT 被 Caddy `read_body_idle` 提前终止的问题：逐请求将读取空闲覆盖为24小时，硬性期限仍有效 | 本项目已有任一方向实际进展刷新、默认600秒的隧道空闲期限；不引入 Caddy 专用覆盖接口。最新版已修复，不能仍称其存在相同问题 |
| 原服务端主动探测 | `probe_resistance`、`hide_ip`、`hide_via` 和真实站点配置影响行为；错误配置、额外管理端口、暴露登录页或凭据泄露仍可能暴露代理 | 保留统一固定反代、H1 严格解析、无 407、无公开版本探测；畸形协议仍会产生正常协议错误，不能保证各服务器错误指纹相同 |
| 服务端／客户端资源 | H2 复用共享 TCP 队头阻塞；H3 对 UDP 可达性和 CPU 敏感；流额度、窗口、连接/握手/拨号期限仍需限制 | 复用既有预算、取消、背压、半关闭、H2 reset 限额、QUIC Retry 和握手回收；不是所有实现都已通过 DoS 压测 |
| 双端 SNI/ECH | 普通 TLS/QUIC Initial 不隐藏入口 SNI；ECH 隐藏 ClientHelloInner，不隐藏 IP、外层公开名称、长度、时序，也不修复错误信任链 | 保留默认关闭的实验性 ECH；不按 ECH 是否接受切换 Padding；DNS 发布、公开证书和轮换仍需管理 |
| 服务端对外 HTTPS | 网站反代、HTTPS 下一跳、ACME 使用其实际 TLS 验证路径；BoringSSL 加载系统 CA 不自动拥有 Chrome 的全部吊销、CT 或 blocklist 机制 | 未把客户端的 eMudhra 修复误称为服务端全面吊销防护。固定上游可配置独立 CA；生产仍需信任策略维护与审计 |

来源：[官方协议说明](https://github.com/klzgrad/naiveproxy/blob/v154.0.8037.49-5/README.md)、[中文 Wiki](https://github.com/klzgrad/naiveproxy/wiki/简体中文)、[客户端安全修复发布说明](https://github.com/klzgrad/naiveproxy/releases/tag/v154.0.8037.49-5)、[证书修复提交](https://github.com/klzgrad/naiveproxy/commit/23953c90e3b9f08f8d0c6ede92ae35f357af6f73)、[服务端空闲修复发布说明](https://github.com/klzgrad/forwardproxy/releases/tag/v2.11.7-naive2)、[原服务端源码](https://github.com/klzgrad/forwardproxy/tree/e747854e78743dba85c039b38ed185fb11d93667)。旧 Wiki 示例和平台依赖有过时内容，以固定版本源码/构建 workflow 为准。这里不把推测写成 CVE，也没有发现或证明最新版存在未修复远程执行漏洞。

## 认证：不发送可复用 Basic 密码

只在完成 **TLS 1.3** 握手的 H2/H3 上允许代理。H1、无 ALPN 和 TLS1.2 H2 仍可访问网站，不能启用代理。没有 TLS 0-RTT、TCP Fast Open 或代理 Fast Open。

1. 取得实际连接的标准 TLS exporter：label 为 ASCII `EXPORTER-moon-naive-v2`，context 为显式空字节串，输出 32 字节。必须是正常握手 exporter，禁止 early exporter。重连/会话恢复后重新取得；ECH 接受与否不改变算法。
2. 从实际 H2/H3 分配的流 ID 取得 `stream_id`，编码为 8 字节无符号大端整数。H2 首个请求通常是 1，H3 首个请求通常是 0；前导网页同样消耗请求流编号，不能按 CONNECT 次数猜测。
3. `key = SHA256(b"moon-naive/v2/key\0" || UTF8(username) || b":" || UTF8(password))`。用户名不能包含冒号。用户名/密码要求与 TOML 一致；请使用随机 32 字符以上秘密。此派生不是口令拉伸，不防低熵密码的离线猜测。
4. `message = b"moon-naive/v2/request\0" || exporter || u64be(stream_id) || fields`。
5. fields 固定依次为 method、authority、scheme、path-and-query、protocol。存在的字段编码为 `u64be(UTF8字节数) || UTF8字节`，缺失字段为 8 个 `0xff`；空值与缺失不同。使用线上实际值，不额外改大小写、端口、百分号编码或查询顺序。普通 CONNECT 的后三项必须缺失。
6. `mac = HMAC-SHA256(key, SHA256(message))`；发送唯一一个 `Proxy-Authorization: Moon2 <标准带=的Base64(mac)>`。值长度 50 字节。scheme 大小写不敏感，重复首部、别名、错误长度、Basic、错误证明都不认证。客户端必须禁止 HPACK/QPACK 动态索引该字段。

服务端先对请求上下文做一次SHA256，再以恒定时间比较每个配置用户的HMAC证明，避免256用户把超长请求上下文的哈希工作放大256倍；无连接级“已登录”标志。没有时间戳、全局 nonce 缓存、重放窗口或相应时钟依赖。跨连接 exporter 改变，跨流 ID 改变，目标/方法改变也改变 MAC。HTTP 状态机不得重新接受同一流的第二个请求头；网站 trailers 不能再认证。服务端重启后新 TLS 连接同样产生新 exporter。普通 TLS 记录或 QUIC 包的网络重放仍由底层协议处理。

成功 CONNECT 在完成目标拨号后返回 200、独立生成的随机 `Padding` 响应头，以及唯一一个：

```text
Proxy-Authentication-Info: Moon2 <Base64(server_mac)>
```

server_mac 使用同一算法与字段，仅将 domain 改为 `b"moon-naive/v2/response/200\0"`。新客户端必须验证状态、唯一性和证明后才发送代理数据，拒绝缺失/错误证明，不能退回旧协议。请求 MAC 不能反射为响应 MAC。Padding值为64..127个均匀随机URL安全字符，每流用BoringSSL CSPRNG生成，已取消原插件的30..61字符、符号前缀和波浪线尾部。它只影响响应首部长度，不参与能力协商，也不代表已拟合网页分布。H2 响应这两个动态字段均标记 never-index；当前固定 quiche 的 QPACK encoder 使用静态引用/字面量，不动态插入。

认证证明是标准密码原语的一次新协议组合，尚未经外部审计。不能关闭正常证书链、名称、用途和吊销验证；建议新客户端提供预置 SPKI pin 与可轮换备份 pin。TLS 终止的 CDN/反代会改变 exporter，不能把本协议直接藏在另一个终止 TLS 的代理后面。L4 透传仍可用。通用 HTTP 正向请求同样逐请求认证，正文保持 HTTP 语义；上述成功响应证明仅定义于 CONNECT。

### 独立互操作向量

以下为公开测试凭据，不用于部署。username=`user`，password=`a-long-test-secret-123`，exporter为32个`07`字节，stream_id=1，method=`CONNECT`，authority=`example.org:443`，scheme/path/protocol均缺失。Python hashlib/hmac独立计算结果：

```text
request: Moon2 qAdcDC83SyA19CS+esufugEw6Ru5dKXYpAo46je6BoA=
response: Moon2 IxtsmM/fpCvZCEvwbfOiZW0NTDvxlfWE79geIKR2KSE=
```

## 全程 Padding 记录

每个方向独立；全程没有切换裸流，也没有可协商的旧格式：

```text
u16be payload_length | u16be padding_length | payload | padding
```

约束：payload_length ≥ 1，padding_length ≤ 2047，整条记录 ≤ 16375 字节。服务端输出的 padding 内容为零，接收方忽略内容；保密与完整性由 TLS/QUIC 提供。拒绝 padding-only、过长、畸形和被截断记录；解析失败后状态不可恢复。正常空流可直接 HTTP END_STREAM，无需发送零长度记录。没有额外结束标记或填充尾记录。

服务端下载策略：前16条 padding 均匀取 0..2047，读取有效数据最多 **14324** 字节；之后仍有 4 字节帧头和 0..255 padding，读取最多 **16116** 字节。读取上限不随该条随机长度反向变动，避免抵消扰动。CSPRNG 每批取 64 字节，每条消费两个字节，短读立即编码；空读/取消不消耗计数或熵。不新增等待凑块、假流量、定时抖动或空闲保活。

解码器只限制格式上界，不要求对端采用完全相同的长度分布。初期预算变大并没有证明最佳流量分布；第16条后的预算变化也仍是需实测的设计选择。首16条每方向平均新增约16KiB填充，长连接满读平均约0.82%编码开销，小包交互的比例可能高很多。需要真实客户端抓包和吞吐/延迟测量后再决定调参；ECH并不会消除这项代价。

`BytesMut` 直接承接读取、原地写头和尾部，冻结为 `Bytes` 交给流控/队列；部分发送不重新编码、不重新抽随机数。上传使用有限 scratch，解码跨任意 HTTP DATA 边界；全程 framing 因而不再有 RC4 的“第8/16条后释放 scratch”路径。这不是内核零拷贝。H2帧、TLS记录、QUIC包仍可能拆分/合并记录，16375预算不等于抓包中单包长度。

## 路由与兼容性

| 请求 | 路由 |
| --- | --- |
| H1 的任意凭据、普通网页、CONNECT、absolute-form | 既有严格网站规则/固定反代；CONNECT或非法目标为普通网站错误；零任意目标代理拨号 |
| H2 TLS1.2 | 网站；无法生成有效 Moon/2 认证上下文 |
| H2 TLS1.3 / H3，无凭据、Basic、错误/重放证明 | 共同网站路径，移除代理元数据；不返回407、不宣告协议版本，不为代理解析DNS/拨号 |
| H2/H3，有效普通 CONNECT | 检查配额、目标ACL及拨号；成功200与响应证明；全程记录；失败不提前200 |
| H2/H3，有效通用 HTTP 请求且非网站域名 | 按用户+origin隔离的正向池，沿用出站ACL及HTTP(S)/SOCKS5下一跳 |
| H1 Upgrade / H2/H3 扩展 CONNECT WebSocket | 只到管理员配置的固定网站路由，无任意目标权限；保持原始WebSocket字节，不套Moon/2记录 |
| 语法攻击、超限头、流重置洪泛、握手拖延 | 既有解析错误、reset、限额和关闭策略；不是所有攻击都会返回同一页面 |

不会增加外层浏览器请求头、伪造 User-Agent 或更改客户端 ClientHello。服务端无法替未来客户端实现 Chromium 请求顺序、前导站点选择、RST_STREAM关闭和会话调度。新客户端完成前，本版本不能供旧 Naïve 客户端日常代理使用。

## 已拉取的客户端构建项目

本地独立目录：`/workspace/naiveproxy-client-upstream`。固定标签 `v154.0.8037.49-5`，无工作树修改；原 `/workspace/moon-naive-client` 的既有实验修改保留。它是官方精简 Chromium 源码项目，不是只包含预编译二进制，也不是从头下载完整 Chrome 浏览器。

| 目录/文件 | 用途 |
| --- | --- |
| CHROMIUM_VERSION、.github/workflows/build.yml | 固定Chromium版本及官方跨平台构建步骤 |
| src/get-clang.sh、src/get-sysroot.sh、src/build.sh | 下载版本匹配工具链/所需构建资源，GN生成并Ninja构建naive |
| src/net/tools/naive/ | SOCKS/HTTP本地入口、配置、转发、旧Padding、代理delegate、前导网页请求 |
| src/net/http/、src/net/spdy/、src/net/quic/ | HTTP CONNECT、H2会话、H3会话与连接复用 |
| src/net/socket/、src/net/ssl/、src/net/cert/ | TLS socket、exporter/验证、证书策略与已修复blocklist |
| src/net/third_party/quiche/、src/third_party/boringssl/ | Chromium QUICHE与BoringSSL；前者是C++实现，不是服务端Cloudflare Rust quiche |
| src/base/、src/build/、src/buildtools/、src/BUILD.gn | Chromium基础运行库和GN构建配置 |
| tests/、tools/、apk/ | 官方测试、开发工具和Android打包 |

在适合官方Linux构建流程的Debian/Ubuntu构建机上，基础命令如下；版本特定包安装及sysroot步骤以固定workflow为准：

```sh
sudo apt update
sudo apt install git curl xz-utils python3 build-essential ninja-build pkg-config ccache cmake
cd /workspace/naiveproxy-client-upstream/src
export EXTRA_FLAGS='target_cpu="x64"'
./get-clang.sh
./build.sh
../tests/basic.sh out/Release/naive
```

这些命令构建的是原版客户端，**不能连接Moon/2代理**。构建脚本还会下载LLVM/GN/PGO/sysroot等资源，拉取源码不代表这些资源已下载，也不代表新客户端已编译完成。建议预留足够磁盘及内存，不把服务器Cargo工具链误用为客户端Chromium构建工具链。

改造顺序：保留Chromium外层TLS/H2/H3与证书策略；在实际分配CONNECT流ID之后、发送HEADERS之前获取exporter并计算证明；确认200响应证明；替换NaivePaddingSocket/Framer为全程记录；禁用代理H1回退、Fast Open和0-RTT；保持受控前导网页和会话复用；最后执行双端ECH/恢复/丢包/抓包对照。HPACK/QPACK须never-index认证值。若转为Rust，优先让Rust承载控制/配置或编解码，通过清晰接口继续使用Chromium外层网络栈；单独采用BoringSSL并不能复现Chromium全部网络行为。

## Caddy相关清理清单（本轮继续）

运行依赖审计未找到Caddy、xcaddy、CertMagic、Go运行时、Go插件装载器或Caddyfile适配器。不能把不存在的组件列为“刚刚删除”。本轮删除的是遗留协议兼容与配置负担；它们原来借鉴作者forwardproxy，不是动态链接Caddy。

| 项目 | 实际处理 | 影响 |
| --- | --- | --- |
| Caddy/forwardproxy式Basic代理认证 | 删除旧解析/路由入口，改为Moon/2连接和流绑定HMAC | 官方客户端不能直接使用；HTTPS下一跳的标准Basic仍保留，与客户端入口认证不同 |
| 无Padding、前8条、协商前16条、随后裸流 | 删除这些运行分支和padding-type协商函数 | 所有认证CONNECT统一持续framing，无降级开关 |
| 旧响应Padding生成模块 | 删除 `crates/core/src/padding.rs` 和模块导出 | 不再复制作者插件30..61字符、符号+波浪线模式 |
| 当前响应首部扰动 | 在现有Reply构造中生成独立的64..127随机字符，保留HPACK never-index | 不新增文件、不参与旧客户端协商，不宣称仅此就更难识别 |
| `listener.fast_open` / `listener.zero_rtt` | 删除结构字段、运行配置判断及三个示例中的无效开关 | 实现仍禁用；运行配置严格拒绝这些旧字段 |
| 一次性配置迁移 | `moon-naive config migrate old.toml new.toml` 清除旧false字段，true或非布尔值拒绝 | 原配置和ACME状态不覆盖，新文件0600；保留已有秘密合并功能 |
| 旧插件敏感首部名 | 仅保留在统一清理列表，包括FastOpen、padding-type-* | 清理规则不是功能支持，删除它反而可能向网站泄露探测/代理元数据 |
| Caddyfile / xcaddy / CertMagic / Go插件 / 管理API | 当前源码与Cargo图中不存在，不作虚假删除统计 | Cargo构建无需Go或xcaddy；不会监听Caddy管理端口 |
| 静态文件、目录列表、模板、PHP/FastCGI、动态网站插件、按需证书 | 当前服务端没有这些能力，本轮没有新增 | 网站只反代到管理员固定源站；源站若运行PHP/Node仍须自身更新 |
| Pingora反代、路由、gzip、WebSocket、SSE/gRPC、trailers、HTTP跳转、Alt-Svc | 保留 | 都是你要求的网站能力/标准HTTP机制，不依赖Caddy |
| ACME/GTS/Porkbun/EAB、持久恢复、systemd/OpenRC | 保留Rust实现和标准服务配置 | 删除会破坏你要求的一配置启动和自动证书流程 |
| Caddy对照说明与外部研究源码 | 保留为证据和参考，不进入运行依赖或服务端发布包 | 不通过删除对照资料制造代码精简效果；新拉取的官方客户端保持原样 |

与RC4源码逐项对照的函数/字段变化：

| 位置 | 删除或替换的接口 |
| --- | --- |
| `crates/core/src/auth.rs` | 删除`Credentials::matches`、旧`Route`及`route`；`principal`增加可信传输上下文，取消Basic解码认证 |
| `crates/core/src/codec.rs` | 删除`FIRST=8`、两个`with_record_limit`及裸流切换；`feed`/`feed_into`返回错误，畸形记录不可继续解析 |
| `crates/core/src/padding.rs` | 整个文件及`response_header([u8;17])`删除，`lib.rs`不再导出该模块 |
| `crates/core/src/ingress.rs` | 删除`TunnelRequest::padded`及其字段；认证隧道不再以请求Padding头决定是否编码 |
| `native/src/net/mod.rs` | 删除`negotiated_padding_records`；`Reply::tunnel`直接生成新的响应扰动值，成功响应附加绑定证明 |
| `native/src/net/tunnel.rs` | 取消0/8/16记录模式和达到阈值后释放scratch/裸流分支；原始字节模式仅用于固定网站WebSocket |
| `crates/core/src/config.rs`、三个示例 | 删除`Listener.fast_open`和`Listener.zero_rtt`；`cli.rs`仅在一次性迁移时识别旧false字段 |
| `xtask/src/main.rs` | 更新旧字段拒绝检查，直接注入被废弃字段，避免示例删字段后字符串替换无效 |

运行依赖图仍保留一套BoringSSL/Tokio/Pingora/quiche组合。删除上述入口兼容不等于删除`outbound.rs`中的标准下一跳Basic认证，也不删除测试中的旧格式拒绝样例。两者都用于维持既定功能或证明边界。

旧配置迁移完成只代表配置可加载，不能让旧客户端兼容Moon/2。RC4归档和原客户端实验工作树均保留；没有推送GitHub或覆盖已部署服务。


# 0.2.0-dev.1 / Moon/2 重构验证（2026-10-27）

当前源码主动放弃官方及旧moon-naive客户端兼容。服务端协议测试已经执行，配套可分发客户端尚未实现；不得把旧RC4互通证据当作当前代理可用性证据。RC4验证已归档到[HISTORY.md](HISTORY.md#rc4-验证归档moon2重构前)，原发布包及冻结二进制保留。

## 实际检查结果

| 检查 | 结果与范围 |
| --- | --- |
| Debug workspace | **123 passed、0 failed、0 ignored** |
| Release workspace | **123 passed、0 failed、0 ignored** |
| 测试组成 | core 29、control 13、native 75、CLI 2、Pebble 2、xtask 2；另有0测试的程序入口。显式启用外部程序和ignored测试 |
| 编译/静态检查 | workspace全部测试目标编译、all-targets Clippy `-D warnings`、第一方fmt和Git diff空白检查通过 |
| 真实H2/H3 | Moon/2请求及响应证明、跨流/跨连接/跨传输重放拒绝、全程记录、慢读背压、半关闭/取消、空闲期限及配额归还通过 |
| 官方客户端 | 官方v154.0.8037.49-5的旧Basic协议在H2/H3上均不能取得目标拨号权限；这是拒绝降级测试，不是互通成功 |
| 网站与ACME | 真实Chromium的H3发现/H2回退、固定反代高级协议及Pebble/EAB签发恢复测试通过；不涉及公网Porkbun/GTS生产账户 |
| 配置清理 | 旧fast_open/zero_rtt的true和false均被正常CLI拒绝；迁移旧false值、拒绝true、保留原文件和私有权限的回归通过 |
| 生产构建 | Rust 1.89 / x86_64-unknown-linux-musl，独立执行`cargo build --release --offline --locked --target x86_64-unknown-linux-musl -p moon-naive`通过 |
| 生产文件 | `target/protocol-v2/moon-naive`，16,322,080字节；ELF无INTERP和NEEDED，CLI版本及字节输出基准通过 |
| 发行版运行 | 同一生产文件在固定digest的Alpine 3.22、Debian 12、Arch容器中，普通用户/只读文件系统/无网络执行版本、配置和TCP BBR检查，三者均通过 |
| 依赖与vendor | 固定源revision和Pingora SHA256SUMS审计通过；相对RC4只有新增hmac 0.12.1，没有升级其他外部依赖；无Caddy运行依赖 |
| 客户端源码 | 独立官方源码checkout、Git连通性检查及三个构建脚本的shell语法检查通过；未下载完整构建工具链，未编译或改写客户端 |

全套测试后，仅修正验证工具对脱敏“unknown field”错误文本的预期；此分支用最终生产程序实际验证，并再次检查Clippy和xtask构建/测试。服务端源码未因产物检查再次修改。测试数低于RC4是因为旧8/16条及裸流测试被删除/替换，并删除旧响应Padding模块测试；网站、ACME和传输边界仍有实际回归，不能按数量推断覆盖率相同。

生产文件SHA-256：

```text
6006464920361fc2ed77ef20772c55ec4ee84733daea62351dc27c1cf60347c5
```

RC4冻结二进制哈希仍为`69ea42fbb65884fca1f3aef2b46b00914b798ca42315d419479b245332418bad`，没有用开发版覆盖回退资产。

## 可复核证据

持久结果位于`reports/protocol-v2/`（本地验证产物，Git忽略）：

- `debug-tests.log`、`release-tests.log`、`test-results.json`及对应Cargo artifacts JSONL：实际执行记录。
- `clippy.log`、`production-build.log`、`production-smoke.json`、`platform-results.txt`：编译、静态产物和三发行版检查。
- `final-tool-build.log`、`final-tool-tests.log`：最终验证工具的定向补充检查。
- `component-audit.json`、`dependency-delta.json`、`native-graph.txt`：清理边界及依赖对照。
- `change-set.patch`、`changed-files.json`：相对于RC4源码归档的最终变更，而非较旧Git HEAD的全部历史修改。
- `client-checkout.json`、`upstream-review.json`：客户端基线、原工作树保留情况及原服务端最新修复版本。

详细协议、已知问题来源、实际删除的函数/字段与保留项见[PROTOCOL-V2.md](PROTOCOL-V2.md)。运行方式仍是一份私有TOML加systemd/OpenRC；迁移命令不会让旧客户端兼容Moon/2。

## 未完成的外部验收

- 配套新客户端实现、真实Chromium新协议闭环，以及跨系统客户端构建。现有测试适配器不等于可交付客户端。
- 新认证组合的独立协议审计；高熵秘密、正常证书验证和信任策略维护仍是必要条件。
- 完整ECH公开证书/DNS发布/轮换自动化和双端验收。目前仍是默认关闭的实验性接入。
- 与同条件纯反代、Caddy+官方客户端比较的抓包、DPI识别率、吞吐、尾延迟、RSS、丢包/MTU和24小时稳定性验收。
- 公网Porkbun/GTS签发与实际VPS systemd/OpenRC升级恢复演练。容器共享宿主内核，不能替代目标VPS的BBR条件检查；TCP BBR不等同于quiche BBRv2。

本轮没有创建稳定发布包、推送GitHub或更新运行中的服务。新持续Padding增加小包开销，BoringSSL/ECH/新认证均不能单独证明更难被识别。


---

## 0.2.0-dev.2 协议与验证历史快照（已由 dev.3 替代）

# 上游弱点、moon-naive 协议与客户端构建基线

更新：2026-10-27。当前服务端为 **0.2.0-dev.2**，协议名称为 **moon-naive**，内部认证域/exporter修订号为3（不是另一个协议名）；只接受这一修订，明确不兼容官方 Naïve 客户端或旧 moon-naive-16 客户端。RC4 包仍保留用于回退；不能直接用旧客户端验证新代理成功。网站、自动证书和服务启动配置继续使用现有 TOML schema v2；配置 schema 与隧道协议版本是不同概念。

## 已知问题的证据与边界

客户端基线是官方最新稳定标签 `v154.0.8037.49-5`，提交 `d04efe1ea4477c2db24a7d0e2f068b3bee931e45`，Chromium `154.0.8037.49`。服务端对照已从作者 forwardproxy `c096d6a00cb28e019cc1995b04bdc6a9311d8024` 补查至最新标签 `v2.11.7-naive2`（`e747854e78743dba85c039b38ed185fb11d93667`）；原研究工作树保持不变。不能由此宣称审查了所有 Caddy、Go 或插件版本。

| 对象 | 已确认或由源码直接得出的限制 | 本轮处理／仍有限制 |
| --- | --- | --- |
| 客户端证书信任 | 2026-10-22 官方发布说明明确：旧版无法安全抵御使用伪造 eMudhra 证书的 MitM。修复提交 `23953c90e3b9f08f8d0c6ede92ae35f357af6f73` 给 `cert_verify_proc_blocklist.inc` 增加 8 个被阻止的 SPKI | 新拉取源码含修复。不能说最新版仍有这个已修复问题；系统根更新也不能替代客户端 blocklist／撤销策略更新 |
| 双端 Padding | 官方每方向只填前 8 条应用记录，u16 数据长度 + u8 填充长度，0..255 填充；之后裸流。不能掩盖全部长度、突发、方向、长连接和关联特征 | moon-naive仅前16条有限填充，之后无应用记录封装；接收端同样检查小额填充预算；没有证明 DPI 识别率下降 |
| 客户端 H2 关闭行为 | 官方 README 记录：额外 48..72 字节 END_STREAM DATA 用于掩饰 RST_STREAM，可能引发 WINDOW_UPDATE，新特征是否产生仍不确定 | 服务端不人工制造这类小尾帧。新客户端需要重写关闭策略并实测，不应机械复制旧补丁 |
| 客户端 H1 回退 | H1 隧道缺少 H2/H3 的跨流复用，容易保留目标连接建立和 TLS-in-TLS 的时序结构。这是协议限制，不是 TLS 加密被破解 | 服务器 H1 只服务网站；新客户端只允许 H3→H2 回退，不得回退 H1 代理或直连 |
| 客户端网络栈维护 | 复用 Chromium 不等于完整浏览器行为；需要及时更新 TLS、QUIC、证书策略、HPACK/QPACK 和会话调度。官方已加入真实网站前导请求及旧隧道清理改进 | 保留 Chromium 构建基线及前导机制作为参考。重写全部为普通 Rust TLS 客户端会丢失这一优势 |
| 原服务端认证 | Basic 依赖外层 TLS 保密；一旦在终止端、错误日志或受信 MitM 处泄露，凭据可跨连接使用。正常 TLS 密文重放会被 TLS 拒绝，不能混为一谈 | moon-naive 用 TLS exporter + 流 ID + 请求语义的 HMAC；逐流验证，成功响应也有独立证明 |
| 原服务端隧道空闲 | `v2.11.7-naive2` 修复认证 H2/H3 CONNECT 被 Caddy `read_body_idle` 提前终止的问题：逐请求将读取空闲覆盖为24小时，硬性期限仍有效 | 本项目已有任一方向实际进展刷新、默认600秒的隧道空闲期限；不引入 Caddy 专用覆盖接口。最新版已修复，不能仍称其存在相同问题 |
| 原服务端主动探测 | `probe_resistance`、`hide_ip`、`hide_via` 和真实站点配置影响行为；错误配置、额外管理端口、暴露登录页或凭据泄露仍可能暴露代理 | 保留统一固定反代、H1 严格解析、无 407、无公开版本探测；畸形协议仍会产生正常协议错误，不能保证各服务器错误指纹相同 |
| 服务端／客户端资源 | H2 复用共享 TCP 队头阻塞；H3 对 UDP 可达性和 CPU 敏感；流额度、窗口、连接/握手/拨号期限仍需限制 | 复用既有预算、取消、背压、半关闭、H2 reset 限额、QUIC Retry 和握手回收；不是所有实现都已通过 DoS 压测 |
| 双端 SNI/ECH | 普通 TLS/QUIC Initial 不隐藏入口 SNI；ECH 隐藏 ClientHelloInner，不隐藏 IP、外层公开名称、长度、时序，也不修复错误信任链 | 保留默认关闭的实验性 ECH；不按 ECH 是否接受切换 Padding；DNS 发布、公开证书和轮换仍需管理 |
| 服务端对外 HTTPS | 网站反代、HTTPS 下一跳、ACME 使用其实际 TLS 验证路径；BoringSSL 加载系统 CA 不自动拥有 Chrome 的全部吊销、CT 或 blocklist 机制 | 未把客户端的 eMudhra 修复误称为服务端全面吊销防护。固定上游可配置独立 CA；生产仍需信任策略维护与审计 |

来源：[官方协议说明](https://github.com/klzgrad/naiveproxy/blob/v154.0.8037.49-5/README.md)、[中文 Wiki](https://github.com/klzgrad/naiveproxy/wiki/简体中文)、[客户端安全修复发布说明](https://github.com/klzgrad/naiveproxy/releases/tag/v154.0.8037.49-5)、[证书修复提交](https://github.com/klzgrad/naiveproxy/commit/23953c90e3b9f08f8d0c6ede92ae35f357af6f73)、[服务端空闲修复发布说明](https://github.com/klzgrad/forwardproxy/releases/tag/v2.11.7-naive2)、[原服务端源码](https://github.com/klzgrad/forwardproxy/tree/e747854e78743dba85c039b38ed185fb11d93667)。旧 Wiki 示例和平台依赖有过时内容，以固定版本源码/构建 workflow 为准。这里不把推测写成 CVE，也没有发现或证明最新版存在未修复远程执行漏洞。

## 认证：不发送可复用 Basic 密码

只在完成 **TLS 1.3** 握手的 H2/H3 上允许代理。H1、无 ALPN 和 TLS1.2 H2 仍可访问网站，不能启用代理。没有 TLS 0-RTT、TCP Fast Open 或代理 Fast Open。

1. 取得实际连接的标准 TLS exporter：label 为 ASCII `EXPORTER-moon-naive-v3`，context 为显式空字节串，输出 32 字节。必须是正常握手 exporter，禁止 early exporter。重连/会话恢复后重新取得；ECH 接受与否不改变算法。
2. 从实际 H2/H3 分配的流 ID 取得 `stream_id`，编码为 8 字节无符号大端整数。H2 首个请求通常是 1，H3 首个请求通常是 0；前导网页同样消耗请求流编号，不能按 CONNECT 次数猜测。
3. `key = SHA256(b"moon-naive/v3/key\0" || UTF8(username) || b":" || UTF8(password))`。用户名不能包含冒号。用户名/密码要求与 TOML 一致；请使用随机 32 字符以上秘密。此派生不是口令拉伸，不防低熵密码的离线猜测。
4. `message = b"moon-naive/v3/request\0" || exporter || u64be(stream_id) || fields`。
5. fields 固定依次为 method、authority、scheme、path-and-query、protocol。存在的字段编码为 `u64be(UTF8字节数) || UTF8字节`，缺失字段为 8 个 `0xff`；空值与缺失不同。使用线上实际值，不额外改大小写、端口、百分号编码或查询顺序。普通 CONNECT 的后三项必须缺失。
6. `mac = HMAC-SHA256(key, SHA256(message))`；发送唯一一个 `Proxy-Authorization: moon-naive <标准带=的Base64(mac)>`。值长度 55 字节。scheme 大小写不敏感，重复首部、别名、错误长度、Basic、错误证明都不认证。客户端必须禁止 HPACK/QPACK 动态索引该字段。

服务端先对请求上下文做一次SHA256，再以恒定时间比较每个配置用户的HMAC证明，避免256用户把超长请求上下文的哈希工作放大256倍；无连接级“已登录”标志。没有时间戳、全局 nonce 缓存、重放窗口或相应时钟依赖。跨连接 exporter 改变，跨流 ID 改变，目标/方法改变也改变 MAC。HTTP 状态机不得重新接受同一流的第二个请求头；网站 trailers 不能再认证。服务端重启后新 TLS 连接同样产生新 exporter。普通 TLS 记录或 QUIC 包的网络重放仍由底层协议处理。

成功CONNECT在完成目标拨号后返回200及唯一的认证证明，不添加随机Padding首部或装饰性正文：

```text
Proxy-Authentication-Info: moon-naive <Base64(server_mac)>
```

server_mac使用同一算法与字段，仅将domain改为`b"moon-naive/v3/response/200\0"`。新客户端必须验证状态、唯一性和证明后才发送代理数据；请求证明不能反射为响应证明。响应字段值固定55字节，但MAC内容必须随上下文改变。H2将证明设为never-index，固定quiche版本的QPACK编码器不动态插入；这不禁止Huffman编码，也不保证压缩后HEADERS长度完全一致。已删除上一开发版64..127字符的随机Padding响应头。网站响应仍由真实源站决定，不随机改写正文、长度或Server字段。

认证证明是标准密码原语的一次新协议组合，尚未经外部审计。不能关闭正常证书链、名称、用途和吊销验证；建议新客户端提供预置 SPKI pin 与可轮换备份 pin。TLS 终止的 CDN/反代会改变 exporter，不能把本协议直接藏在另一个终止 TLS 的代理后面。L4 透传仍可用。通用 HTTP 正向请求同样逐请求认证，正文保持 HTTP 语义；上述成功响应证明仅定义于 CONNECT。

### 独立互操作向量

以下为公开测试凭据，不用于部署。username=`user`，password=`a-long-test-secret-123`，exporter为32个`07`字节，stream_id=1，method=`CONNECT`，authority=`example.org:443`，scheme/path/protocol均缺失。Python hashlib/hmac独立计算结果：

```text
request: moon-naive iNCC25LF+wiMQOcnyJ3mi33ALNLnr4XOYDZpDmWGed8=
response: moon-naive uhcLCypLvyHnjjXjHnOqdEzXEhdglOcY4jMegASNEoI=
```

## 有限初期记录：前16条，随后直接转发

每条CONNECT的两个方向独立计数，与HTTP DATA帧、TLS记录、QUIC包无一一对应关系。前16条非空应用记录为：

```text
u16be payload_length | u8 padding_length | payload | padding
```

令`i`为该方向已经完成的记录数（0..15），`N`为有效载荷长度，则线上双方都必须满足：

```text
1 <= N <= 16341
0 <= P <= min(floor(N / 8), 31 - 2*i)
record_size = 3 + N + P <= 16375
```

服务端从0..P上限均匀选取填充长度，填充内容为零。随机性只有初期的小额长度扰动：BoringSSL CSPRNG按32字节批量获取，采用拒绝采样避免取模偏差；上限为0时不消耗熵。短读立即发送，不等待凑块、不分裂成额外小写入、不加定时抖动或空闲假流量。未来Chromium客户端可以在上述边界内选择自己的发送长度，不要求复制服务端抽样分布。

第16条的payload和padding完整结束之后，**紧接的所有字节都是原始隧道数据**，不再有记录头、Padding、RNG调用或结束标记。第16条尾部和原始字节可以处于同一个HTTP DATA块。流不足16条时允许在完整记录边界结束；截断头/载荷/填充和纯填充记录拒绝。切换由每方向独立的协议计数决定，不通过未认证头、时间、ECH状态或猜测TLS内容决定。

这里的原始字节仍在已加密的H2/H3 CONNECT内传输，只移除应用层填充；不会关闭TLS/QUIC加密，也不会绕过ACL或配置好的下一跳。

最多16×3+sum(31,29,...,1)=**304字节额外开销/方向/CONNECT**（仅应用封装；不含HTTP/TLS/QUIC）。有效数据足够大且按服务端均匀抽样时，期望为48+128=176字节；小数据的比例上限会继续降低填充。1..7字节的初期payload不加padding，但仍有3字节记录头，因此不能声称小记录总开销也不超过12.5%。上一开发版前16条平均16440字节、之后每条仍平均131.5字节的方案已弃用。

下载读取上限初期固定16341字节，避免用本条P反向减小有效数据而抵消扰动；切换后读取最多16384字节。BytesMut原地读入、写头/尾、移交Bytes，部分发送不重新抽样。上传`decode_slice`直接返回借用的payload切片，不再收集到scratch Vec；切换后删除解析状态并直接写入原输入。不是内核零拷贝；异步写完之前仍持有输入缓冲，流控、背压和半关闭保持生效。

这是一组保守的开销边界，**不是已测得的网站长度分布**。不把密文字节熵当成流量类别判据；TLS密文本来应具有高熵。被动识别更关心包长、方向、时序、复用和长期关联；本轮减少人为扰动及长期协议痕迹，但仍需同条件抓包验证。有限填充只能影响连接初期，后续长度相关性仍然存在。

## 路由与兼容性

| 请求 | 路由 |
| --- | --- |
| H1 的任意凭据、普通网页、CONNECT、absolute-form | 既有严格网站规则/固定反代；CONNECT或非法目标为普通网站错误；零任意目标代理拨号 |
| H2 TLS1.2 | 网站；无法生成有效 moon-naive 认证上下文 |
| H2 TLS1.3 / H3，无凭据、Basic、错误/重放证明 | 共同网站路径，移除代理元数据；不返回407、不宣告协议版本，不为代理解析DNS/拨号 |
| H2/H3，有效普通 CONNECT | 检查配额、目标ACL及拨号；成功200与响应证明；有限初期记录后直接转发；失败不提前200 |
| H2/H3，有效通用 HTTP 请求且非网站域名 | 按用户+origin隔离的正向池，沿用出站ACL及HTTP(S)/SOCKS5下一跳 |
| H1 Upgrade / H2/H3 扩展 CONNECT WebSocket | 只到管理员配置的固定网站路由，无任意目标权限；保持原始WebSocket字节，不套moon-naive记录 |
| 语法攻击、超限头、流重置洪泛、握手拖延 | 既有解析错误、reset、限额和关闭策略；不是所有攻击都会返回同一页面 |

不会增加外层浏览器请求头、伪造 User-Agent 或更改客户端 ClientHello。服务端无法替未来客户端实现 Chromium 请求顺序、前导站点选择、RST_STREAM关闭和会话调度。新客户端完成前，本版本不能供旧 Naïve 客户端日常代理使用。

## 已拉取的客户端构建项目

本地独立目录：`/workspace/naiveproxy-client-upstream`。固定标签 `v154.0.8037.49-5`，无工作树修改；原 `/workspace/moon-naive-client` 的既有实验修改保留。它是官方精简 Chromium 源码项目，不是只包含预编译二进制，也不是从头下载完整 Chrome 浏览器。

| 目录/文件 | 用途 |
| --- | --- |
| CHROMIUM_VERSION、.github/workflows/build.yml | 固定Chromium版本及官方跨平台构建步骤 |
| src/get-clang.sh、src/get-sysroot.sh、src/build.sh | 下载版本匹配工具链/所需构建资源，GN生成并Ninja构建naive |
| src/net/tools/naive/ | SOCKS/HTTP本地入口、配置、转发、旧Padding、代理delegate、前导网页请求 |
| src/net/http/、src/net/spdy/、src/net/quic/ | HTTP CONNECT、H2会话、H3会话与连接复用 |
| src/net/socket/、src/net/ssl/、src/net/cert/ | TLS socket、exporter/验证、证书策略与已修复blocklist |
| src/net/third_party/quiche/、src/third_party/boringssl/ | Chromium QUICHE与BoringSSL；前者是C++实现，不是服务端Cloudflare Rust quiche |
| src/base/、src/build/、src/buildtools/、src/BUILD.gn | Chromium基础运行库和GN构建配置 |
| tests/、tools/、apk/ | 官方测试、开发工具和Android打包 |

在适合官方Linux构建流程的Debian/Ubuntu构建机上，基础命令如下；版本特定包安装及sysroot步骤以固定workflow为准：

```sh
sudo apt update
sudo apt install git curl xz-utils python3 build-essential ninja-build pkg-config ccache cmake
cd /workspace/naiveproxy-client-upstream/src
export EXTRA_FLAGS='target_cpu="x64"'
./get-clang.sh
./build.sh
../tests/basic.sh out/Release/naive
```

这些命令构建的是原版客户端，**不能连接moon-naive代理**。构建脚本还会下载LLVM/GN/PGO/sysroot等资源，拉取源码不代表这些资源已下载，也不代表新客户端已编译完成。建议预留足够磁盘及内存，不把服务器Cargo工具链误用为客户端Chromium构建工具链。

改造顺序：保留Chromium外层TLS/H2/H3与证书策略；在实际分配CONNECT流ID之后、发送HEADERS之前获取exporter并计算证明；确认200响应证明；替换NaivePaddingSocket/Framer为本节有限记录和精确切换状态机；禁用代理H1回退、Fast Open和0-RTT；保持受控前导网页和会话复用；最后执行双端ECH/恢复/丢包/抓包对照。HPACK/QPACK须never-index认证值。若转为Rust，优先让Rust承载控制/配置或编解码，通过清晰接口继续使用Chromium外层网络栈；单独采用BoringSSL并不能复现Chromium全部网络行为。

## 本轮精简、Go审计与Rust实现参考

| 项目 | 当前处理 |
| --- | --- |
| 持续4字节记录头、0..2047大填充、后期0..255填充 | 删除，改为上述有限初期格式 |
| 随机响应Padding生成器、128字节响应熵缓冲 | 删除；只保留安全协议必需的固定长度响应证明 |
| 上传scratch Vec和逐块payload复制 | 删除，返回借用切片；第16条后直接转发 |
| Basic入口、旧8/16协商、旧认证scheme | 不恢复；当前moon-naive认证使用v3域/exporter，旧证明拒绝 |
| Fast Open、0-RTT | 实现继续禁用；旧false字段只在一次性迁移中剔除 |
| Caddy、xcaddy、CertMagic、Go TLS、Go QUIC | 原本没有进入服务端运行依赖，没有虚构删除数量 |
| Go防回归检查 | 构建源审计拒绝服务端输入中的.go/go.mod/go.sum；依赖审计拒绝Caddy等包名；发布ELF拒绝常见Go元数据段。元数据检测不是完整二进制安全审计 |
| Go编写的Pebble测试程序及原forwardproxy研究源码 | 保留在项目之外，仅测试/对照使用；不链接、不随服务端运行包发布 |
| Pingora网站、H1网站、WebSocket、SSE/gRPC、压缩、ACME、下一跳 | 保留；下一跳标准Basic不是入口Basic认证 |
| 旧代理元数据过滤 | 保留，防止敏感或过时首部泄露到源站；不表示支持旧协议 |

参考了[ripgrep 14.1.1](https://github.com/BurntSushi/ripgrep/tree/4649aa9700619f94cf9c66876e9549d83420e16c)的`crates/searcher/src/line_buffer.rs`借用切片接口及`searcher/mod.rs`复用缓冲/按路径选择执行方式。采用其工程方法，不复制其搜索算法，不新增regex、搜索引擎、mmap或第二套异步运行时。参考checkout位于`/workspace/ripgrep-reference`，不进入Cargo依赖。证据在`reports/finite-padding/ripgrep-reference.json`。

协议文档统一为`docs/PROTOCOL.md`。旧开发版说明和验证保存在HISTORY，冻结二进制及既有客户端实验修改保留；未修改官方Chromium源码。后续客户端继续基于Chromium外层网络栈，先实现新认证、有限编解码和流ID绑定，再对照原版/纯网站的请求顺序、关闭流和复用行为。


# moon-naive 0.2.0-dev.2 验证（2026-10-27）

本轮将持续填充改为最多16条的小额初期记录，删除随机响应Padding首部，协议名称及认证scheme统一为moon-naive，认证域/exporter使用内部修订3。旧客户端与上一开发版均不兼容。配套Chromium客户端仍待实现；服务端集成测试使用独立测试适配器，不等于已经交付客户端。

## 结果

| 检查 | 实际结果 |
| --- | --- |
| Debug workspace | **124 passed、0 failed、0 ignored**；完整7个测试程序 |
| Release workspace | **124 passed、0 failed、0 ignored**；完整7个测试程序 |
| 测试组成 | core 29、control 13、native 76、CLI 2、Pebble 2、xtask 2；程序入口另有0测试 |
| Rust检查 | 全部workspace测试目标编译、Clippy all-targets `-D warnings`、第一方fmt、Git diff空白检查通过 |
| 记录协议 | 独立字节向量、所有分块大小、第16条与原始字节同块、截断/过量填充拒绝、最大304字节预算、payload指针复用、阶段结束后不再消耗熵通过 |
| 真实网络 | H2/H3认证/响应证明/跨流跨连接拒绝、有限记录后直通、慢读背压、半关闭、空闲回收、取消和配额归还通过 |
| 网站与证书 | H1网站边界、反代/下一跳/WebSocket/trailers/103等既有测试、真实Chromium H3发现/H2回退、Pebble/EAB首次取证及恢复均显式执行 |
| 旧客户端 | 官方v154.0.8037.49-5在H2/H3上无法使用旧Basic获得代理权限；不是旧客户端互通成功 |
| 确定性模型 | 10,000轮有限记录/直通、随机分块字节对拍与配额/证书模型通过；不是公网长时间soak |
| 生产构建 | Rust1.89 / x86_64-unknown-linux-musl，独立release构建服务端和xtask通过；生产文件冻结在target/finite-padding |
| 静态产物 | 无INTERP/NEEDED；CLI字节基准、私有配置副本、旧字段拒绝及BBR检查通过 |
| 发行版 | 同一静态文件在固定digest的Alpine3.22、Debian12、Arch容器中，以普通用户、只读文件系统、无网络执行版本/配置/TCP BBR检查，全部通过 |
| Go审计 | 服务端构建输入未发现.go/go.mod/go.sum；依赖图无Caddy/Go网络栈；生产ELF未发现常见Go构建段。发布工具也已加入拒绝检查；这不是任意二进制的完整语言归属证明 |
| 依赖/vendor | 固定Git来源与Pingora完整摘要审计通过；本轮未新增、删除或升级任何外部Cargo依赖 |
| 验证工具 | 不完整/失败的Cargo artifacts及空测试清单均拒绝，防止提前读取清单造成漏测；实际CLI检查通过 |

最初回归发现H3空闲测试仍断言旧4字节记录头的发送长度，已按新3字节头修正；最终完整Debug/Release均重新通过。首次测试清单提前读取的问题也已修正，最终汇总确认两个profile各执行7个程序，未将部分运行计作全套通过。

## 可量化的变化

前16条的应用填充上限依次31、29、…、1字节，且不超过有效数据的八分之一。每方向封装额外开销最多16×3+256=**304字节**；足够大payload的均匀策略期望**176字节**。第16条结束后没有应用记录头/填充/随机数调用。1..7字节的小记录仍有3字节头，不能把12.5%填充比例上限误称为总开销上限。

参考ripgrep14.1.1的借用切片和复用缓冲方式，生产上传路径取消scratch Vec和整块payload复制。内存微基准使用同一有限协议，比较复用Vec收集与借用切片，9批、每批64条约1MiB流：

| 指标 | Vec收集参考路径 | 借用切片路径 |
| --- | ---: | ---: |
| 每批payload复制量 | 67,117,056字节 | 0字节 |
| 每批中位耗时 | 1.320 ms | 0.109 ms |

该微基准不包含socket/TLS/QUIC，且在当前构建主机执行，不能推导实际代理吞吐提高倍数。TLS/内核仍可能复制数据，不声称内核零拷贝。没有网站包长拟合、DPI识别率或端到端吞吐改善的实测结论。

## 产物与证据

生产文件：`target/finite-padding/moon-naive`，16,358,944字节。SHA-256：

```text
dea6b5a07c0cd53d70cc471d4030e289a371bc0719a80bc809812e9c818cd62e
```

`reports/finite-padding/`保存实际测试/编译日志、artifacts JSONL、test-results.json、production-smoke.json、platform-results.txt、native-graph.txt、model-results.txt、artifact-input-guard.json、独立认证向量、微基准源码/结果、ripgrep参考来源及本轮变更快照。报告目录为本地验证产物，不自动进入Git或运行包。

旧RC4冻结产物哈希保持不变，上一开发版生产文件、既有未提交修改、原客户端实验工作树和官方Chromium参考源码均保留。未推送GitHub、部署服务或执行公网CA/DNS写入。

## 待完成范围

- 配套Chromium客户端的新认证、有限记录和精确切换实现，以及双端互通和会话恢复验收。
- 完整ECH公开证书/DNS发布/轮换自动化；当前仍为默认关闭的实验性接入。
- 新认证组合独立审计、实际目标VPS服务升级恢复、公网Porkbun/GTS签发及长期运行。
- 同条件纯网站/原项目/新双端的抓包、长度/时序/方向分布、DPI、吞吐/尾延迟/RSS与丢包/MTU对照。有限填充减少额外扰动，也减少后续长度遮蔽；TLS密文高熵本身是正常性质。

协议和具体预算见[PROTOCOL.md](PROTOCOL.md)，网络行为边界见[FINGERPRINTS.md](FINGERPRINTS.md)。


---

## 整合前审查文档存档

# 项目审查与精简（RC2 后工作树）

本文件主体为截至RC4的历史审查记录，保留当时的实现和测试结论；其中Basic/8条互通描述不代表当前协议。当前变更统一见PROTOCOL.md，避免修改原始审查证据。

> 当前源码为0.2.0-dev.2，协议名称moon-naive，采用有限初期填充；官方及旧开发版客户端均不兼容。构建、TOML和服务管理步骤继续适用，历史互通结果不适用于当前修订。新客户端要求和本轮证据见[PROTOCOL.md](PROTOCOL.md)与[VERIFICATION.md](VERIFICATION.md)。

日期：2026-10-23。比较对象是本轮开始时的 RC2 工作树，而非仓库最初提交；已有未提交改动完整保留。重构前源码和差异另外备份在工作区 moon-naive-review-baseline，已发布 dist/rc2 不覆盖。

下述精简阶段记录保留；随后以 dist/review 源码为基线进行的性能修改单列于“后续代理性能优化”，最新测试与测量见 VERIFICATION.md。

## 审查范围与结论

检查第一方 Cargo 包/依赖、配置与认证边界、H1/H2/H3 分流、拨号/ACL/下一跳、Pingora 网站/反代/WebSocket/头部、ACME 及状态权限/恢复、服务文件、验证打包脚本与文档引用。第三方检查针对实际依赖图、本地 Pingora 补丁和完整摘要清单；不是对全部第三方实现的独立安全认证，也没有进行公网渗透或识别率测量。

| 发现 | 本轮处理 | 影响 |
| --- | --- | --- |
| 网站、正向请求、WebSocket 重复维护秘密头和转发头列表 | 共用 core::ingress::PROXY_HEADERS 与网站 FORWARDED_HEADERS | 消除规则漂移；补齐扩展 WebSocket 的 X-Forwarded-Port 清理，并将原仅 HTTP/1.1 的入口清理覆盖 HTTP/1.0；真实上游回归检查伪造身份和秘密字段 |
| daemon 只有一个薄 main，却独占 Cargo.toml/src/tests 目录 | 根 Cargo 包承接，main 位于 native/src/main.rs，CLI 测试位于 tests/cli.rs | 二进制名、CLI、默认 cargo build 和 -p moon-naive 不变；workspace 仍为五包 |
| 21 份历史阶段文件与旧安装说明分散 | 原文合并到 HISTORY.md；当前安装流程统一到 VPS-GUIDE.md | 保留历史证据，避免旧名称、旧命令与当前说明混用 |
| 五份小型 TOML 片段分散在 examples/secrets 与 examples | 模板集中到 CONFIGURATION.md；生产主配置含可启用的路由示例 | v1 读取/迁移不删除；网站文档片段继续由 Rust 测试解析校验 |
| xtask 验证报告仍写 H1 rejection | 改为实际检查项 Fast Open rejection | 不再误导为禁止网站 H1 |
| 项目结构与发布输入指向已移动文件 | 同步逐文件说明、导航、Cargo 路径和归档清单 | 构建、测试、归档随结构变化一起验证 |

没有为凑数量合并 H2/H3 驱动、ACME provider/状态机或大型测试模块。core/control 继续可独立测试；全部现有测试保留。前八条 Padding、16 KiB 读取、认证先于目标解析、拨号成功才 200、0-RTT/Fast Open 禁用、证书状态格式和配置 schema 均未改变。

Pingora 快照继续完整保留：其 Cargo manifests 包含可选后端、开发依赖和相对路径引用，直接删目录会破坏来源校验/上游测试/升级可比性。Rustls/OpenSSL/s2n 的源码目录存在不代表链接；生产依赖仍只启用 BoringSSL/quiche。本轮不通过删许可证、测试证书夹具或改动依赖锁来减少数字。

## 精简统计

以源码包中普通文件及其父目录计数，排除 .git、target、dist、reports 和运行状态；第三方公开测试夹具计入 vendor。

| 范围 | 重构前 | 重构后 | 减少 |
| --- | ---: | ---: | ---: |
| 第一方文件 | 126 | 100 | 26（20.6%） |
| 第一方目录（不计根） | 29 | 23 | 6（20.7%） |
| 含 vendor 的源码文件 | 573 | 547 | 26 |
| 含 vendor 的目录（不计根） | 166 | 160 | 6 |

数量下降主要来自历史文档、配置模板与入口目录；不是删除业务功能，也不是宣称二进制缩小 20%。第一方仍保留 5 个 Cargo 包，Cargo.lock 和整个 vendor 快照逐字节不变。

## 与作者原服务端的差异校对

基准为本地 klzgrad/forwardproxy 提交 `c096d6a00cb28e019cc1995b04bdc6a9311d8024`（工作树无修改），重点核对 forwardproxy.go、caddyfile.go、httpclient、CADDY_VERSION 及 .github/workflows/build.yml。`go.mod` 写 Caddy v2.8.4，但发布工作流实际读取 CADDY_VERSION=v2.11.7，并应用 sing-quic BBRv1 补丁；不能用 go.mod 版本代替作者发布构建，也不能把任意 xcaddy 构建都算成同一协议栈。

| 项目 | 作者 forwardproxy / Caddy | moon-naive | 结论 |
| --- | --- | --- | --- |
| 客户端与认证 | 官方 Chromium/Naïve 客户端，Basic 逐请求检查；认证可配置关闭 | 不改客户端，强制认证，每流检查；无效/重复凭据走网站 | 核心互通；配置自由度不同 |
| H1 CONNECT / 普通代理 | 支持 H1/H2/H3；H1 可 hijack | H1/无 ALPN 仅网站；代理限 H2/H3 | 主动保留的差异，普通 curl/browser H1 代理不兼容 |
| CONNECT 成功时机 | forwardproxy.go 先写 200/Flush，再拨目标 | 目标或下一跳隧道成功后才 200 | 按用户要求禁用 HTTP CONNECT Fast Open；不是等价延迟/错误语义 |
| Padding | 响应头 30..61 字节，前八条 legacy 数据记录 | 保留该规则与官方客户端互操作 | 不保证帧分段、随机数实现或发送时序相同；不宣称未来全部版本兼容 |
| 普通 HTTP(S) 转发 | 支持；可配置 hide_ip/hide_via | H2/H3 已认证转发，按用户/origin 隔离池 | 非完整通用 H1 代理；固定头部策略，无对应开关 |
| 代理链 | HTTP(S)/SOCKS；HTTPS 上游 httpclient 可复用 H2；上游模式跳过本地目标 ACL/DNS | 一个下一跳，HTTP(S) CONNECT 使用 H1，SOCKS5 发送已检查 IP；本地 DNS/ACL，失败不直连 | 不是任意多跳；缺少 HTTPS 上游 H2 隧道复用和远端 DNS 策略；localhost TLS 也不跳过校验 |
| 访问控制 | 有序域名/IP/CIDR/端口/文件 ACL | 固定公网 IP/自身地址限制，逐候选检查 | 未实现可配置规则及内网放行；wildcard 监听不等于自动枚举所有本机公网地址 |
| 探测响应 | 可选 probe resistance、secret-domain 认证页、407、PAC | 无认证走固定网站，不提供 407 引导/secret-domain/PAC 生成 | 保留的接口收敛；不据此推导识别率 |
| TLS/H2/QUIC | Go TLS、Go HTTP、作者发布 QUIC 补丁 | BoringSSL、Pingora/h2、quiche BBRv2 | 状态机/参数/票据/错误行为不同；BoringSSL 不复制 Chromium 或 Caddy 服务端指纹 |
| TCP 拥塞 | 宿主内核控制 | socket 显式 bbr 或 system | TCP bbr 具体版本取决于内核；不等于用户态 quiche BBRv2 |
| ACME | Caddy/CertMagic 多挑战、多域名、模块化 provider/storage | 单域名 DNS-01，GTS/LE、Porkbun/Cloudflare，EAB/ARI/续期/持久恢复 | 满足当前单机流程，不等价全部 CertMagic 能力 |
| 证书/配置更新 | 证书自动管理；admin API/reload | 证书热更新，静态文件即时生效；配置/用户/池变更重启 | 无事务式配置热重载、集群存储锁、按需取证、手动证书配置入口 |
| 网站反代 | Caddy matcher/handler/module 生态 | 固定前缀路由、文件、gzip、HTTP1/H2 上游池、SSE/gRPC、100/103/trailers、WebSocket | 保留成熟基础路径；无完整重写/模板/主动健康检查/动态发现/可编程 LB/缓存模块 |
| 高级隧道 | 能力依具体 Caddy/模块版本 | 仅固定网站 WebSocket 扩展 CONNECT；无 MASQUE/WebTransport | 不把网站扩展 CONNECT 当成任意目标代理 |
| 运维 | xcaddy + Caddyfile，丰富日志/指标模块 | cargo + TOML，单服务 systemd/OpenRC，脱敏事件与本地 status | 部署形式相似，配置不互相通用 |

前述是源码与已有协议测试支持的结论；没有声称复刻 Caddy 全平台。更细的部署差异和未实现原因见 [VPS-GUIDE.md](VPS-GUIDE.md)，指纹证据边界见 [FINGERPRINTS.md](FINGERPRINTS.md)。

## 后续代理性能优化

| 热点 | 修改 | 适用范围 |
| --- | --- | --- |
| 每次隧道读写通过 watch 通知空闲检测 | 原子单调时间戳，旧截止时间到达后再检查最新进展 | H2/H3 双向隧道；消除逐块通知、锁和计时器重设 |
| HTTP(S) 下一跳 CONNECT 逐字节读取响应头 | 最大 2 KiB 分块读取，保留成功响应后的二进制前缀 | 减少下一跳握手的 read/SSL_read 调用；仍限总头部 32 KiB、八个响应块 |
| 普通正向请求重复读/解析 CA bundle | HTTPS 首次异步加载并按应用实例共享；HTTP 不加载 | 降低逐请求开销，证书解析不占数据面工作线程；系统根更新需重启 |
| 新 TLS 回归暴露字面 IP 的名称验证问题 | Pingora BoringSSL connector 对 IP 使用 iPAddress SAN 验证 | 正确 IP 证书可用；错误 IP 和不受信任 CA 仍拒绝，DNS 名称路径保留 |

这轮保留全部先前修改，不增加文件或目录；新增测试和三个可重复微基准放在现有 Rust 文件中。Cargo.lock、core Padding/codec、H2/H3 驱动、协议配置、16 KiB 读取、拥塞控制与 Fast Open/0-RTT 策略均未更改。仅在开发依赖开启 Tokio test-util，用虚拟时间验证到期、双向活动及计时器取消；生产构建不依赖该测试功能。Pingora 补丁说明与逐文件摘要随 IP 校验修复同步更新。

微基准包含旧实现的测试内对照，分别测活动时间更新、回环 TCP 响应头读取及热 CA 缓存。它们不等于公网吞吐/端到端延迟，也不测审查识别率或与 Caddy 的性能差距。首次 CA 加载仍需读取解析，HTTPS 下一跳 TLS context 构建、DNS 查询和用户/origin 池淘汰策略未在这轮调整。

## 保留的后续优化点

- 后续性能轮已将通用正向 HTTPS 的 CA bundle 改为按应用实例共享，增加缓存及实际 TLS 校验回归，详情见 VERIFICATION.md。正向 HTTP 仍只选第一个合规 DNS 地址；与 CONNECT 的候选竞速不同，统一候选回退仍待实现和专门验证。
- 配置私有文件检查与打开分两步，依赖受信任的父目录；不是抵御本地管理员恶意换文件的沙箱。固定网站根和状态目录也由管理员控制。
- wildcard 监听时，自身地址列表不是网卡地址全集；域名和明确监听 IP 被拒绝，但别名指向本机公网 IP 的情况需要更完整的本机地址策略。配置中没有因此新增开放内网能力。
- 尚缺真实 Porkbun/GTS 签发、VPS 长期负载、同条件 Caddy 指纹/性能对照。继续保留这些验收边界，不把本地测试当作公网证明。

验证与文件统计见本轮完成后的 VERIFICATION.md。旧 RC2 运行包保持原样，本轮源码快照另存，避免覆盖原验证对应的二进制。

## 2026-10-24 安全增量审查

基线为 dist/performance 的源码快照，另存于工作区 moon-naive-security-baseline。保留前轮原子活动计时、分块 CONNECT 读取、CA 缓存和 IP SAN 修复；未修改 Cargo.lock、Padding 编码或 BBR 策略。本轮针对网络边界加固，不代表已完成整个依赖树的漏洞证明。

| 风险 | 本项目处理 |
| --- | --- |
| H1 请求走私、后端连接被后续请求污染 | 对原始头再次检查严格 CRLF、字段数/字节数、CL/TE；歧义报文以及用 Connection 指定删除认证/转发/报文边界字段的请求均 400 并关闭，不送固定源站；H2/H3 的合法重复长度归一化 |
| 慢速请求头、未完成握手占用配额 | H1 完整头部 10 秒期限、每连接 1,000 请求；H3 Retry 后 TLS 未完成 10 秒回收，异常 accept 不终止全局 UDP 驱动 |
| H2 reset 资源攻击 | 显式保留 50 个本地 reset 状态、20 个待 accept 的远端 reset；128 次库判定协议错误 reset 后 GOAWAY。正常取消不是协议错误；这不是全面的每 IP/每秒限速 |
| 复用连接继承代理认证 | 每条 H2/H3 流重新认证；验证成功后同连接上的无凭据、错误、重复、下划线别名凭据均不授予代理权限 |
| HTTPS 连接池跨身份/信任配置复用 | 固定池 group、正向代理 user/origin 分区；实际 TLS 回归验证同一源站可复用，但错误 SNI、不同 CA、SAN 不匹配而 CN 匹配均不借用可信连接 |
| HTTP/CGI 元数据混淆 | 清除 Proxy/httpoxy、代理凭据、Padding、伪造的转发身份及其下划线别名；H1/H2/H3 与 trailers 一起覆盖，保留网站 Authorization |
| 重放与中间人 | 保留 CA/名称/IP 校验、禁用 0-RTT；验证重复 QUIC 包不重复拨号。Basic 密码泄露后的新会话认证仍需轮换凭据处理 |

### 参考公告与适用关系

- [Pingora GHSA-vx4q-2c55-cvmg](https://github.com/cloudflare/pingora/security/advisories/GHSA-vx4q-2c55-cvmg)：Connection 指定字段可能使下一跳删除受信头，修复于 0.9.0。本项目已在该版本，继续使用 standard 上游头部策略，不启用 preserve。
- [Pingora GHSA-mgg9-6xw2-jfgp](https://github.com/cloudflare/pingora/security/advisories/GHSA-mgg9-6xw2-jfgp)：H2 authority/Host/userinfo 解释不一致，修复于 0.9.0，当前 vendor 已含校验。
- [Pingora GHSA-7gpj-mj4q-x62x](https://github.com/cloudflare/pingora/security/advisories/GHSA-7gpj-mj4q-x62x)：H2 请求头/并发流无界，修复于 0.8.1；本项目外部 H2 与内部 H3→H2 桥已有显式上限。这三个公告的页面发布日期为 2026-10-20；没有将已有修复冒充本轮升级。
- [Node.js 2026-07 公告](https://nodejs.org/en/blog/vulnerability/july-2026-security-releases)：HTTP/2 头部资源耗尽、头截断后转发导致请求不同步、HTTPS Agent 身份与 TLS session 复用问题（包括 CVE-2026-56846、CVE-2026-58044、CVE-2026-56850、CVE-2026-58040）。借鉴其边界检查与池隔离测试；本项目不依赖 Node/nghttp2。
- [Node.js 2025-05 公告](https://nodejs.org/en/blog/vulnerability/may-2025-security-releases)：CVE-2025-23167 的 H1 头结束符差异，作为严格 CRLF 回归的参考；不是声称 Rust 使用 llhttp。
- [PHP 官方 ChangeLog](https://www.php.net/ChangeLog-8.php)：8.5.11 的 TLS SAN 不匹配后回退 CN（CVE-2026-91769）、IPv6 FastCGI ACL（CVE-2026-91768），以及 8.5.12 的 bailout 状态损坏安全修复。本项目无 PHP/CGI/FastCGI 执行器，不能靠反代清理修复后端 PHP 的内存安全/RCE；运行这些后端仍须升级其运行时。额外移除 Proxy 是针对更早的 httpoxy 类风险。

安全功能改变错误流量的处理，不声称模拟特定镜像站的完整指纹。DPI 证据边界见 FINGERPRINTS.md；完整编译、互通与平台检查结果记入 VERIFICATION.md。

## 仅反代网站与作者 Padding 原理（2026-10-24）

本节取代先前“内置静态文件”的架构描述。核对作者 forwardproxy 固定提交 c096d6a00cb28e019cc1995b04bdc6a9311d8024 的 ServeHTTP、dualStream 和 flushingIoCopy：

1. **认证分流**：启用 probe resistance 后，未知/错误凭据请求交给 Caddy 后续 handler，通常是文件网站或反代；不会对所有探测都发 407。网站并非 Padding 的一部分。可选 secret-domain 认证页面会暴露专门的认证行为，本项目不提供它。
2. **CONNECT 响应头**：作者生成 30..61 字节的 Padding，前 16 字符从 `!#$()+<>?@[]^` 加花括号这一 16 字符表抽取，其余为 `~`。随机前缀也影响压缩后的头部长度；并非每个字符都随机。
3. **数据记录**：客户端请求有非空 Padding 时启用 legacy framing。两个方向分别处理最初八条记录：`u16 大端 payload 长度 | u8 padding 长度 | payload | padding`；每条随机选择 0..255 字节填充，作者服务端发送的填充内容是零字节。计数对象是应用记录，不是 IP 包、TLS record 或 H2/H3 DATA frame；传输层可能拆分/合并它们。
4. **作用与边界**：扰动连接初期长度，降低直接依赖内部握手长度的识别效果；八条以后转发原始字节。它不隐藏 SNI，不消除长连接、上下行比例和时序特征，也不等于持续模拟网页请求。TLS 库、分帧和 flush 行为仍形成各自可观察特征。

moon-naive 保留既有 response_header、codec、16 KiB 读取、随机数调用和逐流认证，仍先拨号成功再返回 200，与作者的提前响应时机不同。未为追求所谓伪装任意改变 Padding 长度、数量或添加常驻随机流量。

本次移除生产 ServeDir 文件服务、文件路径/symlink/ETag/静态 Cache-Control 逻辑、site_root/files/static_cache_secs 配置、附带站点文件以及直接 tower-http/tower-service 依赖。上游自身的文件、Range、条件请求、缓存策略原样经反代处理；gzip、固定路由、H1/H2 连接池、SSE/gRPC、1xx/trailers/WebSocket 保留。测试里的临时 HTTP 源站仅用于本地回归，不随程序启动或发布。

生产示例用 `/` 路由指向 `http://127.0.0.1:8080`，需要实际运行源站或改为管理员选定的 HTTPS origin。匹配域名的普通 H1/H2/H3 请求使用同一反代引擎；H1 CONNECT 继续返回普通网站 405，未知 Host/路由 404，源站故障 502，均不开放代理目标。无反代路由时启动预检失败。没有到内置文件的回退。

## 当前记录预算与历史结论的更新

用户随后授权调整 Padding 读取/RNG：前八条下载读取现在预留 3+padding 字节，使单记录不超过 16 KiB；每流预取八个独立随机长度，之后不再执行填充 RNG/编码器。编码格式、填充数量/分布、响应头 Padding 和上传解码保持兼容。此前“16 KiB 原样读取、逐次 RNG 保留”仅描述旧快照，不再描述当前实现。SNI/时序/长连接边界及三类流量矩阵统一见 FINGERPRINTS.md。


---

## 0.2.0-dev.3 验证存档

# 当前验证记录

2026-10-27，0.2.0-dev.3。最终范围为8/16逐流协商、可选稀疏后段、固定长度认证/确认；空闲假流量和反代Padding试验已撤回，代码、配置字段和协议位均未保留。

| 检查 | 本轮结果 |
| --- | --- |
| Rust 1.89，Linux x86_64 musl，workspace Debug测试 | 128通过，0失败，0忽略；7个测试程序，显式执行ignored测试 |
| Clippy workspace/all-targets，`-D warnings` | 通过 |
| cargo fmt / git diff空白检查 | 通过 |
| 源码、vendor哈希和运行依赖审计 | 通过；未新增Go或另一套TLS/QUIC |
| 确定性有限窗口模型soak | 10,000轮通过；不是网络压测 |
| 新模式测试 | 8/16窗口任意输入分片、稀疏额度、密集读块不消耗填充随机数、篡改提议/选择拒绝 |
| 实际H2/H3集成测试 | 每种传输同一外层连接先打开4条不同模式CONNECT，再校验完整320,000字节payload回传 |
| 既有回归测试 | 反代连接池、H1歧义请求、上游HTTP(S)/SOCKS5、半关闭/取消/流控、证书重载、ECH、BBR、Chromium H3发现与回退、Pebble ACME通过 |

测试中的认证字段长度断言已从旧55字节更新至58字节。最终test-artifacts.jsonl含成功build-finished记录和全部7个测试程序；最终日志全部通过。完整报告位于`reports/adaptive-padding/`。

尚未执行：新Chromium代理客户端构建/互通、真实网页分布拟合、DPI分类实验、生产VPS长期负载、公开GTS/Porkbun签发、独立密码协议审计。本轮未重复Release模式的完整测试集或Alpine/Debian/Arch容器平台矩阵；之前版本的相应结果不能当作本版已测结果。不能凭编译和回环测试宣称流量等同网页或无法识别。

开发协议不兼容官方Naïve与旧moon-naive；普通浏览器网站能力继续兼容。未推送、部署或创建新的发布压缩包，已有冻结包保持不变。dev.2协议及验证已归档至HISTORY。

## Release构建与产物

Rust 1.89 x86_64-unknown-linux-musl Release构建通过；最终二进制`target/adaptive-padding/moon-naive`，16383520字节，SHA-256 `f09e7a6d3ff4fab6d1086ec5a63b4f8d0d23f02e0604fd134ce573f48a74e45b`。ELF无INTERP/NEEDED；版本输出为`moon-naive 0.2.0-dev.3 (boringssl/quiche; x86_64-linux-musl)`。实际CLI校验8/16配置通过，12窗口及已撤回idle_cover/website_padding字段拒绝。CLI检查使用本地staging示例，不发起ACME请求。详见`production-smoke.json`。
