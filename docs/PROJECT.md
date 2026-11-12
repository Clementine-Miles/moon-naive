# moon-naive 项目手册

0.7.0，Linux x86_64 服务端。canonical 协议名 **moon-naive**，简称 **mona**；
只实现修订 4，不兼容官方 NaiveProxy。生产客户端留待后续，导入的 Chromium/Android
客户端仍属实验。协议字段与 framing 的唯一权威是 [协议规范](PROTOCOL.md)，
配置字段与默认值以 [config.example.toml](../config.example.toml) 和配置校验为准。

- [运行与配置](#运行与配置)
- [组件与路由](#组件与路由)
- [证书、健康与恢复](#证书健康与恢复)
- [构建、验证和实验](#构建验证和实验)
- [发布与许可证](#发布与许可证)
- [维护与验证记录](#维护与验证记录)

## 运行与配置

构建需要 Rust 1.89+（验证使用 1.94）、C/C++、make、CMake、libclang、Perl、
pkg-config、Git 和系统 CA。BoringSSL 使用原生工具链；普通构建不需要 Go 或 Python 实验依赖。

```sh
cargo build --release --locked -p moon-naive
moon-naive config init /etc/moon-naive/config.toml
moon-naive check-config /etc/moon-naive/config.toml
moon-naive check /etc/moon-naive/config.toml
moon-naive serve /etc/moon-naive/config.toml
```

先创建由服务用户所有的父目录。init 创建 0600 私有配置并拒绝覆盖；填写真实域名、
高熵用户密码、固定网站 origin、DNS 凭据与 CA 联系方式，阅读条款后明确设置
`accept_terms=true`。state_dir 默认 `/var/lib/moon-naive`，权限 0700，必须持久保存。
`check-config` 做结构校验；`check` 做本地预检，不申请证书、不改 DNS、不启动监听器。
`serve` 取得并验证首张证书后监听 TCP/UDP 443，随后自动续期。

域名 A/AAAA 必须指向实际可达地址；不可达 IPv6 不应发布 AAAA。源站不要指回本站，
NAT/无法从接口推导的本机公网地址应显式配置以防自反代。DNS-01 无需开放 80；程序
只管理挑战 TXT，不替操作者管理 A/AAAA、NS 或 CAA。

### 网站、正向代理与下一跳

- `[website].origin` 为单站简写，如 `http://127.0.0.1:8080`；只接受 scheme/主机/端口，
  不接受用户信息、子路径和 query。HTTPS 使用正确 SNI/链验证；不自动改写跳转或 Cookie。
- 多源站使用 `[[website.upstreams]]` 和 `[[website.routes]]`，与 origin 简写互斥。
  路由按最长 path_prefix 匹配；可设置 Host、TLS server name、私有 CA 和 H1/H2 上游。
  配置源站可用私网；访问域名不能临时指定源站。H1 网站默认启用，可按 listener 配置选择。
- 网站保持 WebSocket、流式响应、trailer、Range、SSE/gRPC 和 no-transform 语义。
  H1 framing/Host/Connection 字段严格检查，清除伪造的 forwarded/代理元数据。
- `[proxy.forward]` 独立于网站：默认上传上限 1 GiB、connect 10s、read/write 120s、
  idle pool 30s、每用户同时 32 个请求。旧配置仍可读，但正向代理不再继承网站 body/timeout。
- 普通网站默认上传上限 64 MiB、connect 5s、read/write 30s、upstream idle/DNS TTL 60s。
  这些是数据/连接期限，不要求全量 body 缓冲。重试限额按唯一客户端字节计数；
  已建立 CONNECT 不重放，非幂等且执行状态不确定的请求也不能透明重试。
- CONNECT、普通正向请求和网站 WebSocket 消耗共享额度；认证代理另有每用户限制。
  QUIC 接收信用与应用队列分开计账，已广告的连接信用不会随一条流结束提前归还。
- 出站只拨经过检查的具体解析候选：ASCII DNS 名、显式端口与 bracketed IPv6，
  拒绝私有、特殊、映射私有地址及自连接。配置的固定网站源站使用独立信任策略。
  HTTP/HTTPS/SOCKS5 下一跳保留各自认证/TLS 校验，失败不静默回退直连；
  不通过远端 DNS 绕过本地目标检查。

完整字段和默认值直接修改唯一配置示例；下方仅保留可执行的局部路由示例。
`moon-naive check-transport CONFIG` 可查看实际传输窗口与参数。

### 网站路由示例

用此块替换原 `[website]` 并删除 origin 简写，不能重复追加同名表；本例由 core 测试实际解析。

```toml
[website]
compression_level = 5
[[website.upstreams]]
name = "app"
origins = ["http://127.0.0.1:3000"]
http2 = true
[[website.routes]]
path_prefix = "/api/"
upstream = "app"
strip_prefix = true
```

`/api/users?limit=10` 转为 `/users?limit=10`，不匹配路径返回 404。

### 凭据与迁移

配置可内嵌用户、DNS/EAB 凭据，也可引用私有 TOML 文件；不要把填好密钥的配置提交 Git。
用户密码至少 16 字节，建议独立随机 32 字符以上。上游代理认证与入站 mona 认证是不同用途。
`config migrate OLD NEW` 输出兼容迁移文件，保留原件；私有读取拒绝符号链接最终组件、FIFO、
非私有文件与超大内容，父目录仍须由可信管理员控制。

GTS/Google Public CA 首次注册需要 EAB，Porkbun API 与 Google EAB 是两套凭据。
在已配置项目和权限的管理机执行：

```sh
gcloud services enable publicca.googleapis.com
gcloud publicca external-account-keys create --format=json
moon-naive acme import-eab /private/export.json /private/eab.toml
```

返回 keyId/b64MacKey 对应 key_id/b64_mac_key，保留 base64url 原文。正式/测试 endpoint
与 EAB 必须配套；检查 gcloud endpoint override，勿把 staging EAB 用于 production。
EAB 应在 CA 规定期限内首次使用，账户成功注册后无需每次续期新建账户或新 EAB。
配置启用的 issuer、environment、directory/CA file 决定信任；staging 证书不受浏览器信任，
.dev 的 HSTS 也不会放宽校验。CAA 限制须允许所选 CA；Porkbun 要开启目标 zone 的 API access，
Cloudflare 使用有该 zone TXT 管理权限的 token。委派/CNAME 不支持时按诊断修正，勿清空 journal。

## 组件与路由

### 当前组件与所有权（2026-11-12）

生产交付是一个 Rust `moon-naive` 服务进程。数据面使用 Tokio 多线程异步运行时；
ACME/DNS 控制面在同进程的独立 OS 线程和单线程 Tokio runtime 上运行，避免控制面
网络等待和持久化 fsync 占用数据面线程。它不是多个语言服务之间的 RPC 架构。

| 组件 | 实际职责与边界 |
| --- | --- |
| `core/src` | 配置、每流认证、能力协商、记录编解码、入口分派、目标地址策略；纯 Rust 协议逻辑，不负责拨号或证书 IO |
| `src/net/h2.rs` | TCP/TLS 接入，Pingora H2 session 适配；未协商 H2 时按配置提供 H1 网站入口 |
| `src/net/h3.rs` | UDP/QUIC/H3 接入、quiche 驱动、流状态和传输信用；H3 自带 TLS 1.3 |
| `src/net/mod.rs` | 共享 App、认证后路由决策与准入；并非另一个公网代理服务 |
| `src/net/site` | Pingora 网站/普通正向代理、固定源站池、头部清理、流式响应、压缩与 WebSocket；H3 网站/正向请求通过有界内存 H2 bridge 复用 Pingora，不另开公网 H2 端口 |
| `src/net/tunnel.rs` | mona CONNECT 的双向字节流、填充记录、背压、半关闭与空闲期限；普通网站和 WebSocket 不用该记录格式 |
| `src/net/egress.rs`、`src/resolve.rs` | 有界解析和拨号、具体 IP 候选检查、本机接口检查、HTTP/HTTPS/SOCKS5 下一跳；配置下一跳失败不会静默改为直连 |
| `resources.rs`、`forward_cache.rs` | 全局/用户/连接与缓冲额度；按用户和 origin 隔离的 128 项 LRU、惰性 300 秒 TTL 和单次初始化，初始化不持有全局缓存锁 |
| `src/net/tls.rs`、`src/trust.rs` | BoringSSL TLS/ECH、信任根、不可变 TLS generation；旧连接保留旧代，新代验证后原子替换 |
| `src/acme` | instant-acme 的 JWS/nonce/EAB/订单协议，加 Rust DNS provider、持久 journal、证书安装和私有健康诊断；发布证书、网络加载和写状态文件是不同事实 |
| `src/runtime.rs`、`src/cli.rs` | 启动、readiness、控制线程、SIGTERM 排空、本地配置/证书运维命令 |
| `tools/xtask` | Rust 验证、依赖/源码审计和按提交打包；Rust 独立生成向量并编排实验；Python 仅用于抓包密码验证 |
| `client/naiveproxy` | 导入的 C++/Chromium 与 Kotlin Android 实验客户端，不进入服务端 Cargo 构建；不是已验收的生产客户端 |

### 未认证与已认证流量怎样走

```mermaid
flowchart TD
    U[HTTPS 请求] --> T{入口}
    T -->|H1 网站| W[固定网站策略 / Pingora]
    T -->|H2 / H3| V[HTTP 格式、首部、流额度检查]
    V --> X{网站 extended CONNECT WebSocket?}
    X -->|是，网站域名与路由合法| S[网站 WebSocket / 固定源站 / 共享 tunnel 额度]
    X -->|否| A{当前流 mona 认证有效?}
    A -->|缺失或失败| W
    A -->|有效| R{请求类型}
    R -->|普通 CONNECT| C[用户与全局额度 / 解析 / 具体 IP 策略 / 拨号]
    C --> P[响应认证确认 / mona 双向隧道]
    R -->|普通 HTTP，非本站目标| F[独立 forward 策略 / 用户额度 / Pingora]
    R -->|普通 HTTP，本站目标| W
    W --> O[配置中的源站池]
    F --> E[受限公网候选 / 可选下一跳]
```

- 认证是 **每个 H2/H3 请求流** 的事实，基于真实 TLS exporter、真实 stream ID 和请求上下文；
  同一连接上的后一条流仍须认证。H2 网站可以使用 TLS 1.2，但认证代理要求 TLS 1.3；
  H1 不提供 mona 认证代理入口。标准 ALPN 仍为 h2/h3，没有产品专用 ALPN。
- 缺失、重复、畸形、重放或上下文不匹配的认证不会获得任意出站权限；代理认证首部会被清除，
  然后交给普通网站逻辑。普通网站按本站域名/路径处理，因此结果可能是正常内容、404 或 405，
  并非保证所有错误请求都返回 200。HTTP 语法错误、额度或协议错误也可能先行拒绝。
- 未认证请求可以触发**已配置固定网站源站**的正常解析与连接；不能把请求 authority 当任意拨号目标。
  固定源站允许受信任的私网后端；任意正向/CONNECT 目标使用不同的公网与自连接防护策略，
  对解析出的具体 IP 检查并拨该候选。网站 WebSocket 是公共站点功能，也只通向固定路由。
- 有效普通 CONNECT 在目标拨通后才返回成功与响应证明，随后使用协商的 mona framing。
  有效普通 HTTP(S) 请求若目标非本站，才走独立 `[proxy.forward]` 策略；并非复用网站上传限额。
  有效认证本身不会让本站域名绕开网站配置，也不会取消目标 ACL 或全局/用户额度。
- TLS 终止型 CDN/反代会改变 TLS exporter；不能把客户端的通道绑定认证直接透传为本服务的认证。

### 技术栈比例与 Go 边界

源码比例按 Git 跟踪的 `.rs/.c/.cc/.cpp/.cxx/.h/.hpp/.py/.sh/.kt/.java/.go`
文件物理行数统计（含测试、注释和空行），排除配置、文档、补丁和仓库外源码。
自有服务端 `src/`、`core/src/` 为 Rust；Rust 工具负责实验编排与向量生成。
Python 仅保留独立抓包/密码分析和导入实验客户端的准备脚本。比例不是二进制或 CPU 占比。
详细变更量见本文末尾维护记录。

服务端网络、认证、策略、控制和运维逻辑是 Rust；TLS/密码学刻意使用 **C/C++ BoringSSL**，
并经 Rust boring/tokio-boring 绑定。quiche、Pingora、instant-acme 为 Rust。BoringSSL 与 quiche
完整依赖源码不都在 Git 跟踪树中，故全仓比例不能用来宣称最终程序的原生代码仅占上述比例。
`rustls-pki-types` 用于证书/密钥数据类型，不等于启用 Rustls TLS 后端；native audit 验证所选后端。

**生产运行、普通 Cargo 构建、默认 `cargo test --workspace` 和现有默认 CI 都不依赖 Go。**
唯一有意保留的 Go 相关部分是可选的真实 ACME 实验：仓库外 Pebble/challtestsrv 测试 CA 和
仓库内 129 行 `tools/pebble.patch`，Rust 的 cfg(test) 夹具调用这些外部测试进程。
它们不会链接进或随服务端启动，不是生产 sidecar。构建该 CA 及记录其 Go 构建信息需要 Go。
完整 `cargo xtask lab` 默认包括 Pebble；不使用 Go 时选择普通 workspace 测试或
`cargo xtask lab --only acme`（Rust 合成 CA/provider，抓包分析使用 Python、tcpdump、tshark）。
保留真实 CA 实验有助于发现仅用自有 mock 无法覆盖的状态机问题；无需为避免测试工具的 Go
而新增一套自研 CA。`xtask` 也已有禁止生产构建目录混入 Go 源码/模块的审计。

## 证书、健康与恢复

instant-acme 负责 JWS、nonce/badNonce、EAB 和 ACME 协议；自有 Rust 管理订单、DNS lease、
重试、证书验证、原子安装和网络加载。证书发布、TLS slot 实际加载和 TLS-LOADED 诊断写入
是三个事件；网络每 5 秒检查新代，失败保留旧有效代，已有连接继续持有其 generation。

```sh
moon-naive status CONFIG
moon-naive acme status CONFIG
moon-naive acme check-ca CONFIG
moon-naive acme once CONFIG
moon-naive acme cleanup CONFIG
```

status 本地验证证书并显示到期秒数、绑定 PID/启动时间/boot ID 的续期 worker 心跳、
最后成功/下次尝试/失败阶段/对账需求。TLS-LOADED 可能陈旧，状态文件不能证明新握手已成功，
也不探测监听器。check-ca 只读 directory；once 执行当前计划允许的一次协调，不强制提前续期。
同一 state_dir 不得同时运行 serve 与另一个维护控制器。

DNS 状态区分只读 Preparing、可能已提交的 CreateUncertain、已创建/验证中及删除不确定。
mutation intent 先持久化再发请求；响应丢失后的空查询不能证明没创建。保留 ownership marker、
borrowed record 和外部 TXT，不删除同名全部记录，不用清空 journal 强迫前进。
收到 challenge acknowledgement 后，超时、SIGTERM 或崩溃不代表 CA 不再需要 TXT；
恢复时依据原订单/授权/challenge 判断清理资格，记录消失或被改写需要明确对账。

Retry-After 区分缺失、畸形、可表示和不可表示，不把溢出写成 u64::MAX。
超出本次操作期限的等待持久化并保留同一订单、私钥和 CSR；ARI 重查与订单等待分开，
本地重查间隔不截短远端 not-before，也不阻止证书自身的续期计划。

异常证书诊断仅保存最多 16 KiB prefix、原长度、全量摘要和分类；不把巨大响应序列化进 journal。
永久错误保留原订单调查，future notBefore 等待后复验，obsolete 先持久退役和冷却。
修正材料/信任后，停止旧控制器再执行 `acme retry-certificate CONFIG`。普通续期失败或诊断
失败时，仍有效的已载入身份继续服务；真实持久化不确定则暂停该控制器，重启后保守恢复。
journal v3 含 blocked/retired 信息，降级前必须处理迁移，不能让旧程序丢弃 lease。

### ECH 与关闭

```sh
moon-naive ech init CONFIG
moon-naive ech check CONFIG
moon-naive ech dns CONFIG
```

ECH 使用 BoringSSL，配置 outer public_name、密钥和独立证书；outer 续期由外部运维负责。
init/check/dns 的输出与示例为实际配置依据，不能通过关闭验证恢复 ECH。outer 过期会暂停新
TLS/QUIC 握手，已有连接按 idle/grace 运行；修复后可加载最新 inner 与 outer。

SIGTERM 停止准入并有界排空，默认 graceful_timeout_secs=300；部署单元
[moon-naive.service](../deploy/moon-naive.service) 使用 TimeoutStopSec=360，修改须同步。
保留账户、journal、CURRENT 与证书代供重启/回滚；不得删除不确定 intent。服务使用专用用户、
StateDirectory 与私有权限；不提供公开管理 API。

## 构建、验证和实验

所有公开工具入口统一为 Rust `cargo xtask`：

```sh
cargo xtask vectors --check
cargo test --locked -p moon-naive-core
cargo test --locked --workspace
cargo xtask verify
cargo xtask audit-native
cargo xtask lab --only oracles --run /tmp/mona-oracles-UNIQUE
```

vectors 使用独立 Rust 参考序列化/HMAC 构造，绝不调用生产 auth/codec；与原 Python
生成并已提交的 TSV 必须逐字节一致。--check 不写文件，省略才重新生成。
verify 执行格式、Clippy（警告为错误）、实际工作区测试及 locked release；空 harness 不算回归。
默认测试离线，仅使用 loopback；显式慢速/外部测试必须单独运行，不能把 ignored 计为通过。

实验编排、套件定义、进程组超时清理、基线/原始退出码、证据门槛和归档已移到 Rust xtask。
仅 [tools/analyze.py](../tools/analyze.py) 保留 Python，调用 tshark 并使用独立 cryptography
验证 JWS、CSR、EAB。result.json 是每次实验唯一机器结论，完整原始日志与私有工件留在源码树外。
缺目标场景/抓包、零相关测试/解码结果、decoder/密码校验失败和未执行的验证均失败；
即便索引成功也不能覆盖原 Rust 测试退出码。oracles 包含这些反例。

```sh
cargo xtask lab --only acme --run /tmp/mona-acme-UNIQUE \
  --tcpdump /path/to/tcpdump --tshark /path/to/tshark \
  --python /path/to/python-with-cryptography
cargo xtask lab --only pebble --run /tmp/mona-pebble-UNIQUE \
  --pebble /path/to/pebble --challtestsrv /path/to/pebble-challtestsrv \
  --pebble-source /path/to/pebble-checkout --python /path/to/python
```

路径可通过旧环境变量/--home 提供；显式选项优先。run 目录必须全新且在源码树外。
实验依赖 Linux 用户/网络 namespace、iproute2、tcpdump、tshark 与 Python cryptography；
Rust runner 不依赖 Python argparse/编排模块。完整 lab 默认含 workspace、Pebble、vendor、
系统 resolver 和证据 oracles；--only 也可选 ari/network/resolver/vendor。

Pebble 固定 `d52948ce25e7c1576bcd18ff0e20a1c24ec7c44b`，在外部 checkout 应用
[测试补丁](../tools/pebble.patch)，用其要求的 Go 构建 `./cmd/pebble` 与 `./cmd/pebble-challtestsrv`。
Go 源码和二进制不放入产品仓库。已有测试二进制可直接提供；无 Go 时基线记录构建信息不可用，
仍保留二进制摘要，不跳过协议/密码验证。实验不需要公网 DNS 凭据或生产签发。

性能显式运行：

```sh
cargo test --release --locked -p moon-naive --lib benchmark_h3_receive_windows \
  -- --ignored --nocapture --test-threads=1
```

真实 QUIC 经过有界 UDP relay，128 KiB/流、1/8 并发，0/20/80ms 延迟与每 100 个 datagram
确定性丢包。此前一轮单样本：20ms/单流，cap100/4587B 为 0.9481 Mbps，cap32/14336B 为
4.5677 Mbps；8 流分别 6.4883/14.5771 Mbps。CPU/RSS 含服务端、客户端、relay，不能当独立
服务端或持续吞吐证明。默认窗口未据此放大，不提前返还不可逆 QUIC 信用；完整原始结果在 Git 历史。

## 发布与许可证

```sh
cargo xtask check-elf /path/to/validated-musl-binary
cargo xtask dist /path/to/validated-musl-binary /outside/dist
cargo xtask source /outside/source HEAD
```

dist/check-elf 当前要求 x86_64-linux-musl 静态包；普通 glibc 构建不能冒充该发行目标，
新增/未执行目标的运行验证不能由编译推导。source 解析显式 Git 提交，拒绝 tracked dirty、符号链接/submodule，只从该提交打包，
不包含任意 untracked 配置/密钥/工件，保留 executable 位并记录 SOURCE_REVISION。
检查归档内容和 SHA256SUMS；摘要证明快照完整性，不证明运行正确性或独立真实性。
发布、生产部署、CA/DNS 变更与 merge 需对应授权。

依赖 pin：Pingora `4487f7b2`、quiche `925b2258`、instant-acme `4a9b80fd`；BoringSSL
binding boring/boring-sys 5.2.0。精确 rev 在 Cargo.toml/lock；生产 feature 禁用额外 TLS 后端。
定制行为与出处见 [Pingora 补丁记录](../vendor/pingora/MOON-NAIVE-PATCHES.md) 和
[instant-acme 补丁记录](../vendor/instant-acme/MOON-PATCH.md)，修改 vendor 时更新其摘要。

项目 Apache-2.0，原文见 [LICENSE](../LICENSE)。release inventory 列出 normal/build 依赖、
版本与可获得的上游许可；构建工具可能也列入，不等于其代码都在最终二进制内。
[licenses](../licenses) 保留原始法律文本，不因减少文件数而合并或删节：
musl v1.2.5 COPYRIGHT 来自 tagged ifduyue/musl mirror；GCC 14/libstdc++ 与 runtime exception
来自 Debian GCC copyright，GPL-3.0 原文配套保留；Rust 1.89.0 的 MIT/COPYRIGHT 配套保留，
其 Apache-2.0 使用根 LICENSE。例外不改变本项目许可证。

## 维护与验证记录

历史审阅与失败尝试保留在 Git 中，不作为当前成功证据。d0f6a082 之后的主要合并：
eab→account、state/store→persist、outbound→egress、site forward→upstream、
generation→bridge；共享 resolver 在 crate root，Manager 本地 bundle 与网络共享 TLS generation 分开。
保留纯 core、H2/H3 adapter、资源账本、framing 和 crypto 边界。

- `1379712`、`da8ed48`：恢复实际测试、独立向量、H3 不完整首部期限、retry body accounting、
  独立 forward 策略/额度/LRU、私有健康、TXT 对账与提交源码打包。
- `055d8bc`、`c4004b7`：修正 ARI 等待被截短、本机接口快照、特殊 IP、恢复路径 panic，
  去除远端错误原文日志；重载与诊断写入分离。既有 C++ 只 offer 0x02 时服务端也只选 0x02，
  并无偏好模式互通缺陷。
- `a5a6207`：真实 Pebble 7/7，7 抓包、103 JWS、1 EAB 验证，零错误。先前 Rust 合成
  ACME 89/89，58 抓包、213 JWS；这些是受控测试，不是公网 CA 结果。
- `0b9fbc7`：work 快进到 main；core 31+2 与 native audit 重跑通过。之前 workspace
  206 server+31 core+2 vectors+1 packaging、Clippy、Linux locked release、MSRV 1.89 check
  和 9 个真实 TLS 激活测试通过，不能把这些历史结果写成每次变更都已重跑。

私有历史工件在 `/workspace/scratch/mona-refactor-acme-final`（bundle SHA256
`e49afc3fed79f6d3ab68ad750054659f76b91d95c2852ad199ce4e7809b603cf`）、
`/workspace/scratch/mona-next-pebble`（`fc1ab421874fec9efd225118d67af0fc374eee991636ab0414077642d34aefcc`）。
失败的缺 crypto、错误 oracle/非零退出码也保留，不由新索引改成成功。
环境外路径可能随会话清理；工件未提交 Git，也未上传密钥/原始 journal。

尚未完成：详细错误分类、全部资源/用户公平性压力矩阵、长时性能与生产部署验收。
测试客户端不是生产客户端；未验证的 DPI、流量不可识别性或“censorship-proof”不作宣称。
### 2026-11-12：Python 与文档收敛

基线 `0b9fbc7`，初始工作区干净。实验 runner 与参考向量生成移到 Rust xtask，
删除 tools/acme-lab/run.py、tools/vectors/generate.py；分析器移为 tools/analyze.py，
测试补丁移为 tools/pebble.patch，删除两个空工具目录。客户端 prepare.py 不在本轮迁移范围。
Rust 参考实现没有依赖生产 core，原 Python TSV 保持逐字节一致；只增加已锁定包的 xtask
直接依赖/feature，未升级依赖版本或改变生产协议。Rust 源码行数增加，不将语言迁移冒充代码行减少。

README 只留入口，IMPLEMENTATION 和许可证导读并入本手册，协议仍独立作为权威。
第三方 README、许可/版权原文不删节；dist 同时收录手册和协议，避免归档后的协议引用失效。
按 Git 跟踪文件和原始物理行统计：总文件 418→415；自有工具 Python 3/525→1/249（减少52.6%），
含实验客户端为 4/621→2/345。自有说明文档（根 README、docs/*.md、许可证导读）5→3，
合计1586→572行（减少63.9%）；第三方许可和文档不计入该减量口径。

实际执行：`cargo xtask vectors --check`、xtask 4 个测试（含真实退出101、进程组超时和
4 个 Python decoder 反例）、Rust lab oracles、真实 Pebble 7/7（7抓包、103 JWS、1 EAB），
ARI 3/3（3抓包、12 JWS），路径名形式的 tcpdump/tshark 发现也通过。
Clippy workspace/xtask warnings denied、native audit、Rust1.89 xtask check、locked Linux release、
Python py_compile 与文档本地链接/锚点检查通过。完整工作区206 server+31 core+2 vectors+4 xtask通过，16项ignored不计入通过。
首轮工作区暴露被省去的可执行路由示例，恢复精简示例后 core31+2通过；原测试未削弱，
失败日志保留在忽略的 work/python-migration/ 中。生产网络逻辑无更改。
新的私有 result.json 在 /workspace/scratch/rust-lab-{pebble,path-ari,oracles-final}/，
零相关结果和缺失密码验证仍不能通过。不上传原始抓包、密钥或 journal。
