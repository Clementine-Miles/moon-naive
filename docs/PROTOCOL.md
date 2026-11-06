# 协议与架构

当前版本 **0.7.0**，认证域与 exporter 使用修订4。**不产生空闲假流量，不为真实反代添加Padding首部或改写正文**。采用认证协商的8/16条初期窗口，可选低比例后段填充。旧moon-naive和官方Naïve客户端不兼容；新的Chromium客户端尚待实现。

## 路由与连接

H1始终进入固定网站反代；H2/H3逐请求验证认证，失败同样进入固定网站，不发407，不拨请求中的任意目标。畸形HTTP请求在解析/校验阶段拒绝。成功认证CONNECT依次经过目标语法、ACL、额度、DNS和拨号检查，拨通后才返回200。认证普通HTTP正向代理由Pingora转发；网站WebSocket使用标准升级路径，都不插入隧道记录。

一个CONNECT对应一个目标TCP连接；多个CONNECT在同一个H2/H3外层连接上复用。每个目标TCP连接独立保持字节流、背压和半关闭，不能把不同网站目标TCP连接合并成一条。网页、TCP连接、CONNECT流并非一一对应。

服务器不主动新增外层连接，不发假请求/假CONNECT，也不为每条应用记录重新拨号。H2共享TCP拥塞控制和队头阻塞；H3使用独立QUIC流与quiche拥塞控制。Pingora网站上游连接池继续复用同一源站的可复用连接；来源/认证隔离、响应完整性和池上限不能为了减少连接而取消。新Chromium客户端应复用已有外层会话，达到流上限才按调度需要扩容，不按标签页新建代理TLS连接。

默认隧道任一方向实际进展更新600秒空闲期限。上传FIN只关闭目标写方向，下载可继续；reset、错误、空闲超时取消任务并释放额度。关闭的目标TCP不能由服务端透明“接续”，重新请求需要新的CONNECT；外层连接仍可复用，若外层也关闭则重新握手和认证。网站连接池另有自己的上游空闲期限。

## CONNECT首部和认证协商

代理仅允许完成TLS1.3握手后的H2/H3；保留标准TLS加密，禁用0-RTT、代理Fast Open和TCP Fast Open。H1及TLS1.2 H2只服务网站。

1. 从实际外层连接取得32字节exporter：label=`EXPORTER-moon-naive-v4`，context显式空串；不得使用early exporter。使用实际HTTP流ID，不按CONNECT次数推算。
2. `key=SHA256(b"moon-naive/v4/key\0" || UTF8(user) || b":" || UTF8(password))`。共享秘密应为高熵值，SHA256不是口令拉伸。
3. 请求转录=`b"moon-naive/v4/request\0" || exporter || u64be(stream_id) || offer_byte || 0x00 || fields`。
4. fields依次method、authority、scheme、path-and-query、protocol；存在字段=`u64be(UTF8字节数)||UTF8值`，缺失=8个0xff。普通CONNECT后三项缺失。使用线上实际值，不改变大小写、端口或编码。
5. MAC=`HMAC-SHA256(key,SHA256(转录))`；使用标准带`=`Base64。提议用两位小写十六进制，整个认证字段值固定58字节。

```text
:method: CONNECT
:authority: example.org:443
proxy-authorization: moon-naive 07.<44字节Base64证明>
```

仅需要普通CONNECT伪首部和唯一认证字段，不追加随机Padding、FastOpen、旧Padding-Type-*或多余Host。客户端应使用Chromium实际HTTP栈，认证字段须never-index，避免人为捏造不一致的浏览器首部。

| 位 | 含义 |
| --- | --- |
| 0x01 | 支持8条初期窗口 |
| 0x02 | 支持16条初期窗口 |
| 0x04 | 支持后段稀疏填充及持续记录边界 |

至少提供一个窗口，未知位拒绝。提议03=两种有限窗口，07=两种窗口并允许稀疏后段。服务端优先配置中的窗口，否则选客户端提供的另一种；只有双方允许才选稀疏。选择中8/16位只能有一个：01、02、05、06分别对应8有限、16有限、8稀疏、16稀疏。同一连接不同流可以并存；不会为同一payload重复套8和16两层填充。双向使用同一选择，但计数与额度独立。

```text
:status: 200
proxy-authentication-info: moon-naive 06.<44字节Base64证明>
date: <正常HTTP日期>
```

成功响应无假正文、随机Padding首部或Server版本标识。响应MAC使用域`b"moon-naive/v4/response/200\0"`，选项字节为`原offer_byte || selected_byte`，其余字段同请求。客户端核验200、字段唯一性、选择属于提议、MAC正确之后才发送目标数据。连接、流、目标、提议或选择变化均会改变证明，请求证明不能反射为响应证明。HPACK/QPACK的编码长度仍会变化，固定58字节字段不等于固定包长。

API为`authorization_with`/`verify_selection`；便利接口`authorization()`只提议02有限模式。没有连接级永久登录、时间戳重放窗口或nonce缓存。底层网络密文重放仍由TLS/QUIC处理，以上证明不替代证书验证。

## 数据记录与预算

```text
u16be N | u8 P | N字节真实payload | P字节零填充
```

`1≤N≤16309`。空记录、控制/假流量记录、超量填充、截断记录均不接受。上传解码借用HTTP输入切片，仅将payload写到目标；下载直接读入BytesMut，在同一存储中编码并转移Bytes所有权。记录与HTTP DATA、TLS record、QUIC包不是同一边界，允许任意分片和合并。

| 阶段 | Padding上限 | 服务端实际发送策略 |
| --- | --- | --- |
| 前8条 | P≤min(floor(N/8),63−8i)，i=0..7 | 小读块在0..上限采样；N≥8192时P=0 |
| 前16条 | P≤min(floor(N/8),63−4i)，i=0..15 | 同上 |
| 有限模式后段 | 无记录头和padding | 精确切换后直接透传，不再调用填充RNG |
| 稀疏模式后段 | N<8192时P≤min(31,floor(N/32),可用额度)；否则P=0 | 有额度的小块以1/16概率尝试，结果可为0；大块不填充、不调用填充RNG |

初期最坏额外开销：8条≤304字节/方向，16条≤576字节/方向，均含记录头。小块的padding≤payload/8不表示包含记录头的总开销也≤12.5%。后段每128字节真实payload赚取1字节padding额度，余额最多128字节，保留除法余数、没有初始赠送；收发双方校验。初期padding由单独的有限上限约束。数据记录头的3字节不计入此padding额度。

稀疏模式持续保留3字节头来解析后续数据，不是全程附加填充。大块头开销约0.0184%，小块相对开销更高，不能宣称总开销恒低于1%。有限模式在第8/16条padding完全消费后释放解析状态；同一输入中的后续裸字节仍须原样保留。

服务端有限模式原始阶段每次最多读取16375字节，为H2 DATA头保留9字节TLS写入空间；这是实现选择，不是解码边界或客户端约束。

不随机拆分读块，不引入随机延迟，不等待凑满读块，不添加结束标记或额外小尾记录。满载时优先数据吞吐；低流量时仅对实际数据附加小额扰动。零填充用于减少无意义的随机内容生成；TLS密文本身仍然高熵，不能将零填充宣传为降低线上密文熵。

## 真实网站与配置

反代正文、正常首部、ETag、Range、压缩、SSE/gRPC和WebSocket维持既有行为。本轮撤回试验中的反代Padding首部和空闲假流量，没有保留可开启它们的配置/协商位，也不让填充成为目标业务内容。

在现有唯一config.toml中可增加：

```toml
[traffic]
initial_records = 16 # 8或16，服务端选择偏好
sparse_padding = true # 客户端也提议0x04才生效
```

以上为缺省值；设sparse_padding=false可仅使用有限模式。所有填充只在成功协商的CONNECT内应用。无需分散创建额外TOML。旧客户端不会因配置变更自动兼容。

## 外部包组成与限制

H2：`IP / TCP / 外层TLS记录{HTTP/2 DATA头(9B) + 应用流片段} / AEAD标签`。

H3：`IP / UDP / QUIC包{STREAM帧 + HTTP/3 DATA帧 + 应用流片段} / AEAD标签`。H3应用数据没有额外TLS record封装，TLS用于QUIC握手。CONNECT传递目标TCP的payload，不携带目标IP/TCP包头；内层HTTPS的payload可能本身是TLS记录。

MAC只位于请求/确认首部，应用记录没有新的自制加密或逐记录MAC。目标TCP的原始字节经去填充后完整恢复。物理包长还受MTU、ACK、拥塞控制、窗口、重传和其他流复用影响；应用层参数不能精确指定每个线上包的大小和时序。

此策略没有网页抓包分布拟合或DPI识别率测试依据，不能承诺等同真实网页。保留真实反代、自然读写时序和现有连接复用，避免加入新的定时假流量模式。ECH不隐藏IP/外层公开名称/长度/时序，也不消除TLS-in-TLS。BoringSSL服务端不等于Chromium浏览器栈。

## 实现位置和客户端后续工作

认证协商在core/src/auth.rs，预算与借用解码在core/src/codec.rs，采样/缓冲/空闲期限在src/net/tunnel.rs，H2/H3适配分别使用Pingora/quiche。没有新增运行依赖或Go栈。

客户端应保留Chromium证书策略、TLS/H2/H3栈，在实际分配流ID后签名，验证协商后初始化双向codec；复用外层会话，禁止H1代理回退、0-RTT和Fast Open。验证范围见[VERIFICATION.md](VERIFICATION.md)。


## 服务端架构

0.7.0 由根包构建 moon-naive；core 提供协议与配置逻辑，tools/xtask 提供构建及发布工具。运行时只需服务端程序、配置、持久化状态和所需系统信任根。

### 生命周期

CLI 先校验配置、用户、网站和传输条件。ACME 控制面运行在独立线程的 Tokio runtime，避免 DNS、日志写入和 fsync 占用数据面线程。没有有效证书时等待 DNS-01 签发，验证、安装后绑定 TCP/UDP，并通知 systemd 就绪。

账户操作使用 instant-acme；Porkbun/Cloudflare 适配器管理 TXT，日志记录未完成操作。证书经 SAN、私钥、链、有效期等检查后写入 generation，原子更新 CURRENT。续期失败保留仍有效的证书；轮换后新连接使用新上下文，已有连接继续。

SIGTERM/SIGINT 停止接入并排空连接，随后限时清理本进程拥有的 TXT。状态使用单写锁；升级时应保留整个 state_dir。

### 请求路径

- TCP：BoringSSL 处理 TLS；H1 提供网站，Pingora H2 支持网站与认证代理。
- UDP：quiche 处理 QUIC/H3；网站通过有界内存 H2 桥进入同一 Pingora 引擎。
- 代理仅在 TLS 1.3 H2/H3 上启用。每条请求绑定 exporter、流 ID 和请求字段验证；CONNECT 经 ACL、预算和目标拨号后才返回 200 与响应证明。
- 未认证请求进入固定网站路由；固定网站与任意目标正向代理使用不同的路由、元数据和连接池隔离规则。

实现见[网络入口](../src/net/mod.rs)、[网站引擎](../src/net/site/mod.rs)及[内存桥](../src/net/site/bridge.rs)。认证和记录格式以[协议](PROTOCOL.md)为准。

### 连接与资源

每条 CONNECT 对应一条目标 TCP 连接，外层 H2/H3 连接可以复用。隧道保留背压、半关闭、取消和额度释放；任一方向实际进展更新空闲期限，默认 600 秒。

网站支持固定源站池、最长前缀路由、gzip、SSE/gRPC、trailers 和固定路由 WebSocket。HTTPS 回源校验证书及名称；安全方法的建连失败可有限回退，不重放 POST。正向出站先检查 DNS/IP ACL，可使用一个 HTTP、HTTPS 或 SOCKS5 下一跳，失败不回退直连。

连接/流窗口和共享接收预算约束内存，接收预算不等于 RSS 上限。TCP 拥塞由内核处理，QUIC 拥塞由 quiche 处理；Linux timerfd 为 QUIC 提供发送期限等待，UDP 阻塞时等待可写。

### 依赖与边界

TLS 共用 BoringSSL；quiche 使用 boring crate 后端。gzip 由 Rust miniz_oxide 处理。源码打包、SHA-256 和 ELF 检查由 tools/xtask 的 Rust 库完成；首次 BoringSSL 构建仍需要原生工具链。

固定 Pingora 与 instant-acme 补丁随 vendor 提供并校验；后者仅增加使用持久化私钥和 EAB 注册的接口，复用上游协议实现。

不提供管理 API、动态任意网站路由、多 SAN 自动证书、分布式状态或多 CA 自动切换。ECH 为实验性功能。配置详见[配置指南](CONFIGURATION.md)，未验收范围见[验证记录](VERIFICATION.md)，网络可观察性见[可观察性与兼容性](#可观察性与兼容性)。


### 恢复边界

H3 内存桥使用可替换代际。任一驱动退出会通知当前交换失败；后续请求经有界、单次构建及冷却后获得新桥。不会重放应用请求。DATA 长度在进入共享 H2 连接前检查，长度不符只重置该流。

CONNECT、HTTP 转发及固定网站源站复用有界 TCP 候选拨号，最多同时尝试两个地址。固定源站允许显式配置的私网地址，任意转发目标仍应用公共目标策略。源站选择与其地址回退分开；固定源站在 HTTP 发送前可推进 TCP/TLS 候选，并把 DNS、建连和会话初始化纳入连接期限；已发送的应用请求不隐式重放。

上述改动没有完成控制面进程隔离、双身份自动证书管理、原子多路径激活或认证容量预留。当前真实实现及验收差距见[实施报告](VERIFICATION.md#安全实施记录)。


## 项目结构

0.7.0 使用一个 Cargo workspace 和锁文件，共三个包：moon-naive、moon-naive-core、xtask。

| 路径 | 职责 |
| --- | --- |
| [src](../src/) | 服务端 CLI、运行时、证书控制面及网络入口 |
| [src/acme/account.rs](../src/acme/account.rs) | instant-acme 账户创建、恢复及 EAB 导入/注册 |
| [src/acme/manager.rs](../src/acme/manager.rs) | DNS-01 订单、续期、退避及恢复 |
| [src/acme/persist.rs](../src/acme/persist.rs) | 日志、私有权限、证书 generation 和 CURRENT |
| [src/net](../src/net/) | TLS、H2/H3、隧道、ACL 拨号及固定下一跳 |
| [src/net/site](../src/net/site/) | 共用 Pingora 网站/正向代理、上游池和 WebSocket |
| [core/src](../core/src/) | 配置、认证、记录 codec、准入及额度策略 |
| [tools/xtask](../tools/xtask/) | Rust 审计、构建检查及发布打包 |
| [deploy](../deploy/) | systemd、OpenRC 和可选 musl 构建镜像 |
| [config.example.toml](../config.example.toml) | 唯一运行配置模板，config init 内嵌同一文件 |
| [assets](../assets/) | 对应内置 staging CA 的公开根证书 |
| [vendor/pingora](../vendor/pingora/) | 固定 Pingora 源码、补丁和校验清单 |
| [vendor/instant-acme](../vendor/instant-acme/) | 固定 instant-acme 源码及持久化私钥注册接口补丁 |
| [licenses](../licenses/) | 第三方许可文本 |
| [docs](./) | 使用、设计、限制与历史摘要 |

第一方单元、传输及隔离 ACME 测试已恢复；`tests/` 保存 CLI 和 Pebble 集成测试。HANDOFF 和外部抓包工具未恢复。vendor 中的公开测试夹具属于受校验的上游快照，不能直接清理。target、reports、dist 为生成目录，不属于运行依赖。

构建入口见[工具说明](../tools/README.md)。

## 可观察性与兼容性

BoringSSL、Pingora、quiche 的组合不代表浏览器指纹，也不证明更难识别。TLS/QUIC 握手、SNI、ALPN、HTTP 设置、包长、方向和时序仍可被观察；认证和填充不能消除 TLS-in-TLS、关联或长度信号。ECH 不隐藏 IP、公开名称、长度或时序，证书及 DNS 发布边界见[配置](CONFIGURATION.md#ech)。

本项目不兼容官方 NaïveProxy 客户端，未实现 REALITY 的目标站握手校准。AnyTLS 等协议的历史对照不代表当前上游漏洞状态，也不能用于推导本项目的安全性或识别率。桥接上传失败、最终响应、半关闭和取消分别处理；固定网站可携带服务端生成的转发元数据，任意目标正向代理清理身份字段及 Via，动态压缩尊重 no-transform。

旧抓包数据保留在 [packet-lab-results.json](packet-lab-results.json)，仅供追溯；未完成真实 Chromium 客户端或公网 DPI 验收。验证结果见[验证记录](VERIFICATION.md)。
