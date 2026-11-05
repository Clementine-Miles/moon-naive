# moon-naive 协议和隧道方案

当前版本 **0.6.0**，内部认证域/exporter修订为4，与dev.3线格式相同。根据最新取舍，**不产生空闲假流量，不为真实反代添加Padding首部或改写正文**。采用认证协商的8/16条初期窗口，可选低比例后段填充。旧moon-naive和官方Naïve客户端不兼容；新的Chromium客户端尚待实现。

## 路由与连接

H1始终进入固定网站反代；H2/H3逐请求验证认证，失败同样进入固定网站，不发407，不拨请求中的任意目标。畸形HTTP请求在解析/校验阶段拒绝。成功认证CONNECT依次经过目标语法、ACL、额度、DNS和拨号检查，拨通后才返回200。认证普通HTTP正向代理由Pingora转发；网站WebSocket使用标准升级路径，都不插入隧道记录。

一个CONNECT对应一个目标TCP连接；多个CONNECT在同一个H2/H3外层连接上复用。当前测试同时打开4个采用不同窗口/填充方案的CONNECT，使用同一外层连接。每个目标TCP连接独立保持字节流、背压和半关闭，不能把不同网站目标TCP连接合并成一条。网页、TCP连接、CONNECT流并非一一对应。

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

认证协商在core/src/auth.rs，预算与借用解码在core/src/codec.rs，采样/缓冲/空闲期限在src/net/tunnel.rs，H2/H3适配分别使用Pingora/quiche。没有新增运行依赖或Go栈。保留ripgrep式借用切片/缓冲复用。

客户端应保留Chromium证书策略、TLS/H2/H3栈，在实际分配流ID后签名，验证协商后初始化双向codec；复用外层会话，禁止H1代理回退、0-RTT和Fast Open。原客户端源码基线v154.0.8037.49-5仍在/workspace/naiveproxy-client-upstream，本轮未构建或修改Chromium客户端。验证范围见[VERIFICATION.md](VERIFICATION.md)。

## 已知问题的证据与边界

客户端基线是官方最新稳定标签 `v154.0.8037.49-5`，提交 `d04efe1ea4477c2db24a7d0e2f068b3bee931e45`，Chromium `154.0.8037.49`。服务端对照已从作者 forwardproxy `c096d6a00cb28e019cc1995b04bdc6a9311d8024` 补查至最新标签 `v2.11.7-naive2`（`e747854e78743dba85c039b38ed185fb11d93667`）；原研究工作树保持不变。不能由此宣称审查了所有 Caddy、Go 或插件版本。

| 对象 | 已确认或由源码直接得出的限制 | 本轮处理／仍有限制 |
| --- | --- | --- |
| 客户端证书信任 | 2026-10-22 官方发布说明明确：旧版无法安全抵御使用伪造 eMudhra 证书的 MitM。修复提交 `23953c90e3b9f08f8d0c6ede92ae35f357af6f73` 给 `cert_verify_proc_blocklist.inc` 增加 8 个被阻止的 SPKI | 新拉取源码含修复。不能说最新版仍有这个已修复问题；系统根更新也不能替代客户端 blocklist／撤销策略更新 |
| 双端 Padding | 官方每方向只填前 8 条应用记录，u16 数据长度 + u8 填充长度，0..255 填充；之后裸流。不能掩盖全部长度、突发、方向、长连接和关联特征 | moon-naive支持认证协商的8/16初期窗口及可选稀疏后段；接收端检查填充预算；没有证明 DPI 识别率下降 |
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


