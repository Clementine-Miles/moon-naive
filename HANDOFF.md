# moon-naive：接手 Agent 工作说明

交接日期：2026-11-04。当前版本：0.6.0，协议修订4。

## 先读与工作原则

先阅读本文件、README.md、docs/PROTOCOL.md、docs/ARCHITECTURE.md、docs/VERIFICATION.md、docs/FINGERPRINTS.md，再检查源码与实际测试结果。用户需要 Rust 编写的代理服务端，网站能力仅保留真实固定源站反向代理，以自然网站行为和性能为目标；未来客户端会基于 Chromium 网络栈另行开发。

当前工作区包含大量尚未提交的历史重构，删除旧 crates/、迁移到 src/ 和 core/ 等均是既有成果。请保留，不要 git reset/clean 或从 Git HEAD 恢复旧文件。源码包不含 Git 历史，因此解包后请先自行建立版本基线。版本号相同不代表内容等同此前的 dev.4 包。

优先完成可验证的改进，不承诺规避真实审查系统。普通镜像响应与 CONNECT 的语义不同，不能用虚假正文、Content-Length 或 ETag 污染成功隧道。不要为了迎合分类器反向调整其阈值。

## 目录与入口

- src/：服务端库、CLI、生命周期；src/acme/ 管理 ACME、DNS、证书存储及续期。
- src/net/：TLS、H2/H3、隧道、认证准入和出站；site/ 是 Pingora 网站反代及正向 HTTP 代理。
- core/：TOML 配置、认证、codec、ACL 与资源预算。
- xtask/：依赖及 vendor 审计、测试辅助、Rust 实现的源码/发布包生成。
- vendor/pingora/：固定版本与已有补丁，修改前阅读校验清单和来源信息。
- tests/：CLI、Pebble 集成测试；网络回归位于 src/net/tests/。
- tools/packet-lab/：可选抓包及 OpenGFW 离线测试工具，含 Python 和独立 Go 适配器，不参与服务端构建。
- deploy/：systemd、OpenRC 和 musl 构建环境；根目录 config.example.toml 是唯一配置示例。
- docs/：架构、协议、统一配置/ACME、VPS构建/发布/服务端差异及验证范围。

无需恢复原来的重复目录或静态文件服务。完整文件说明见 docs/PROJECT-FILES.md。

## 用户约束

生产网络栈保留 BoringSSL、quiche、Pingora；不引入 Go 服务端、rustls/Quinn 平行栈。BoringSSL 本身含 C/C++，不能称为纯 Rust 全栈。

默认端口443；H1仅走网站/固定路由，不开放任意目标代理。TLS1.3上的已认证H2/H3支持CONNECT及通用HTTP(S)正向请求；未认证流量进入共同网站处理。成功CONNECT须先完成目标拨号，再返回200；保留逐流认证与响应证明。严禁Fast Open及0-RTT。HTTP(S)/SOCKS5下一跳失败不自动回退直连。

配置尽量集中到单一TOML。用户域名服务商为Porkbun，后缀.dev，偏好GTS证书；需要真实的ACME自动签发/续期，不得把本地Pebble通过当作公网签发验收。

不添加空闲假流量，不随机改写反代内容，不全程大量填充。支持协商前8或16条有限填充及可选稀疏后段；大块优先性能。TLS密文高熵是加密性质，不能声称零填充降低线上密文熵。

目标平台为Linux x86_64，尤其Alpine、Debian、Arch；TCP BBR依赖内核，quiche使用BBRv2。不要把两者混为同一种实现。

## 最近已经完成的改动

1. src/net/h2.rs 中的有界16KiB写缓冲合并已提交的切片，按正常flush发送。修复底层vectored write仅处理首切片造成的273字节TLS记录重复；保留Pending重试指针及部分写入语义。
2. src/net/site/mod.rs 保留有明确Content-Length的H1镜像响应，仅未知长度恢复chunked。真正压缩时交由Pingora更新分帧；新增同连接固定长度、gzip、Range、流、HEAD、304、204回归。
3. src/net/tunnel.rs 原始阶段读取上限为16375字节，给H2的9字节DATA头预留TLS写空间；不等待凑满、不改变payload。编码阶段的MAX_PAYLOAD仍为16309。
4. H3成功响应Date复用Pingora按秒缓存。
5. 抓包夹具覆盖32流突发、预热H2回源复用、多次空闲及连续大文件。工具迁入tools/，以保持生产构建输入无Go代码的审计。

## 协议要点

请求和响应使用moon-naive修订4证明，绑定TLS1.3 exporter、实际流ID、请求字段及协商选项。字段值加密前为58字符，不等于固定包长；H2响应证明never-index。请直接阅读core/src/auth.rs和协议文档，勿自行删除或弱化HMAC。

记录格式为u16BE payload长度、u8 padding长度、payload、零padding。有限模式在8/16条后转原始流；稀疏模式保留记录解析。无结束假帧。完整限制、预算及模式位以core/src/codec.rs和docs/PROTOCOL.md为准。

## 构建与验证

常规环境需要Rust1.89+、C/C++、CMake、libclang、Perl、pkg-config等原生依赖，详见docs/VPS-GUIDE.md及deploy/Dockerfile.musl。

```sh
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --locked -p moon-naive -p xtask
cargo run --release --locked -p xtask -- source dist/handoff-source
```

源码打包命令依赖git ls-files收集文件。无Git元数据的解包副本应先git init并建立基线，确认.gitignore排除了密钥、state、target、dist、reports以及实验输出。

显式ignored测试需要外部程序与环境变量，包括CHROMIUM_BIN、NAIVE_BIN、PEBBLE_BIN、CHALLTESTSRV_BIN、PEBBLE_SOURCE；不具备它们时不能声称完整外部验收。抓包另见tools/packet-lab/README.md，该脚本依赖特定本地Docker实验容器布局，迁移机器后需准备对应环境。不要同时运行多个抓包驱动，它们共用18443。

交接环境曾使用/workspace/naive-pingora-resume/moon-naive、Alpine容器moon-naive-musl-builder及/tmp/moon-cargo辅助脚本；这些不是项目运行依赖，也不保证新Agent环境仍存在。不要依赖交接机绝对路径构建产品。

## 2026-10-30 历史证据与限制

该轮workspace Debug报告125项通过，其中124项实际执行，另一个抓包入口无专用变量时返回跳过；Clippy、fmt、Release musl构建通过。该轮没有完整Release测试集；0.6.0的验证见下方最新记录及docs/VERIFICATION.md。

37项有效捕获零丢包，H2 DATA长度一致，8项H3完成偏移、FIN和内容核验。大文件有限8/16模式前后各3次，26字节TLS记录从117～118降至0～2。首次bulk-before一项丢6包，整个阶段排除，以扩大缓冲后的bulk-baseline替代。

32流共用一个外层H2连接；预热后的Pingora H2回源池以一条连接处理32路请求。32个任意目标CONNECT仍需32条目标TCP连接。16资源、4次两秒空闲的测试验证活动延长三秒空闲期限，不能视为长期稳定性验收。

固定OpenGFW v0.4.3离线结果：29 TCP的FET阴性，Trojan26阴性、3无结论；8 UDP不适用TCP分类器。修复前后分类没有改善。正负对照通过，但已观察到上游Trojan首段验证问题，非TLS样本也可能命中长度树。不要把无结论算作阴性。

公开摘要在docs/packet-lab-results.json；原始reports及测试keylog不随包交接。当前实验客户端为BoringSSL/h2/quiche合成客户端，未完成真正Chromium代理客户端抓包，没有公网DPI识别率、真实时延/丢包、24小时稳定性或吞吐基准。

ECH是默认关闭的实验性支持，DNS发布、公开名称证书和轮换仍有人工步骤；本轮未验证ECH流量统计。ECH不能消除TLS-in-TLS长度、时序或目标IP信号。

## 2026-11-02 AnyTLS 对照加固

本轮分析与证据分级见 docs/ANYTLS-REVIEW.md。修改 H3 网站内存桥的错误传播：最终响应前上传失败及时结束交换；已有最终响应仍允许正文排空；正常 EOF 保留半关闭。新增完成状态测试和 codec 后开流/方向/额度隔离回归。协议修订4、认证与填充参数、依赖和 vendor 均不改变。不要把该修正描述为消除所有流量特征或修复 AnyTLS 的 Go 竞态。验证结果以新报告末尾为准，不能沿用此前环境的测试数。

## 2026-11-02 NaïveProxy / REALITY 对照加固

参考快照、社区报告的修复状态和限制见 docs/NAIVE-REALITY-REVIEW.md。本轮修正 src/net/site/mod.rs：通用 HTTP(S) 正向代理不再把网站入口生成的转发身份字段及 Via 发给任意目标；固定网站仍保留可信回源元数据。共用引擎尊重请求侧 Cache-Control: no-transform，避免额外 gzip，原响应侧规则保留。增强 H2/H3 HTTP、HTTPS 正向和网站压缩网络回归，先证实旧行为失败再验证修复。

保持真实证书、标准 TLS/H2/H3 与应用层逐流认证；不引入 REALITY 的目标站 TLS 校准或认证前后 TLS 实现切换。没有开发新 Chromium 客户端，没有新的 DPI 抓包/识别率或公网验收。完整 workspace Debug 为123通过、0失败、8 ignored；最终工具检查见新评审报告。源码包包含之前的 AnyTLS 加固，协议、依赖和 vendor 均未改变。

## 2026-11-02 单文件配置重构

仅保留 config.example.toml（中文注释），config init 将同一模板原子写成0600文件且拒绝覆盖。默认 schema2、state_dir=/var/lib/moon-naive、TCP/UDP443、H1网站/H2/H3开启；允许省略 listener/limits 和 ACME固定参数，按字段覆盖。保留 issuer=letsencrypt、environment=staging 的兼容默认值，示例显式选择 google/production。accept_terms默认false；check-config可离线通过，运行控制面仍要求true。

website.origin 是新简写，配置加载时展开为固定上游和根路由，并设置源站Host；不能同时设置upstreams/routes。DNS provider、Cloudflare Zone ID、内联EAB和HTTPS目录在本地校验。EAB类型/校验集中在core；init/migrate/EAB导入共用私有原子写入。既有账户、订单、证书、TXT清理状态及协议不变。

三份配置合为一份；自动证书内容并入CONFIGURATION.md，发布与服务端对照并入VPS-GUIDE.md；CLI输出夹具内联入测试，总计减少6个文件。保留模块边界与完整vendor，未合并为大源码文件。源码打包修正已有SHA256SUMS的自引用/重复归档问题。后续不要恢复旧配置示例或旧文档路径，历史引用仅在HISTORY.md保留。

已核对GTS/Porkbun官方文档；本轮没有真实域名/凭据，未执行公网签发。验证记录见docs/VERIFICATION.md的新条目。

## 2026-11-02 Caddy 插件与请求准入加固

固定参考klzgrad/forwardproxy naive分支e747854e（完整提交与对照见docs/NAIVE-REALITY-REVIEW.md末节）。按逐流密码学认证分流，未知请求走普通网站；不引入基于IP/浏览器指纹的“DPI识别器”、secret-domain/PAC挑战或Fast Open。保留TLS1.3 exporter/流ID/请求绑定、响应证明、先拨号后200、正常半关闭及现有预算。

修正App::prepare对H2/H3网站WebSocket过早申请通道额度：先经site::websocket::prepare检查Host/版本/固定路由，再申请额度并connect。已复现旧版未知Host在额度空闲时404、额度耗尽时503；修正后无效网站请求的状态/正文保持一致。合法WebSocket及全局CPU/连接/请求/通道资源仍共享，不声称负载不可观察。

H2 admit_until_closed优先轮询已就绪的reset/连接错误，避免对已关闭流先启动准入；取消等待会释放额度。新增2个确定性生命周期测试和1个真实H2/H3额度回归；增强同连接认证失败首部/正文等价检查，覆盖正确格式的伪造MAC。已有H2/H3早期DATA取消、正常FIN、跨流/连接/传输重放和固定源站WebSocket测试通过。H3现有取消机制、协议/配置/依赖/vendor不改变，没有增加项目文件。

workspace Debug结果127通过、0失败、8 ignored；Clippy与fmt通过。没有新Chromium代理客户端、公网DPI测量、Caddy对照抓包、Release/musl或公网ACME验收。不能把MAC常数时间比较表述为整个请求路径恒定时间，也不能保证撤回已经发出的DNS或TCP报文。最新记录见docs/VERIFICATION.md。

## 2026-11-03 0.6.0 延迟与CPU适配

用户明确本轮关注代理建连、请求处理和转发延迟，优先按部署主机检测指令集，不以CLI启动耗时为目标。workspace三个包统一0.6.0，认证/exporter协议修订4和TOML schema2保持；历史审查日期/版本不批量改写。

固定HTTPS下一跳改为outbound::NextHop，在Prepared::load的阻塞预检中一次准备authority、CA及TLS上下文，由Egress通过Arc共享；每连接仍创建独立SSL、验证当前证书与名称，保持拨通后200。CA读取错误现在使预检失败，根证书更新需重启；不影响入口ACME证书热更新。HTTP/SOCKS5不初始化TLS，失败不回退直连。

增加已锁定memchr 2.8.3的直接依赖，用预构造Finder扫描下一跳响应头，用memchr3检查H2/H3字段的NUL/CR/LF；自动分派AVX2/SSE2/通用实现。已有sha2 SHA-NI及BoringSSL AES/CLMUL分派保留。status/check-transport/启动诊断报告架构与CPU特性，不新增TOML、不强制target-cpu=native或AVX-512、不引入第一方unsafe。参考eza、fd、ripgrep、memchr源码的固定提交见ARCHITECTURE.md。

保留原有候选地址拨号调度。曾尝试单地址跳过JoinSet，但配对本地基准回退，因此已撤回；不要因少一次任务/分配就无证据恢复。新增Release基准只在显式--ignored运行；实际旧/新基准二进制与原始日志留在reports/perf-0.6.0，源码包只含测试实现和文档。最终测试计数、性能数值和适用范围见VERIFICATION.md，不沿用上轮数字。

## 2026-11-03 BBR与证书抓包

保持0.6.0、协议修订4及单TOML。TCP监听改为在bind/listen前设置并读回BBR，保留已接受/出站socket检查及系统缓冲管理。Linux H3改用单个timerfd+AsyncFd遵守微秒级quiche pacing；WouldBlock等待可写，64包额度耗尽后续调度。不要恢复毫秒sleep或为了追求吞吐提前发送。新增rustix直接依赖仅启用锁内1.1.5的time功能，没有新增第三方版本、第一方unsafe或vendor修改。

本轮使用独立Docker实验容器、TShark4.4.19、MTU1500、关闭GRO/GSO/TSO及fq。四种本地自签CA证书方案覆盖H1/H2/H3、认证失败、有限/稀疏填充、内层TLS、并发复用和空闲。抓包器和分析器支持环境变量选择容器；隔离无密钥被动视图与解密视图，正文与H3偏移/FIN核验后才纳入结果。中间CA夹具曾漏发内层TLS链，已修正并统一重跑。原始pcap/keylog留在reports，不能装入源码包。

当前内核没有prio/netem，RTT/丢包试验改用固定目标、单客户端、4MiB有界队列的本地UDP中继；它不终止QUIC/TLS，只用于H3实验，不能作为TCP BBR在公网损伤下的证据。`ss`在本环境只输出基础TCP字段，BBR算法由真实socket的getsockopt测试验证。正式97份抓包捕获丢包为0，38份H3完整性通过；Release workspace132通过/11 ignored，真实BBR门控测试另行执行，Clippy/fmt/Release构建与vendor审计通过。最新数字与限制以VERIFICATION.md及packet-lab-results.json的current为准，旧结果在history；旧phase和调试失败样本不能混入正式结果。

TShark无密钥TLS1.3使用opaque_type，不能只数content_type；当前分析器按记录树提取类型与长度。Tokio1.53.3的新泛型注册API为unsafe，私有OwnedFd初始化局部expect弃用警告并说明不变式，保持第一方unsafe禁令；不要泛化该例外或悄悄恢复全局allow。

## 建议接下来的工作

先复核当前代码和上述证据，明确下一轮要验证的假设。优先补真实Chromium客户端、真实网络RTT/丢包/流控下的吞吐和长连接测试，再决定是否调整padding与调度。保留响应认证，记录普通反代与CONNECT仍有的差异，不将局部长度改善宣传为整体不可识别。

源站池冷启动可能建立多条H2连接，预热单连接结果不能外推；长连接超时、取消、半关闭、背压与资源预算仍是后续性能修改必须回归的行为。

交付时只打包源码、示例配置、部署文件、测试源码与文档。vendor中的公开上游测试证书/测试私钥是固定fixture，应保留以满足源码校验；用户真实SSH私钥、证书私钥、ACME状态、凭据、TLS会话密钥绝不可加入。历史对话曾出现的SSH凭据不要复制或复述。


## 2026-11-04 长连接、高丢包及CVE增量

先核对Linux CVE列表与RustSec/OSV，再审查实际网络路径。CVE-2026-98432是IPv4 TCP握手内核UAF，早于accept/TLS，应用认证与BBR不能修复。增加只读版本参照诊断，不以版本号认证发行版回补；内核升级及可回滚的IPv4 IP options临时过滤说明在VPS-GUIDE.md。隔离容器只验证普通流量通过/options报文被丢弃，未执行漏洞利用或更改VPS。

H3移除50ms固定轮询，按QUIC/应用/握手/排空实际期限唤醒，保留Notify/UDP readiness和额度续调度。每轮消费最多64个路径事件，网站来源取active路径。quiche固定提交本已包含失败路径插入的队列防护，不得将本轮描述为修复其所有CVE。**连续第二次NAT源端口变化仍可能超时**：单CID路由缺少完整轮换/退役，单次重绑定回归通过；后续应完整实现CID生命周期，不能靠增加路径上限。

hickory-proto升级0.26.1、time升级0.3.47，锁定有限传递更新。权威DNS先检查UDP事务/问题/opcode后才TCP回退，最终检查AA/IN/NoError/无截断；本地八种响应场景回归通过。OSV仍有derivative和unsafe-libyaml停止维护两项提示；Pingora/quiche固定源码另查，不宣称依赖扫描零提示。vendor不变。

抓包工具增加可配置损失概率/种子/短时双向中断，以及h2-soak/h3-soak单认证通道。正式样本、耗时、失败/排除及检查结果见VERIFICATION.md与packet-lab-results.json；原始reports不随源码。虚拟24小时期限测试和120秒网络试验均不能充当24小时稳定性验收；不是Chromium、公网TCP BBR或DPI识别率测试。

最终Release workspace136通过、0失败、11 ignored；Clippy/fmt/Release构建/来源vendor审计通过，BBR门控及CLI配置/传输检查另显式执行。正式25份捕获零抓包丢失，24份QUIC内容/偏移/FIN核验通过。30秒间歇H3驱动循环1198→620，但长通道某次p50/p95反而较高，不得把减少轮询写成全面延迟提升。十秒后注入的两秒中断确认落在认证后，同通道恢复；一秒后中断的原样本可能只影响握手，保留但不作严格恢复配对证明。
