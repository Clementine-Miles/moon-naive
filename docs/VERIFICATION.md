# 2026-11-04 0.6.0：长连接、高丢包与网络栈漏洞（最新）

本轮在审阅网络实现前先查询Linux CVE、RustSec/OSV与上游安全公告，再核对锁定依赖和实际调用路径。版本0.6.0、协议修订4、TOML schema2保持。旧的97份证书/BBR实验保留为历史，不计入本轮样本。

## CVE与依赖适用性

| 公告/问题 | 本项目判断与处理 |
| --- | --- |
| [CVE-2026-98432，Linux CVE团队](https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/refs/heads/master/cve/published/2026/CVE-2026-98432.mbox)；[AWS公告2026-160](https://aws.amazon.com/security/security-bulletins/2026-160-aws/) | IPv4 TCP握手request socket的IP options生命周期/RCU竞争导致UAF，发生在TLS/认证前。普通TCP可能受崩溃、泄露、内存破坏影响；AWS描述的研究RCE场景针对MPTCP监听，不能据此宣布所有普通TCP均已证实RCE。关闭MPTCP不修复普通TCP。必须升级并实际运行修复内核；增加版本参照诊断和临时IPv4 options入口过滤说明，未远程修改VPS。 |
| [hickory-proto RUSTSEC-2026-0118](https://rustsec.org/advisories/RUSTSEC-2026-0118.html)、[0119](https://rustsec.org/advisories/RUSTSEC-2026-0119.html) | 0.25.2命中NSEC3分配及DNS编码复杂度公告，升至0.26.1。当前未启用DNSSEC，NSEC3路径不可达；生产只编码单个有界TXT问题，不接受任意多记录输入作为待编码消息。升级用于消除受影响依赖，并加强回退校验，不虚构已证实远程利用链。 |
| [time RUSTSEC-2026-0009 / CVE-2026-25727](https://rustsec.org/advisories/RUSTSEC-2026-0009.html) | RFC2822嵌套注释可栈溢出；0.3.44升至0.3.47。未确认本服务网络请求可到达该RFC2822解析路径，不把依赖命中等同可利用。 |
| [h2 RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258.html) | 空DATA队列耗尽类问题已由锁定的0.4.20覆盖（修复门槛0.4.16）；保留首部、reset、流与总接收预算。 |
| [Pingora安全公告](https://github.com/cloudflare/pingora/security/advisories) | 锁定vendor 0.9.0已经覆盖CVE-2026-105298的authority/Host问题、CVE-2026-105297的首部/流限制及CVE-2026-2833的过早升级问题；继续核对应用的32KiB/128字段/流上限，不改vendor、不以版本号替代已有协议回归。 |
| [Cloudflare quiche GHSA-4fgf-9xrr-88gf](https://github.com/cloudflare/quiche/security/advisories/GHSA-4fgf-9xrr-88gf)、[GHSA-4q5x-gp38-rfp4](https://github.com/cloudflare/quiche/security/advisories/GHSA-4q5x-gp38-rfp4) | 固定0.30.0提交925b225825e2188f8e58e359114150500557bf61已跨过0.29.3修复门槛；实际源码在路径成功插入后才产生复用CID事件。应用补充持续消费路径事件。它不是Google QUICHE/Envoy，不能混用后者CVE。 |
| [Tokio RUSTSEC-2026-0384](https://rustsec.org/advisories/RUSTSEC-2026-0384.html)、[0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html) | 保留1.53.3，不升级到受Interval UAF影响的1.54.0。AsyncFd旧泛型注册接口存在安全契约问题；本项目timerfd私有OwnedFd不替换/不提前外部关闭，保留具体所有权约束与局部deprecated说明，未关闭unsafe_code=forbid。此判断不推广到所有AsyncFd用法。 |

2026-11-04 OSV对Cargo.lock中310个crates.io包按名称/版本扫描，升级后仍有两项提示：derivative 2.2.0（RUSTSEC-2024-0388）和unsafe-libyaml 0.2.11（RUSTSEC-2024-0449）已停止维护。它们来自现有传递依赖；不是“零公告”或完整独立安全审计。Git/vendor另行按固定源码检查，数据库未索引的公告不能因查询为空视为不存在。

宿主实验内核为6.18.57，位于上游6.18.56修复参照以上；没有以uname证明发行版补丁真实性。独立实验容器内nft语法检查通过，带四字节合法IPv4 NOP options的UDP被丢弃，普通UDP和TCP握手/数据通过，计数器1；随后删除测试表。没有执行漏洞利用、关闭SACK/TCP timestamps或更改生产防火墙。临时防护与版本列表见[VPS指南](VPS-GUIDE.md#2026-11-04内核握手漏洞与长连接)。

## 长连接与丢包实验

本轮正式**25份抓包**：18份H3大文件（5%/10%/20%丢包，各旧/新×3种子）；2份30秒间歇H3；4份120秒H3（10%丢包+两秒中断，分早期中断与已建通道中断）；1份120秒H2。25份工作负载均通过、捕获丢包为零；24份QUIC完成逐流偏移连续、FIN、DATA字节和保存正文核验，H2 DATA长度一致。中继主动随机丢弃9259个报文，中断另丢40个，没有队列溢出、发送错误或退出残留。故意网络丢包与抓包器丢包分别统计。

环境为Rust1.89 Release、Linux6.18.57、3个EPYC 9V74 vCPU、TShark4.4.19；隔离容器lo、MTU1500、关闭GRO/GSO/TSO、fq。TCP BBR及QUIC BBRv2保持。缺少netem，H3经不终止TLS的本地UDP中继，每方向20ms/100Mbit/s、4MiB队列，TCP目标仍在loopback。这不是公网TCP BBR、WAN交叉流量或多流公平性试验。

控制二进制采用上一份BBR交付的驱动，仅加入双方共有的抓包夹具和测试计数器；新版另含DNS/time升级。每档种子1、42、2026，运行顺序旧→新、新→旧、旧→新；没有并行编译或分析。种子固定伪随机序列，不能保证不同调度恰好丢弃相同报文。每次两条CONNECT共用一条QUIC连接，各24个小片段后1MiB，耗时不含外层握手/关闭。

| 随机丢包率 | 旧版批间中位数 | 新版批间中位数 | 每版样本数 |
| --- | ---: | ---: | ---: |
| 5% | 1172.524 ms | 1083.633 ms | 3 |
| 10% | 1007.059 ms | 784.993 ms | 3 |
| 20% | 3568.982 ms | 1175.011 ms | 3 |

20%组旧版范围930.700–17893.329ms，新版1082.667–3200.951ms，变化很大；三个种子不足以推断公网尾延迟、稳定倍数或证明BBR优于其他算法。既有pacing和流控仍生效，没有放宽生产握手/空闲期限；仅实验客户端的单次I/O上限设为60秒，双方相同。

30秒、每次1KiB且间隔250ms的直接H3负载：旧版119轮/1198次驱动循环，新版120轮/620次循环，循环次数减少约48%。往返中位数0.284→0.2945ms，p95为0.580→0.542ms。这证明该样本减少轮询，**不是CPU使用率降低48%或所有延迟更低**。

初次中断在首个UDP包后一秒开始：新版中断发生在握手期间，不能用于配对证明已建通道恢复。两份原始数据保留；补做双方都在十秒后中断，并记录绝对时间，确认中断完整落在认证通道生命周期内。结果如下；本表每种条件仅一次，不用于普遍速度结论。

| 120秒负载 | 完整往返数 | 往返中位数 / p95 | 最大往返 | 外层连接 / 目标拨号 |
| --- | ---: | --- | ---: | --- |
| H2新版，直接连接 | 478 | 0.232 / 0.463 ms | 0.903 ms | 1 / 1 |
| H3旧版，10%丢包+已建通道中断 | 365 | 52.479 / 137.634 ms | 2760.004 ms | 1 / 1 |
| H3新版，同上 | 344 | 70.127 / 189.316 ms | 2143.769 ms | 1 / 1 |

两次补充中断分别始于认证后的8.514秒、9.431秒，持续两秒，同一条通道恢复，不重新拨号。新版该次中位数和p95高于旧版；早期中断那组结果方向相反，不能据此声称普遍降低长连接延迟。优化的确定收益是减少固定轮询，并保持这些损伤条件下的完整性与恢复能力。

所有长通道结束后的活动流计数为0。H3过程FD采样均为19，H2为20；120秒新版H3/H2样本的整体测试进程RSS分别增加536/720KiB。RSS包含服务端、客户端、收集的正文和结果，不能视为生产服务端泄漏测量。夹具空闲期限10秒，生产默认600秒；虚拟时钟另推进24小时验证活动刷新与最终空闲到期，未运行24小时真实负载。

**仍未解决连续多次NAT重绑定**：当前单CID路由验证一次端口变化后同连接12次请求成功，但连续第二次端口变化实验超时。需要完整CID路由/轮换/退役及路径回收，不通过增大路径容量掩盖。该失败保留在本地报告，不能把单次回归写成任意迁移支持。

## 最终检查与交付

Release workspace **136通过、0失败、11 ignored**；新增DNS八场景、内核版本参照、虚拟长时活动期限和单次NAT重绑定回归。TCP BBR门控回归另显式执行，读回监听继承及真实出站socket，不重复增加测试总数。25次抓包显式运行ignored夹具，独立于上述计数。五份早期smoke不计入正式样本。

Clippy workspace/all-targets Release且-D warnings、fmt、diff检查、Python语法、Release服务端/xtask构建及依赖/vendor审计通过。实际CLI生成0600单文件示例，启用bbr/bbr2后check-config/check-transport通过，输出有效bbr和非补丁认证的内核参照，没有开启监听或访问CA/DNS。保持547个源码包文件，vendor不变；新增内容并入现有模块、文档和工具，没有增加独立配置文件。

未重跑Debug全套、musl/三发行版构建、外部Chromium/Pebble、公开Porkbun/GTS、真实VPS长时间负载、内核利用或DPI分类。抓包是验证证书/主机名的BoringSSL/h2/quiche合成客户端，不是Chromium；SNI、ALPN和服务端JA3S仍可观察，不能声称特征消失。原始PCAP与实验TLS密钥留在本地reports，不进入源码包；脱敏结果、原始哈希、全部配对样本和限制见[packet-lab-results.json](packet-lab-results.json)的current，之前97/37份记录保留在history。复现工具说明包含损失概率、种子、可配置中断时机和完整性核验。

# 2026-11-03 0.6.0：BBR调度与证书抓包（历史）

本轮保留版本0.6.0、协议修订4、TOML schema2。TCP在监听前设置并读回BBR，使accept队列中的连接也继承策略；保留接受/出站socket的验证，不改宿主sysctl或强制缩小内核缓冲。H3修正发送调度：Linux单个timerfd提供高精度期限，UDP背压等待可写，64包工作额度用完后主动继续调度；不提前发送quiche尚未到期的数据包。

## 实验方法与有效样本

正式**97份抓包**：四种证书方案各16种请求共64份，TLS1.2/H1对照4份，H2复用3份、空闲2份，本地旧/新调度对照12份，UDP延迟/丢包对照12份。59份TCP、38份QUIC。所有正式工作负载断言通过，dumpcap报告零捕获丢包，H2 DATA长度无不一致，38份H3均通过偏移连续性、FIN及正文校验。故意注入的网络丢包单独统计，不算抓包器丢包。

环境为Rust1.89.0 Release、GNU/Linux 6.18.57、EPYC 9V74虚拟机、TShark4.4.19，独立Docker容器loopback、MTU1500、GRO/GSO/TSO关闭、fq；内核可用reno/bbr，默认bbr。TLS客户端使用BoringSSL，HTTP客户端为h2/quiche测试夹具，并非Chromium。四种方案均使用临时自签CA并验证信任链及主机名，不使用跳过证书校验。

当前内核没有prio/netem，因此有损试验使用**不终止QUIC/TLS的本地UDP中继**：每方向20ms延迟、100Mbit/s序列化、丢包组每包概率0.2%、种子42，队列上限4MiB。六个丢包样本共54次主动丢包，没有队列溢出、send错误或退出残留；它不是TCP网络仿真，也不代表真实公网队列/交叉流量。其余抓包直接连接服务端。

证书夹具中间链最初漏发内层TLS链，已修正并重跑完整矩阵；独立自签非CA叶证书被现有Validator拒绝的试验没有绕过检查；中继启动曾因最小Python缺少标准库失败，安装完整Python后重跑。上述调试/失败样本及早期探索阶段均排除。测试夹具补齐与生产一致的TCP_NODELAY，不能把原先约40ms的夹具Nagle等待当作生产优化收益。

## 配对转发时间

对照仅替换为上一份0.6.0源码中的H3驱动，其余测试夹具、TCP策略、配置和工作负载与优化组相同；不是对旧版全部功能的比较。两条CONNECT共用外层连接，各发送24个间隔4ms的数据段，再传1MiB；表中时间覆盖请求和完整正文，排除外层握手与关闭。每组3批、交替运行顺序，编译和离线分析均在测量外，以下为批间中位数，不报告这三个样本的p95。

| 工作负载 | 旧调度 | 新调度 | 适用范围 |
| --- | ---: | ---: | --- |
| H2，本地loopback对照 | 141.550 ms | 141.922 ms | 基本不变 |
| H3，本地loopback | 2093.626 ms | 321.018 ms | 此工作负载约6.5倍 |
| H3，UDP双向20ms/100Mbit/s | 3019.774 ms | 545.584 ms | 此工作负载约5.5倍 |
| H3，同上并注入0.2%丢包 | 3245.846 ms | 563.076 ms | 此工作负载约5.8倍 |

该结果证明驱动调度没有充分利用quiche pacing时会形成显著延迟；不能据此宣称所有代理流量获得同等倍数、TCP BBR优于其他算法或公网带宽达到100Mbit/s。夹具记录的QUIC RTT/cwnd/loss/PTO是客户端视角，不是服务端BBR状态。`ss`在本内核没有返回拥塞算法/pacing_rate，保存的基础快照不作为BBR生效证据；监听、继承的accept、显式设置及真实Egress的BBR使用getsockopt回读测试验证。

## 检查与交付边界

本轮Release workspace为**132通过、0失败、11 ignored**；BBR环境门控测试另用`MOON_NAIVE_TEST_TCP_CONGESTION=bbr`实际运行，不重复增加独立测试总数。新增三项发送调度/计时回归覆盖取消后重新设定期限、保留未发送包、背压和额度续调度。97次抓包另行显式运行ignored夹具，不混入单元测试数。

Clippy全workspace/all-targets且`-D warnings`、fmt、diff检查、Release服务端/xtask构建及依赖/vendor审计均通过。实际CLI成功生成0600单文件配置，显式启用bbr/bbr2后`check-config`及`check-transport`通过，读回`tcp_congestion_effective=bbr`，未打开服务监听或请求CA/DNS。Linux使用已锁定rustix1.1.5的time功能，无新依赖版本及vendor修改。Tokio1.53.3将泛型AsyncFd注册的新接口定义为unsafe；此处保留`unsafe_code=forbid`，只对私有、不可替换/外部关闭的具体OwnedFd注册语句标注`expect(deprecated)`并解释所有权不变式，没有全局屏蔽警告。测试及抓包中的实际计时路径不因此改变。

本轮未重新执行Debug全套、musl构建、真实Chromium代理、公网Porkbun/GTS签发、真实VPS/跨网TCP BBR测量、BBR多流公平性、24小时负载或DPI识别率评估。未更改生产VPS。可观察特征见[FINGERPRINTS.md](FINGERPRINTS.md#2026-11-03-证书与请求矩阵)，97份脱敏明细、原始抓包哈希和配对样本见[packet-lab-results.json](packet-lab-results.json)的`current`；历史37份结果保留在`history`。原始抓包和TLS会话密钥仅存本地reports，不随源码发布。复现命令见[packet-lab工具说明](../tools/packet-lab/README.md)。

# 2026-11-03 0.6.0：代理延迟与CPU自动适配

workspace三个包升至0.6.0；协议保持修订4，TOML保持schema2。改动是固定HTTPS下一跳TLS上下文在启动预检时准备并共享、memchr运行时SIMD字节扫描，以及本地CPU诊断。源码依据见[ARCHITECTURE.md](ARCHITECTURE.md#060-建连延迟与运行时指令集适配)，部署行为见[VPS-GUIDE.md](VPS-GUIDE.md#cpu-自动适配与延迟优化060)。

## 本地配对测量

Rust1.89.0、GNU/Linux、Release opt-level=3，无全局target-cpu=native/LTO/AVX编译要求。执行环境为AMD EPYC 9V74虚拟机，3个可见vCPU，支持AVX2、SHA-NI、AES、PCLMULQDQ及AVX-512F；这是构建实验机，不是用户尚未提供接入信息的VPS。测量进程固定在同一个允许的CPU，编译全部结束后才开始测量，没有并行构建。

对照是0.2.0-dev.4入口加固源码加入同一组基准后的实际Release测试二进制；优化后是最终0.6.0源码的Release测试二进制。每组7批，交替旧→新、新→旧运行，以下取批间中位数。HTTPS每批64次稳定样本，另记第1次连接；单地址TCP每批512次；头解析每个长度每批10,000次。

| 测量范围 | 旧实现 | 0.6.0 | 说明 |
| --- | ---: | ---: | --- |
| HTTPS下一跳：TCP+完整TLS+CONNECT+首字节，p50 | 9.485 ms | 0.592 ms | 每次仍校验CA/SNI，断言没有TLS会话恢复；约16.0倍仅适用于此本地路径 |
| 同上，p95 | 10.911 ms | 0.804 ms | 各批p95再取中位数，不是公网分位数 |
| 128字节响应头解析 | 0.156 μs | 0.093 μs | 有界分片内存输入，包含解析/缓冲，不含TCP和TLS |
| 8KiB响应头解析 | 4.811 μs | 0.480 μs | 同上，约10.0倍 |
| 32KiB响应头解析 | 18.660 μs | 1.626 μs | 同上，约11.5倍；32KiB仍是总头上限 |
| 单地址TCP拨号，p50（对照） | 14.101 μs | 14.111 μs | 最终保留原拨号实现，没有测得加速 |

HTTPS上下文一次性准备耗时的中位数为**8.236 ms**，现在计入服务启动预检，未计入每次连接计时。不是消除了初始化工作；收益来自每条隧道不再重复加载/解析CA和创建上下文。基准使用本机系统CA bundle加临时测试CA，系统根数量、CPU和文件缓存状态都会影响数值。网络部分在loopback上执行，不包含客户端到代理的H2/H3握手、认证、目标DNS或公网RTT。

另一个单地址省略JoinSet的候选在相同初次配对方法下由14.12μs变为17.42μs，故撤回并对最终源码重新测量。没有把候选实现的收益或测试数当成最终交付结果，也没有用微基准结果推导全代理吞吐、真实WAN延迟或DPI识别率。

基准实现位于`src/net/tests/evolution.rs`、`src/net/egress.rs`和`src/net/outbound.rs`，可显式运行：

```sh
cargo test --release --locked -p moon-naive --lib benchmark_https_next_hop_connect -- --ignored --nocapture --test-threads=1
cargo test --release --locked -p moon-naive --lib benchmark_single_address_dial -- --ignored --nocapture --test-threads=1
cargo test --release --locked -p moon-naive --lib benchmark_header_scan -- --ignored --nocapture --test-threads=1
```

性能测试不设易波动的耗时阈值作为正确性闸门。原始日志、旧/新二进制SHA-256和每批结果在工作区`reports/perf-0.6.0/latency-results.json`，不随源码包复制原始构建产物或私有状态。

## 正确性与范围

- `cargo test --workspace --locked`与`cargo test --release --workspace --locked`均报告**129 passed / 0 failed / 11 ignored**：主库96、CLI2、core29、xtask2。常规运行中的BBR入口未设置环境变量时提前返回；本轮另行设置`MOON_NAIVE_TEST_TCP_CONGESTION=bbr`，在真实连接前、入站和出站socket上读回BBR并通过，不重复累加测试数。
- 3项新增Release基准显式运行通过，并完成上述7批旧/新配对；其余ignored外部集成、抓包与旧微基准没有计为通过。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`、`cargo fmt --all --check`、`git diff --check`通过；GNU/Linux Release服务端与xtask构建通过。`xtask audit-native`依赖图审计通过，源码归档另行核验vendor与输入清单；未把图审计称为其他平台编译。
- 最终Release CLI输出`moon-naive 0.6.0`，`status`报告运行主机CPU能力。无需新增配置项，未改变全局编译指令集要求；Cargo.lock仅更新三个workspace包版本和已存在的memchr直接依赖边。

回归覆盖共享TLS上下文对新对端仍拒绝不受信CA、错误名称/新配置隔离、缺失CA预检失败、预读隧道数据、SIMD/2KiB读取边界、32KiB上限、多响应和EOF，以及原有H2/H3认证、取消、额度、半关闭与网站行为。

运行时CPU诊断与库的分派路径已核对；已有sha2/BoringSSL硬件加速不计作本轮新增。没有在无AVX2的实体CPU、其他架构或musl上重跑，也未执行公网Porkbun/GTS签发、真正Chromium代理客户端、长时间吞吐/丢包或DPI验收。自动回退依据所用库的实现，不能写成已完成所有CPU型号测试。

# 2026-11-02 Caddy 插件与请求准入

版本保持0.2.0-dev.4、协议修订4；本次改动接续单文件配置版本。源码依据、准入顺序及特征边界见[请求准入评审](NAIVE-REALITY-REVIEW.md#后续加固caddy-插件与请求准入)。

- Rust1.89.0、GNU/Linux Debug：`cargo test --workspace --locked` **127 passed / 0 failed / 8 ignored**（主库94、CLI2、core29、xtask2）。主库另行跑过94 passed / 0 failed / 6 ignored；不是两组相加。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`、`cargo fmt --all --check`、`git diff --check`通过。
- 先增加真实H2/H3额度回归，旧实现因未知Host在额度满时503、预期404而失败。修正后，未知Host/缺失路由/错误WebSocket版本，在无/错误凭据、额度空闲/满的组合下状态与正文一致，无代理认证/Padding响应字段；代理DNS与拨号计数均为0。合法固定源站H1/H2/H3 WebSocket及预读数据测试通过。
- 两个新增H2确定性生命周期测试：已就绪reset阻止准入副作用；等待中取消归还通道额度。已有真实H2/H3延迟准入、早期DATA取消、STOP_SENDING及正常FIN测试通过，目标成功之前没有200。
- 同连接先授权再发送无凭据/错误Basic/格式正确伪造MAC/重复/下划线别名的测试，比较各传输自身的无认证响应基线首部/正文（排除Date），无额外拨号。已有跨流/连接/传输重放测试继续通过。
- 无新增生产依赖、vendor修改、配置字段或项目文件。唯一TOML示例、Porkbun/GTS控制面和之前加固保留。
- 未运行Caddy对照抓包、新Chromium代理客户端、公网DPI/长时间负载、Release/musl或公网ACME验收。以上断言不测量时延、全局负载侧信道或识别率。

原始本地日志在reports/ingress-review，排除出源码包。

# 2026-11-02 单文件配置与 Porkbun/GTS 核对

版本保持0.2.0-dev.4，协议修订4。配置简化与官方操作依据见 [CONFIGURATION.md](CONFIGURATION.md)，唯一详细示例见 [config.example.toml](../config.example.toml)。本节是本次工作区验证，后面的记录保留原日期和环境，不能视为本轮重跑。

- Rust 1.89.0、GNU/Linux Debug：`cargo test --workspace --locked` **124 passed / 0 failed / 8 ignored**（主库91、CLI2、core29、xtask2）。未将外部集成/抓包/微基准的 ignored 计为通过。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`、`cargo fmt --all --check`、`git diff --check`通过。
- 覆盖可省略表及单字段覆盖、未知字段拒绝、Porkbun zone边界、GTS环境目录、Cloudflare Zone ID、EAB格式与脱敏、真实H2/H3简写反代的Host及转义路径/query、旧配置迁移、0600初始化/拒绝覆盖/软链接，以及首次签发等待期间SIGTERM。
- `check-config`允许尚未接受条款的production模板；实际控制面仍拒绝签发，已用真实CLI断言。原网站/代理、证书、DNS事务、EAB绑定和恢复测试保持通过。
- 修复打包器对已有SHA256SUMS的自引用和重复归档；增强归档回归检查条目唯一性和文件哈希。保持vendor、依赖锁、协议和ACME持久状态格式不变。
- 官方Porkbun入门/DNS API及Google Public CA教程已核对。只读GET验证GTS production/staging directory及HTTPS字段成功，未提交账户、订单或DNS变更。它不是公网签发验收。
- 本轮没有Release/musl构建、真实Porkbun/GTS签发、Pebble外部集成、三发行版运行、真实Chromium修订4客户端或公网DPI测试。

构建检查、打包和校验日志留在工作区reports/config-refactor，不随源码包交付。

# 2026-10-30 镜像反代与连续连接验证

版本仍为0.2.0-dev.4工作副本，协议修订4。新增H1固定长度响应修正、原始隧道16375字节读取上限和H3 Pingora缓存Date；保留之前的H2写缓冲和全部认证校验。详细测量见[FINGERPRINTS.md](FINGERPRINTS.md#2026-10-30-镜像反代并发与连续下载)。

- workspace Debug测试共报告125通过、0失败；其中124项实际测试，另1项抓包入口在无专用环境变量的常规测试中返回跳过。包含显式启用的Chromium网站H3、Pebble、官方旧协议拒绝、ECH、逐流认证/重放、流控/半关闭和新增H1同连接分帧回归。
- 新H1回归逐次验证固定正文、gzip、206 Range、未知长度流、HEAD、304、204和下一请求，在同一下游/源站连接上无正文串扰。
- 本轮37项有效捕获、零抓包丢包；H2逐流DATA长度一致，8项H3偏移/FIN/内容重组通过。首次bulk-before阶段因一项抓包丢6包而整个排除，扩大缓冲后重新生成bulk-baseline。
- OpenGFW v0.4.3固定规则离线重放：29 TCP的FET阴性，Trojan 26阴性/3无结论；8 UDP不适用TCP分类器。8项独立正负对照和非TLS首段对照通过。原版分类器未修改，未注入TLS密钥，未执行在线阻断。
- fmt、Clippy workspace/all-targets -D warnings、Release x86_64-unknown-linux-musl服务端与xtask构建通过。没有新增服务端依赖、unsafe或vendor改动。Go仅用于独立可选的OpenGFW实验适配器。
- 没有完整Release测试集、真实Chromium代理客户端、长时间公网连接/带宽基准、网络故障注入或GFW识别率验收。循环短时空闲测试不能代替24小时稳定性测试。

可复现源码见[tools/packet-lab/README.md](../tools/packet-lab/README.md)，脱敏结果见[packet-lab-results.json](packet-lab-results.json)。原始本地证据在reports/packet-lab/{mirror-before,mirror-after,bulk-baseline,bulk-after,mirror-final}及final-*.log；源码包不包含抓包/密钥/构建产物。以下保留之前验证记录。

# 2026-10-29 H2写入修复验证

当前仍为0.2.0-dev.4工作副本、协议修订4。本次H2发送缓冲修复及抓包结论见[FINGERPRINTS.md](FINGERPRINTS.md#2026-10-29-本地抓包与h2写入修复)。

- workspace Debug测试程序共报告124通过；其中123项实际回归测试，另1项抓包入口在未指定目录的常规运行中明确跳过。包含Chromium、Pebble、重放拒绝、小窗口、复用、半关闭和新增4项写缓冲测试。
- 抓包入口另行显式执行48次，全部通过；前后各15场景及各9次H2重复。H2逐流DATA完整，H3通过派生分析副本逐流重组核验；原始包保留给DPI分析。
- Clippy workspace/all-targets -D warnings、fmt及Release x86_64-unknown-linux-musl构建通过。没有新增运行依赖或unsafe，没有改动vendor。
- 新二进制保存在target/tls-coalesced/moon-naive，SHA-256为0f68772c34b44f0c275100ab84d770f734068a5d7dfea487a09410917e755a73；旧target/consolidated产物保持历史版本。
- 未执行完整Release测试集、三发行版矩阵、吞吐/延迟对照、真实Chromium代理客户端或公网DPI验收。OpenGFW分类前后相同，不能声称Trojan识别率下降。

原始构建/测试日志见reports/packet-lab；以下保留上轮整合验证历史。

# 0.2.0-dev.4 整合验证

日期：2026-10-28。协议保持dev.3的moon-naive修订4；TOML配置、填充协商、H1网站/H2-H3认证代理、反代内容及TLS行为不因模块迁移改变。

| 检查 | 结果 |
| --- | --- |
| Rust 1.89 workspace Debug测试 | 119通过、0失败、0忽略；6个测试程序，包含显式ignored网络/Chromium/Pebble测试 |
| Clippy workspace/all-targets -D warnings | 通过 |
| cargo fmt / git diff空白 | 通过 |
| Release x86_64-unknown-linux-musl构建 | 通过，主服务端与xtask |
| 静态ELF与CLI | 无INTERP/NEEDED；8/16配置接受，12及撤回的假流量字段拒绝 |
| 来源/vendor/依赖审计 | 通过；外部依赖版本未改变，未新增Go或其他TLS栈 |
| 确定性codec/配额模型soak | 10,000轮通过；不再运行未接入服务的RenewalScheduler模型 |

整合前128项测试中的重复core/ACME模型测试随死代码删除，磁盘事务测试迁至src/acme/store.rs，快照/有效期测试直接验证现用类型。真实网络测试保留，包括先拨号后200、早期DATA取消、H1拒绝走代理、H2/H3复用与逐流认证、8/16和稀疏记录完整回传、反代连接池和高级协议、BBR读回、ECH、证书热更新、Pebble首次签发/续期/恢复。不能把减少的测试数量解释为删除相应运行功能。

静态二进制：`target/consolidated/moon-naive`，16367136字节，SHA-256 `8af2be44f98f482cb6545a6b7dd5328b7fbe5d72f80cb6c8e59778c288e289d7`。版本输出：`moon-naive 0.2.0-dev.4 (boringssl/quiche; x86_64-linux-musl)`。产物是开发版；新的Chromium代理客户端仍未实现，本轮不改变客户端兼容范围。

## 精简与源码参考

第一方Rust文件加Cargo清单：60→51；相关目录16→11；Cargo包5→3。统计排除vendor、缓存、参考仓库、报告和发布归档。文档15→12，需求和验收并入RELEASING，旧审查并入HISTORY。数量减少主要降低维护成本，不能据此推断运行吞吐提升。

- 删除独立control包的旧Controller/AcmeIssuer/IssueFuture/Outcome、RenewalScheduler和PublishingStore模型；保留真实Manager、持久journal、证书校验、CURRENT原子提交及快照。
- native包并入主服务端src；core移到根目录，profile并入config、limits并入policy。
- 删除未接入的core Admission/Phase、ALPN Transport/negotiate、h2_settings/acme_account_builder包装及废弃INITIAL_RECORDS常量；实际h3_settings移到TLS模块。
- 验证通过的证书材料构造器缩为ACME模块可见，字段保持私有；存储通过只读访问器使用材料。

参考[fd v10.3.0](https://github.com/sharkdp/fd/tree/d38148f0aabdd073b4080cde770f679f3197b920)：src/main.rs:105在扫描前编译正则、src/fmt/mod.rs:147借用不需修改的路径、src/dir_entry.rs:81缓存元数据。参考[zoxide v0.9.8](https://github.com/ajeetdsouza/zoxide/tree/859268aec873465b6707f73001003a76adcafabd)：src/db/dir.rs:9借用Cow、src/db/mod.rs:190预留最终缓冲并直接序列化、src/db/stream.rs:23逐项借用返回。借鉴其减少重复计算/分配的方法，没有复制搜索算法、源码或引入其运行依赖；未猜测不明确的sslx仓库。

本项目应用：加载凭据时预计算标准HMAC keyed state；逐请求克隆固定状态继续计算；认证字段借用扫描不collect临时Vec；Base64直接写入预留58字节的最终String。所有用户仍执行证明比较，不因找到匹配而提前退出；重复认证字段仍拒绝。

微基准在同一Release程序中交替运行旧/新等价算法，9批、每批200,000次，取中位数：HMAC计算 200→111 ns/次；字段构造 116→54 ns/次。旧算法按dev.3实现独立重现；不是旧/新完整服务端二进制对比。预计算增加每用户固定状态内存，最多256用户。没有测TLS、拨号、网络吞吐或DPI；不能将局部微基准倍数套用到代理整体。代码和原始结果在reports/consolidation/bench及auth-benchmark.json。

本轮未新增unsafe，继续使用safe Rust、借用切片、固定大小状态和标准加密库。尚未执行本版完整Release测试集、三发行版平台矩阵、公开GTS/Porkbun签发、真实VPS长期压测、新Chromium客户端构建或网页/DPI抓包对照。旧版本相关结果只保留为历史记录。
