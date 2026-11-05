# 服务端架构

0.7.0 由根包构建 moon-naive；core 提供协议与配置逻辑，tools/xtask 提供构建及发布工具。运行时只需服务端程序、配置、持久化状态和所需系统信任根。

## 生命周期

CLI 先校验配置、用户、网站和传输条件。ACME 控制面运行在独立线程的 Tokio runtime，避免 DNS、日志写入和 fsync 占用数据面线程。没有有效证书时等待 DNS-01 签发，验证、安装后绑定 TCP/UDP，并通知 systemd 就绪。

账户操作使用 instant-acme；Porkbun/Cloudflare 适配器管理 TXT，日志记录未完成操作。证书经 SAN、私钥、链、有效期等检查后写入 generation，原子更新 CURRENT。续期失败保留仍有效的证书；轮换后新连接使用新上下文，已有连接继续。

SIGTERM/SIGINT 停止接入并排空连接，随后限时清理本进程拥有的 TXT。状态使用单写锁；升级时应保留整个 state_dir。

## 请求路径

- TCP：BoringSSL 处理 TLS；H1 提供网站，Pingora H2 支持网站与认证代理。
- UDP：quiche 处理 QUIC/H3；网站通过有界内存 H2 桥进入同一 Pingora 引擎。
- 代理仅在 TLS 1.3 H2/H3 上启用。每条请求绑定 exporter、流 ID 和请求字段验证；CONNECT 经 ACL、预算和目标拨号后才返回 200 与响应证明。
- 未认证请求进入固定网站路由；固定网站与任意目标正向代理使用不同的路由、元数据和连接池隔离规则。

实现见[网络入口](../src/net/mod.rs)、[网站引擎](../src/net/site/mod.rs)及[内存桥](../src/net/site/bridge.rs)。认证和记录格式以[协议](PROTOCOL.md)为准。

## 连接与资源

每条 CONNECT 对应一条目标 TCP 连接，外层 H2/H3 连接可以复用。隧道保留背压、半关闭、取消和额度释放；任一方向实际进展更新空闲期限，默认 600 秒。

网站支持固定源站池、最长前缀路由、gzip、SSE/gRPC、trailers 和固定路由 WebSocket。HTTPS 回源校验证书及名称；安全方法的建连失败可有限回退，不重放 POST。正向出站先检查 DNS/IP ACL，可使用一个 HTTP、HTTPS 或 SOCKS5 下一跳，失败不回退直连。

连接/流窗口和共享接收预算约束内存，接收预算不等于 RSS 上限。TCP 拥塞由内核处理，QUIC 拥塞由 quiche 处理；Linux timerfd 为 QUIC 提供发送期限等待，UDP 阻塞时等待可写。

## 依赖与边界

TLS 共用 BoringSSL；quiche 使用 boring crate 后端。gzip 由 Rust miniz_oxide 处理。源码打包、SHA-256 和 ELF 检查由 tools/xtask 的 Rust 库完成；首次 BoringSSL 构建仍需要原生工具链。

固定 Pingora 与 instant-acme 补丁随 vendor 提供并校验；后者仅增加使用持久化私钥和 EAB 注册的接口，复用上游协议实现。

不提供管理 API、动态任意网站路由、多 SAN 自动证书、分布式状态或多 CA 自动切换。ECH 为实验性功能。配置详见[配置指南](CONFIGURATION.md)，未验收范围见[验证记录](VERIFICATION.md)，网络可观察性见[指纹限制](FINGERPRINTS.md)。


## 恢复边界

H3 内存桥使用可替换代际。任一驱动退出会通知当前交换失败；后续请求经有界、单次构建及冷却后获得新桥。不会重放应用请求。DATA 长度在进入共享 H2 连接前检查，长度不符只重置该流。

CONNECT、HTTP 转发及固定网站源站复用有界 TCP 候选拨号，最多同时尝试两个地址。固定源站允许显式配置的私网地址，任意转发目标仍应用公共目标策略。源站选择与其地址回退分开；TLS 握手后的候选回退、整个 DNS/TCP/TLS 链的一次总截止时间仍待完善。

上述改动没有完成控制面进程隔离、双身份自动证书管理、原子多路径激活或认证容量预留。当前真实实现及验收差距见[实施报告](security/REPORT.md)。
