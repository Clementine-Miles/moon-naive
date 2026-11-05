# AnyTLS 社区经验与 moon-naive 加固

审阅日期：2026-11-02。AnyTLS 源码固定于
`fd6167acd6d73b9fa3e607659951847fbc9e6c50`（当次查询 main，最近版本 v0.0.13）。
moon-naive 基线为本次上传的 0.2.0-dev.4、协议修订4。
这是一轮针对性源码检查与回归，不是完整安全审计或不可识别性证明。

## 证据分级及对应处理

| 社区问题/来源 | 核实结果与边界 | moon-naive 的对应处理 |
| --- | --- | --- |
| [#53 静态哈希凭证](https://github.com/anytls/anytls-go/issues/53) | 源码认证确实比较静态 SHA256(password)。泄露后可作为凭证使用；跳过证书验证使中间人取得它成为可能。报告者后来请求删除 issue，不能将其形式化验证声称当作独立审计结论。 | 已有 exporter + 实际流 ID + 请求字段 + 协商选项 HMAC；独立响应证明。保留证书验证，不加入 Basic/旧协议回退。高熵秘密仍必要，HMAC 不能阻止弱口令离线猜测。 |
| [#32 恒定时间比较](https://github.com/anytls/anytls-go/issues/32) | 固定版本 inbound_tcp.go 使用 bytes.Equal；这是加固建议，未证明可行的远程计时攻击。 | auth.rs 已用 ConstantTimeEq，检查全部用户密钥。 |
| [#54 关闭/写入竞态](https://github.com/anytls/anytls-go/issues/54) | stream.go 的 dieErr 存在普通并发读写；报告含 arm64 崩溃复现。此次未运行该 Go 复现，不能称已独立复现或 CVE。 | Rust 状态所有权、锁/原子变量与 H3 单驱动避免照搬该共享接口；仍检查逻辑取消和任务生命周期，不能由 Rust 直接推导无竞态。 |
| [#23 每流流控](https://github.com/anytls/anytls-go/issues/23) | 作者说明参考客户端倾向单活动流、顺序复用会话；不能把并发 mux 的理论风险当作默认客户端已证明的 OOM。 | 保留 H2/QUIC 流控、全局预算和两格队列，不改为自制 mux；已有慢读、背压和取消网络测试。 |
| [#45 复用断流](https://github.com/anytls/anytls-go/issues/45) | 讨论最终指向第三方 Nexitally 服务端；作者及报告者确认，并报告第三方已修复。不是 anytls-go v0.0.13 的已确认同类缺陷。 | 保留标准 stream ID 与逐流状态；重点核查半关闭、错误传播及下一条流可用性。此次修正内存桥上传错误被忽略的问题。 |
| [#46 padding 全局更新](https://github.com/anytls/anytls-go/issues/46) | 固定 client.go 的 createSession 引用全局 DefaultPaddingFactory，协议文档要求按 Client 保存；隔离范围值得关注。不能将所有第三方实现等同于该路径。 | 每条 CONNECT 在响应证明中固定 Mode；Encoder/Decoder 各自拥有计数与额度，没有远端更新全局策略入口。 |
| [#49 fallback](https://github.com/anytls/anytls-go/issues/49)、[#43 证书](https://github.com/anytls/anytls-go/issues/43) | 参考项目 README 明确默认示例配置不安全；固定 inbound_tcp.go 的 fallback 仅日志输出。 | 已有固定源站网站、ACME 校验/续期、过期证书拒绝新握手。网站行为不代表与其他服务器无法区分。 |
| [FAQ 已知弱点](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/docs/faq.md)、[#19 后续设计](https://github.com/anytls/anytls-go/issues/19) | 上游列出下行、后段流量、长度/时间/突发等限制；不存在“增加 padding 即证明不可识别”的结论。 | 已有双向有限/稀疏模式；不增加假流量、不修改正文、不移除响应认证。真实 Chromium 与公网统计仍未验收。 |

另一个源码边界：inbound_tcp.go 用一次 ReadOnceFrom 所得缓冲解析完整认证前缀及 padding；依赖一次读取足够覆盖认证数据，面对分片可能提前失败。moon-naive 的 HTTP 解析委托标准栈，codec 有跨切片状态，现有所有分割点、截断和有限窗口转裸流测试应持续保留。

参考源码：

- [认证入口](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/cmd/server/inbound_tcp.go)
- [Stream 生命周期](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/proxy/session/stream.go)
- [Client 会话池](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/proxy/session/client.go)
- [协议规范](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/docs/protocol.md)
- [项目定位和示例配置警告](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/readme.md)

## 本次生产代码修正

位置：`src/net/site/bridge.rs`。

原实现无论 upload 返回成功或失败都等待 download。若上传出错而响应尚未就绪，错误会被吞掉，请求继续等待其他超时/取消路径，延迟释放交换状态。现改为：

1. 上传正常 EOF：继续等待响应，保留 HTTP 半关闭语义。
2. 最终响应尚未开始时上传失败：返回错误并丢弃本次响应 future，交由既有 Failed/流取消路径处理。若已收到最终响应首部，则允许该响应正文继续排空，避免误伤源站提前响应后关闭请求方向的合法行为。
3. 响应先完成：结束本次交换并丢弃未完成上传，允许源站提前拒绝请求。
4. 两侧同时就绪时优先已完成的响应。

该问题是本次在 moon-naive 中独立发现的错误传播缺口，不是声称移植或修复了 AnyTLS 的 Go 数据竞争。不会改变协议线格式、认证、padding 参数、依赖或 vendor。

新增五项完成状态测试：上传错误及时返回并释放状态、上传 EOF 等待延迟响应、提前响应取消上传、响应错误取消上传、提前响应的正文在请求方向关闭后仍可排空。完整验证结果在本文件末尾记录。

## 对流量特征的具体约束

本次不引入 AnyTLS 静态哈希认证块、cmdSettings/cmdFIN/cmdWaste 自定义帧、服务器下发全局 padding 表、定时应用心跳或假流量。H2/H3 的正常 ACK、控制流和协议保活不能据此称为假流量。

保留现有逐流、双向的 8/16 初期窗口与可选稀疏后段。新增 codec 回归明确检查：同一进程中繁忙流不会耗掉后来流的初期窗口，不会改变其模式，也不会把已积累的稀疏额度借给其他流/方向。该测试保护已有隔离机制，不代表本次新增了线上填充算法。

标准 H2/H3 本身仍有控制帧；CONNECT 响应证明具有可观测的长度开销；有限模式后段、内层 TLS 握手往返、方向和时间分布仍可能形成统计特征。HMAC 字段和标准协议语义不应为追求表面长度一致而删除。此次没有新抓包实验或 DPI 识别率证据，不能宣称“消除了 AnyTLS 的所有特征”。

## 后续仍需验证

- 真正 Chromium 代理客户端的证书验证、逐流认证和响应证明。
- 真实 RTT/丢包下的 H2 队头阻塞及 H3 流控、取消、并发公平性。
- 长期连接稳定性、资源峰值和热加载；短时本地回归不能替代这些测量。
- 原生 BoringSSL/quiche/Pingora 依赖的后续公告和独立安全审计。

本次仅借鉴公开问题和独立实现修正，未复制 AnyTLS Go 实现。固定仓库根目录没有 LICENSE；相关讨论 #1/#24/#36 不能代替许可证授权。

## 本次验证结果

- Rust 1.89.0，GNU/Linux Debug：`cargo test --workspace --locked` 最终 **123 passed / 0 failed / 8 ignored**。其中主库90、CLI2、core29、xtask2；8项为显式外部集成/抓包/微基准等，未将 ignored 计为通过。
- `cargo clippy --workspace --all-targets --locked -- -D warnings` 通过。
- `cargo fmt --all --check`、`git diff --check` 通过。
- 新增6项回归：5项内存桥生命周期、1项codec流/方向/额度隔离。
- 将实际完成函数及测试提取到独立 Tokio 检查项目，恢复旧的“忽略上传错误”分支：对应测试在1秒期限失败；修复版5项通过。这是完成状态机的对照，不宣称复现了公网DoS。
- 完整网络回归覆盖H2/H3慢读、半关闭、取消释放、同连接不同协商模式、网站413提前响应、流式正文、WebSocket、TLS身份校验等。
- 初次全量构建期间codec测试曾修改，旧测试二进制运行了已修正的额度断言而失败；最终重新编译并运行整个workspace，上述123项为最终源码结果。
- 本次没有执行Release/musl构建、真实Chromium代理、外部Pebble/官方客户端测试、新抓包、DPI或公网稳定性验收。

本地日志：`reports/anytls-review/tests-final.log`、`clippy.log`、`bridge-before.log`、`bridge-after.log`。reports不进入源码包。
