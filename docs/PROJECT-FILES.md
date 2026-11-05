# 项目结构与文件作用

0.7.0：三个Cargo包，服务端代码集中在src，协议核心在core，构建工具在tools/xtask。协议线格式保持dev.3修订4，客户端要求不变。

```text
Cargo.toml / Cargo.lock
src/              主服务端库、CLI、运行时
  acme/           DNS-01、证书验证/持久化、续期
  net/            H2/H3、拨号、TLS、隧道
    site/         Pingora反代与高级协议
core/src/         配置、认证、记录codec、分流、策略与网站模型
tools/xtask/      审计、构建、打包、验证
assets/           公共staging CA证书
config.example.toml  唯一中文单文件配置模板
deploy/           systemd、OpenRC、构建容器
docs/             当前指南与历史档案
licenses/         第三方许可
vendor/pingora/   固定上游与审计过的本地补丁
```

| 文件 | 作用 |
| --- | --- |
| `.cargo/config.toml` | Cargo Git 获取配置及 cargo xtask 命令别名。 |
| `.dockerignore` | 排除构建缓存、私有配置、状态和凭据，避免进入 Docker build context。 |
| `.gitignore` | 排除 target/dist/reports、运行状态和真实秘密文件。 |
| `Cargo.lock` | 唯一依赖锁；固定 registry 版本及 Pingora/quiche/instant-acme Git revision。 |
| `Cargo.toml` | 主服务端库与二进制依赖、三个workspace成员及构建策略。 |
| `LICENSE` | 项目 Apache-2.0 许可文本。 |
| `README.md` | 当前版本入口、运行模型、文档导航和证据边界。 |
| `assets/README.md` | 测试 CA 根来源、指纹与信任隔离说明；这些均为公开 CA 证书。 |
| `assets/gts-test-roots.crt` | 仅内置 GTS staging 的签发证书验证使用的公开测试根，不加入 production/API trust。 |
| `assets/le-staging-roots.crt` | 仅内置 Let's Encrypt staging 的签发证书验证使用的公开测试根。 |
| `config.example.toml` | 唯一中文配置模板：Porkbun/GTS、代理用户、单行反代、默认参数及高级扩展；config init 内嵌同一文件。 |
| `core/Cargo.toml` | 协议和配置纯逻辑 crate 的依赖声明，不依赖真实 TLS/网络适配器。 |
| `core/src/auth.rs` | 多用户HMAC密钥、TLS exporter/流/请求绑定证明、服务端响应证明及恒定时间比较。 |
| `core/src/codec.rs` | 协商8/16窗口和稀疏后段编解码，详见PROTOCOL.md。 |
| `core/src/config.rs` | 严格TOML配置、逐字段默认值、共享EAB校验、H2/H3窗口和拥塞参数。 |
| `core/src/ingress.rs` | H2/H3 共用认证边界；剥除网站请求的代理秘密头，约束普通 CONNECT 伪头。 |
| `core/src/lib.rs` | 导出 core 各模块；不创建监听器。 |
| `core/src/policy.rs` | 目标ACL、域名/authority验证、RAII配额管理。 |
| `core/src/website.rs` | 网站单行origin展开、高级路由与固定上游TOML校验；和代理目标ACL分离。 |
| `deploy/Dockerfile.musl` | 固定 Rust/Alpine 工具链及 BoringSSL/bindgen 构建条件，输出静态二进制；不是运行必需容器。 |
| `deploy/moon-naive.openrc` | OpenRC supervise-daemon 单元、普通用户、TERM 退出、重启与日志路径。 |
| `deploy/moon-naive.service` | systemd Type=notify 单元、普通用户、443 capability、状态目录、就绪与停止期限。 |
| `docs/ANYTLS-REVIEW.md` | AnyTLS 社区问题证据分级、对应防护、内存桥错误传播修正与验证。 |
| `docs/NAIVE-REALITY-REVIEW.md` | NaïveProxy 原则、REALITY 社区报告状态、架构适用边界及本轮隐私/转发语义修正。 |
| `docs/CONFIGURATION.md` | 单文件配置、默认值、迁移、Porkbun/GTS/EAB、自动签发续期恢复和维护。 |
| `docs/ARCHITECTURE.md` | 运行时控制/数据路径、网站桥、组件边界和已知协议限制。 |
| `docs/FINGERPRINTS.md` | BoringSSL/Go、ClientHello/服务端/H2/QUIC/流量形态差异与测量边界。 |
| `docs/HISTORY.md` | 历史任务、协议和审查记录；不代表当前实现。 |
| `docs/PROJECT-FILES.md` | 本逐文件清单和模块职责/依赖边界说明。 |
| `docs/PROTOCOL.md` | 项目源码/构建输入；职责见文件内说明。 |
| `docs/VPS-GUIDE.md` | 三发行版安装构建、systemd/OpenRC、发布验收、与原服务端差异及 H1 路由。 |
| `docs/VERIFICATION.md` | 当前开发版本构建、测试、发行版验证结果及未验收范围。 |
| `licenses/GCC-runtime-copyright.txt` | GCC 14/libstdc++ 版权和 GCC Runtime Library Exception。 |
| `licenses/GPL-3.0.txt` | GCC 运行时许可引用的 GPLv3 全文；不改变项目 Apache-2.0 许可。 |
| `licenses/MUSL-COPYRIGHT.txt` | musl v1.2.5 版权和许可文本。 |
| `licenses/README.md` | Rust/musl/GCC 静态运行时许可证的来源说明。 |
| `licenses/Rust-COPYRIGHT.txt` | Rust 1.89.0 源码分发版权声明。 |
| `licenses/Rust-LICENSE-MIT.txt` | Rust MIT 许可文本；Rust Apache 文本与根 LICENSE 相同。 |
| `src/acme/certificate.rs` | 证书验证、有效期、CSR与只在验证后发布的证书快照。 |
| `src/acme/crypto.rs` | 为 instant-acme 提供 BoringSSL P-256/JWS/HMAC 实现；不启用 rustls/ring/AWS-LC 引擎。 |
| `src/acme/dns.rs` | DnsProvider 接口、备用 Cloudflare provider、权威 NS/TXT 查询、UDP事务先验校验及截断后的TCP回退复核。 |
| `src/acme/eab.rs` | GTS External Account Binding 首次注册，按已持久账户 key 恢复；gcloud JSON 到私有 TOML 的本地导入。 |
| `src/acme/http.rs` | BoringSSL + Hyper 的有界 HTTPS 控制客户端，超时/取消/Retry-After/代理环境处理；不是公开 H1 入口。 |
| `src/acme/manager.rs` | 实际持久化 ACME 状态机：账户/EAB、订单、DNS-01、签发、ARI、退避、恢复与续期。 |
| `src/acme/mod.rs` | ACME 模块导出、时间与 BoringSSL 随机数辅助；控制面和数据面共用 BoringSSL 版本。 |
| `src/acme/porkbun.rs` | Porkbun v3 DNS-01 provider：zone/委派校验、TXT 所有权标记、创建不确定后的恢复和精确清理。 |
| `src/acme/state.rs` | 私有 TOML 读取/脱敏解析、ACME 写前日志、0600/0700 权限、kernel 单写锁、原子 journal 保存和跨环境清理约束。 |
| `src/acme/store.rs` | 证书generation、私有权限、writer锁、fsync、CURRENT原子提交与恢复。 |
| `src/cli.rs` | serve/check/check-config/check-transport/status/acme 子命令、config init和一次性配置迁移（含剔除旧false开关）、配置大小限制、信号注册。 |
| `src/lib.rs` | 主服务端模块入口；不再导出未使用的TLS/ACME包装函数。 |
| `src/main.rs` | 程序入口，由根 Cargo 包构建；统一 CLI、Tokio runtime 与脱敏退出。 |
| `src/net/congestion.rs` | 在监听前及逐 socket 设置并读回 Linux TCP BBR，验证接受连接继承；提供内核CVE版本参照，不修改宿主sysctl/qdisc或加载模块。 |
| `src/net/egress.rs` | 认证隧道目标DNS、逐候选ACL、最多两路错开连接与取消；共享已准备的固定下一跳上下文。 |
| `src/net/h2.rs` | BoringSSL + Pingora H2入口、逐流认证、半关闭，以及16KiB有界TLS写入合并与部分写回归测试。 |
| `src/net/h3.rs` | quiche 单所有者 UDP 驱动、Linux timerfd pacing、实际期限唤醒、可写背压与公平额度续调度、路径事件消费、H3帧、Retry及流控。 |
| `src/net/mod.rs` | 共同App/请求计划/用户加载、SIMD头值校验与本地CPU诊断；准备与绑定分离；组合TCP/UDP、预算和停止信号。 |
| `src/net/outbound.rs` | 固定下一跳TLS上下文预检与共享；HTTP(S) CONNECT增量/SIMD扫描、SOCKS5握手、逐连接TLS校验和读前缀保留；含边界回归和微基准。 |
| `src/net/redirect.rs` | 有界明文 HTTP 监听、规范域名 308 跳转、Host/方法检查。 |
| `src/net/site/bridge.rs` | H3 网站到同一 Pingora 引擎的可复用有界内存 H2 桥；不创建额外公开端口。 |
| `src/net/site/forward.rs` | 按用户/目标隔离的 Pingora 正向 HTTP 连接，复用受 ACL 约束的 Egress。 |
| `src/net/site/mod.rs` | 共同 Pingora HttpProxy/ProxyHttp 网站引擎；路由、gzip、转发头、正文限制和流式反代。 |
| `src/net/site/upstream.rs` | 管理员固定上游池、异步 DNS 缓存、HTTPS 身份校验、池隔离、轮询/被动冷却/有限回退。 |
| `src/net/site/websocket.rs` | H2/H3 扩展 CONNECT 到固定网站 H1 Upgrade，校验握手并保留预读数据。 |
| `src/net/tests.rs` | 真实 H2/H3 网络、认证/ACL、Padding/半关闭、早到数据、背压、取消、热换证等回归。 |
| `src/net/tls.rs` | BoringSSL与quiche配置、证书/ECH加载和热更新。 |
| `src/net/tunnel.rs` | H2/H3 共用的拥有缓冲区的下载读取、上传解码、Padding 生命周期与双向空闲截止时间；保留背压、半关闭及取消语义。 |
| `src/runtime.rs` | 整合单进程生命周期：预检、专用 ACME 线程、首次证书就绪门禁、双监听、systemd notify、排空与清理。 |
| `src/trust.rs` | 定位各发行版 CA bundle；普通 HTTPS 正向代理按应用实例延迟加载/共享解析结果，含缓存回归和微基准；可用 SSL_CERT_FILE 指定。 |
| `tools/xtask/Cargo.toml` | Rust 开发/验证/打包工具依赖；不是常驻服务依赖。 |
| `tools/xtask/build-support/musl-host-rustc.rs` | Alpine rustc wrapper：只把 host build script/proc-macro 改为动态 CRT，保留目标静态链接。 |
| `tools/xtask/src/audit.rs` | 固定 Git 来源审计、Cargo metadata、构建依赖图检查的辅助实现。 |
| `tools/xtask/src/main.rs` | verify/audit-native/check-elf/dist/source/platform-smoke 调度与本地报告保存。 |
| `tools/xtask/src/release.rs` | Rust goblin ELF 检查、依赖/许可清单、tar/flate2 规范化归档与 SHA-256；三发行版固定镜像运行检查。 |

未使用的control控制器/调度器、core隧道/ALPN模型和包装接口已删除；真实ACME Manager、事务存储与TLS热更新保留。原profile和limits文件分别归入config与policy。源码审计、打包与文档路径同步更新。

不合并第三方vendor文件，不把所有网络模块拼成单文件；异步状态机、HTTP边界和证书事务仍有清晰职责。target/reports/dist与外部fd/zoxide/Chromium源码属于生成物或参考材料，不进入服务端运行依赖。
