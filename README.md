# moon-naive

Rust 编写的 Naïve H2/H3 代理服务端，使用 **Pingora + BoringSSL + quiche**。当前版本 **0.6.0**，面向 Linux x86_64。**仅支持 moon-naive 修订4代理协议，官方 Naïve 和修订4之前的 moon-naive 客户端不兼容。** 本版沿用0.2.0-dev.4的线格式，配套Chromium客户端尚未实现。

RC4 将 H2/H3 隧道数据路径合并到 `net/tunnel.rs`，通过 `BytesMut` 直接读取并转移所有权，减少应用层整块复制；gzip 使用 Rust miniz_oxide，未使用的 Brotli/Zstandard 编码器及缓存压缩不进入运行依赖图。发布归档和 ELF 校验也由 Rust 库完成。变更范围、取舍及组件选择见 [Rust 网络栈](docs/ARCHITECTURE.md#rc4-rust-网络栈与边界)。

网站不读取本地文件。简单场景只填 `website.origin`，自动生成 `/` 路由并设置回源 Host；默认示例源站为 `http://127.0.0.1:8080`，部署前需替换或启动对应源站。旧 `site_root`、`website.files`、`website.static_cache_secs` 已删除。

一个 `moon-naive` 程序负责首次 DNS-01 取证、自动续期、H2/H3 监听、Pingora 网站和退出清理。代理使用 TLS 1.3 exporter 绑定的逐流HMAC认证及最多16条的小额初期填充；运行配置使用 TOML。生产配置提供 H1/H2/H3 网站，H2/H3 代理。H1 CONNECT 返回有正文的普通网站错误；关闭 Fast Open 和 0-RTT。域名、用户、Porkbun、GTS EAB、上游代理和网站规则集中于一份 0600 的 TOML。唯一 [中文示例](config.example.toml) 包含基础字段和高级参数说明；监听、限额和续期参数可省略，按需添加覆盖。

0.6.0针对代理建连与请求处理延迟优化：固定HTTPS下一跳的CA/TLS上下文在启动时准备并共享；HTTP字节扫描按运行主机自动采用memchr的AVX2/SSE2/通用实现。`status`、`check-transport`可查看CPU能力，无需新增TOML设置。更新下一跳信任根后重启服务。源码依据、CPU适配和实测范围见[架构](docs/ARCHITECTURE.md#060-建连延迟与运行时指令集适配)与[验证记录](docs/VERIFICATION.md)。

本轮继续完善BBR：TCP在监听前应用策略；Linux QUIC以高精度timerfd执行pacing，并改进UDP背压与发送额度后的调度。可在`[transport]`启用`tcp_congestion="bbr"`和`quic_congestion="bbr2"`，无需配置计时器或全局内核参数。多证书、多请求的tshark实验区分被动可见数据与本地解密结果，详见[指纹分析](docs/FINGERPRINTS.md)。

长连接增量改为按实际QUIC/应用期限唤醒，持续消费路径事件，保留丢包恢复、pacing和有界资源。DNS及时间库已升级并加固权威DNS的TCP回退校验。`status`、`check-transport`新增CVE-2026-98432的内核版本参照；该漏洞必须由宿主内核修复，应用升级不能替代它。部署说明见[VPS指南](docs/VPS-GUIDE.md#2026-11-04内核握手漏洞与长连接)，本地丢包实验及尚存限制见[验证记录](docs/VERIFICATION.md)。

```sh
moon-naive config init /etc/moon-naive/config.toml
# 填写域名、用户、Porkbun API、GTS EAB 和 website.origin，并接受 CA 条款。
moon-naive check-config /etc/moon-naive/config.toml
moon-naive check /etc/moon-naive/config.toml
moon-naive serve /etc/moon-naive/config.toml
```

`config init` 原子创建0600模板且拒绝覆盖；父目录须已存在，文件应由服务用户拥有。`check-config` 验证结构、内联凭据格式及私有主配置权限，允许未接受条款的模板，不验证线上密钥、不读取外部旧式秘密文件。`check` 读取本地凭据、网站和证书状态，不访问 CA/DNS，不监听端口。`serve` 没有旧版实验闸门：没有有效证书时自动申请并等待，就绪后同时监听 TCP/UDP；续期失败保留仍有效的证书，SIGTERM/SIGINT 触发连接排空和 DNS 清理。

当前采用认证协商的8/16条初期窗口及可选稀疏后段；满载读块停止附加填充，不生成空闲假流量或修改真实反代内容。预算、线格式与客户端要求见[PROTOCOL.md](docs/PROTOCOL.md)。

监听地址省略时 TCP/UDP 默认 443。安全加固覆盖严格 H1 报文边界、完整请求头期限、异常 H2 reset、未完成 QUIC 握手回收、逐流认证和 TLS 池隔离；详见 [安全审查与参考公告](docs/HISTORY.md#2026-10-24-安全增量审查)。这些机制不保证 DPI 不可识别；泄露的配置秘密仍需轮换；新协议尚需独立安全审计。

- [VPS 源码构建与功能对照](docs/VPS-GUIDE.md)：三发行版 Cargo 构建、自动取证启动、未复现功能及原因。
- [本轮弱点与协议说明](docs/PROTOCOL.md)；[历史审查](docs/HISTORY.md)。
- [逐文件项目清单](docs/PROJECT-FILES.md)：源码、配置、部署文件和运行时状态的作用。
- [单文件配置与自动证书](docs/CONFIGURATION.md)：默认值、Porkbun/GTS/EAB、网站、迁移、签发续期与维护。
- [架构](docs/ARCHITECTURE.md)：模块、控制线程、代理与网站数据路径。
- [指纹与 Caddy 比较](docs/FINGERPRINTS.md)：可确认的改变及尚未测量的效果。
- [本次验证](docs/VERIFICATION.md)：执行结果及尚未验收的范围。

网站仅保留固定源站反代、最长前缀路由、gzip、H1/H2 上游池和流式转发；Range/条件请求交给源站处理；支持 SSE、H2 gRPC、100/103、请求/响应 trailers 与固定路由 WebSocket（H1 Upgrade、H2/H3 扩展 CONNECT）。普通网站响应宣告 H3，HTTP 监听执行规范域名的 308 跳转。错误凭据与普通访问进入共同网站引擎；请求中的目标地址不能成为网站反代目标。已认证 H2/H3 也支持通用 HTTP(S) 正向请求；按用户和 origin 隔离连接池。Naïve/正向出站统一检查 DNS/IP ACL，可选择一个 HTTP、HTTPS 或 SOCKS5 下一跳，上游失败不回退直连。管理员配置的固定网站上游独立管理。

**BoringSSL 会改变服务端握手特征；目前没有证据证明比 Caddy 更难识别。** 官方客户端的 ClientHello、H2/H3 状态机、QUIC 参数、网站语义与流量形态仍需分别评估。RC 发布包不代表已完成公网 GTS/Porkbun、目标 VPS 长期稳定性或 GFW 识别率验收，具体范围见验证报告。

从源码构建现在只需一个 workspace 和一个 lockfile，quiche/ACME 使用固定 Git revision，Pingora 的受校验源码与协议补丁随 `vendor/pingora` 提供，不必准备相邻仓库：

```sh
cargo build --release --locked -p moon-naive
./target/release/moon-naive --help
```

原生构建需要 Rust 1.89+、C/C++、CMake、libclang、Perl 与 pkg-config。通用 x86_64 静态包使用 [Dockerfile.musl](deploy/Dockerfile.musl) 中的 Alpine 工具链，详见发布说明。

```text
Cargo.toml / Cargo.lock  主服务端、三个workspace成员与依赖锁
src/                    服务端库、CLI与生命周期
  acme/                 真实ACME、DNS、证书校验/事务/续期
  net/                  TLS、H2/H3、隧道、拨号和Pingora网站
core/                   配置、认证、codec、分流和准入策略
xtask/                  Rust审计、验证与打包
tests/                  CLI/Pebble集成测试
tools/packet-lab/       可选抓包/DPI实验工具（不参与服务端构建）
assets/                 公共测试CA证书
deploy/                 systemd、OpenRC、静态构建环境
docs/                   当前说明及历史档案
vendor/pingora/         固定上游源码、协议补丁与校验清单
```

许可证为 Apache-2.0。发布包同时附带依赖清单、第三方许可证、构建信息和 SHA-256 校验。

ECH 提供默认关闭的实验性 TCP/QUIC 接入及 `ech init/check/dns` 命令；公开名称证书、DNS 发布和轮换需人工管理，尚非完整无人值守支持。见 [ECH 配置与限制](docs/CONFIGURATION.md#ech实验性接入默认关闭)。

与作者 Caddy/forwardproxy 的功能差异、现有缺口及 H1 全路由说明见 [服务端对照](docs/VPS-GUIDE.md)。

ECH 密钥集及公开证书可热加载。新客户端必须验证证书和 CONNECT 响应证明，不允许旧协议回退。完整要求见 [协议与客户端说明](docs/PROTOCOL.md)。

本轮进一步移除了旧插件响应Padding模块和Fast Open/0-RTT无效配置字段；实际删除、原本不存在和保留的能力详见[清理清单](docs/PROTOCOL.md)。

接手维护或交给其他 Agent 时，请先阅读 [HANDOFF.md](HANDOFF.md)。

- [AnyTLS 社区经验与针对性加固](docs/ANYTLS-REVIEW.md)：公开问题核实、现有防护及 H3 网站内存桥错误传播修正。
- [NaïveProxy / REALITY 对照与加固](docs/NAIVE-REALITY-REVIEW.md)：标准栈与真实网站、社区报告、正向身份清理、no-transform，以及Caddy插件对照、WebSocket准入和H2取消修正。
