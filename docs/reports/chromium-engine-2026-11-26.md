# Chromium 原生引擎恢复、服务端优化与仓库整合：工程报告（2026-11-26）

本报告记录这一轮工作做完了什么、做了一部分的是什么、哪些没有验证。所有数字都来自一台
4 vCPU 云容器里的回环测试，不代表公网或生产环境。本项目**不**声称客户端流量与 Chromium
浏览器不可区分；服务端的 Rust quiche 路径也**不是** Chromium 原生实现。

## 一句话结论

客户端的数据面换成了真正的 Chromium 网络栈（TLS、HTTP/2、QUIC/HTTP/3、连接池、证书校验），
Rust 只保留应用层；客户端里原来的 Rust h2/quiche 传输整个删掉，没有任何隐藏回退。mona/Rupin
的四条不变量保持不变并有测试覆盖。服务端把 H2/H3 的隧道转发合成一条，H3→H2 网站桥接测量后
决定保留。文档合并为 README + 五篇 docs，构建可复现（本机从零重建的引擎与原产物 sha256
逐字节相同）。

## 已完成

### 客户端：Chromium 原生引擎

- **结构**：`libmoon_engine.so` 是钉死的 NaiveProxy 源码树（Chromium 154.0.8037.49，上游提交
  `d04efe1e…`）里的 `net/`，加上 `engine/chromium.patch`（约 1080 行）和 `engine/src` 叠加层，
  对外只暴露 8 个 `moon_*` C 函数。Rust 侧 `engine/bridge`（crate `moon-naive-engine`）是全仓库
  唯一允许 `unsafe` 的地方，负责加载和调用。
- **引擎查找顺序**：配置项 `engine_library` → 环境变量 `MOON_NAIVE_ENGINE` → 可执行文件同目录
  → `../lib/moon-naive/`（发布包布局）。找不到就报错退出，并给出可操作的提示，不会退回任何
  Rust 传输。
- **mona/Rupin 不变量**：
  1. 证明绑定的是这条代理连接实际的 TLS exporter（标签 `EXPORTER-moon-naive-v4`）。
  2. 证明绑定的是 Chromium 实际分配的流 ID：H2 在 `SpdySession::DoWrite` 分配 ID 之后、发
     HEADERS 之前生成；H3 直接取请求流的 `stream_->id()`，流 0 合法。
  3. 发送任何载荷之前，必须先校验恰好一个有效的 `proxy-authentication-info` 确认。
  4. 记录分帧（record codec）不变。
  另外，`proxy-authorization` 用 never-indexed 方式编码；moon 隧道拒绝 naive 的 fastopen。
- **本地监听**：只接受回环地址（127.0.0.0/8 和 [::1]），IPv4/IPv6 都处理；本地握手有超时。
- **ECH**：设置了 `ech_config_list` 就强制 ECH，服务端不接受 ECH 时连接失败，不降级。
- **证书**：Chrome Root Store 加可选的 `ca_file`，证书校验不能关闭。

### 互操作测试（interop）

`cargo xtask interop --engine <lib>` 跑 11 个端到端用例，全部通过（中继重构之后又跑了一遍，
仍然全部通过）：

- 用 SOCKS5 和 HTTP CONNECT 走 H2、走 H3
- 密码错误时一次拨号都不会发生
- 拒绝不受信任的服务端证书
- UDP 不通时 `h3-then-h2` 回退到 H2
- 服务端重启后客户端重连
- 客户端代码里没有自己的传输实现，也没有 TFO 代码（静态检查）
- ECH 在 H2/H3 上被接受、从不绕过
- 确认缺失、重复或损坏时绝不放行载荷，之后能恢复（H2、H3 各一个）
- 两个方向各自独立半关闭（H2、H3 各一个）

### 构建、可复现性与发布

- `cargo xtask engine fetch | toolchain | build | check | export`：拉源码、准备工具链、构建、
  校验源码树与补丁一致、导出补丁。补丁用 `git diff --full-index` 保存，换一次克隆也稳定。
- **可复现性已验证**：在全新目录里从零 fetch → toolchain → check → build，产物 sha256 为
  `62901f36…63ef`，与之前的构建、发布包里的那份逐字节相同。
- `cargo xtask check-engine` 校验产物：x86_64 ELF 共享库、没有解释器、导出符号恰好是那 8 个、
  依赖只有 libc/libm/libgcc_s/ld-linux。
- `cargo xtask dist-client` 打客户端发布包（glibc 动态链接的客户端 + `lib/moon-naive/libmoon_engine.so`
  + 文档、补丁、构建参数、Chromium 许可证、第三方声明、`BUILD-INFO.json`，其中
  `traffic_indistinguishability` 写的是 `"not claimed"`）。
- CI 新增 `engine` 任务：带缓存地构建引擎、校验、跑 interop、上传客户端发布包。

### 服务端优化

- **H2/H3 分发**：本来就共用 `App::prepare → Plan`，这次没改。
- **隧道转发合并**：H2 和 H3 原来各写一套上传/下载转发，现在合成 `tunnel::relay`，两边只各自
  实现「读客户端数据」和「写回客户端」两个小 trait。行为不变，全量测试和 interop 都通过。
- **H3→H2 网站桥接：先量再决定，结论是保留**（详见 `docs/development.md` 的 Measurements）。
  桥接里那段内存 H2 中转，小响应只占桥接 CPU 的约一成，大响应占三成到近六成；其余是 Pingora 的
  代理路径、上游连接池和源站，换成直连的 H3 Pingora 会话（`ServerSession::Custom`）也照样要付。
  桥接带着这段中转也能跑 5–13 Gbit/s，远高于 QUIC 本身在这台机器上的吞吐，不是瓶颈。
- **资源、出口、ACME 审阅**：没发现需要改的缺陷。
  - `resources.rs`：每个 chunk 的计费在 drop 时会同时 `notify_waiters` 和 `notify_one`，这是
    有意的唤醒策略。
  - egress：每次拨号都重新读本机地址，是为了地址变化后能马上生效；happy-eyeballs 的竞速有上限。
  - ACME：有持久化的日志（journal）、指数退避、遵守 `Retry-After` 和 ARI、每一步都有超时，并有
    pebble 实验室测试。只做了设计层面的审阅，没有改代码。

### 代码与依赖整合

- 公共依赖（hmac、http、serde_json、nix）提到 workspace 里统一声明；`Cargo.lock` 不变。
- 服务端继续用 quiche、Pingora、boring。客户端不再依赖它们。

### 文档

- 合并成 README + `docs/{architecture,usage,protocol,security,development}.md`。原来的
  client/configuration/deployment/testing 四篇并进 usage 和 development，旧的 audit 移到
  `docs/reports/refactor-audit-2026-11-23.md`。
- `tools/xtask/src/release.rs` 里打包的文档清单同步更新；`docs/reports` 整个目录随发布包分发。

## 做了一部分

- **CI 上的引擎构建**：工作流已经写好，本机按完全相同的命令验证过。但它在 GitHub 托管
  runner 上第一次完整跑通（磁盘、时长都在 330 分钟限制内）还要等 PR #2 的 CI 结果确认。
- **H3 与私有 CA**：设置了 `ca_file`（私有 CA）时，Chromium 只有把目标写进
  `origins_to_force_quic_on` 才会走 QUIC，引擎已经这样做。这是 Chromium 自身的策略，不是 bug，
  但意味着私有 CA 场景下 H3 的连接选择逻辑和公网 CA 不完全一样。
- **ECH 在 H3 上不重试**：H2 收到服务端的 retry configs 会用新密钥重试并成功；H3 不重试，
  直接失败（fail closed）。服务端轮换 ECH 密钥后，H3 客户端要等配置更新或回退到 H2。
- **吞吐有回退**：回环测试里，引擎版客户端 H2 为 910–1142 Mbit/s、H3 为 294–368 Mbit/s；旧的
  Rust 客户端在 2026-11-23 测的是 1479–1637 和 380–417。原因是每个数据块都要跨一次 C ABI，
  在 Chromium 网络线程和 Tokio 之间切线程，而且每条隧道同时只有一个读、一个写在途。这是换取
  真正 Chromium 栈的代价，目前没有优化。

## 没有验证

- **流量是否与 Chromium 不可区分：不声称，也没有验证。** 引擎用的是 Chromium 的网络栈，但
  调用方式、连接模式和时序都由本项目决定，和浏览器的真实行为不同。
- 公网、真实丢包/乱序/MTU 变化下的表现：需要特权网络命名空间（netem），本环境没有。
- 非 x86_64 Linux 的引擎构建（ARM、macOS、Windows）：没做，发布包只有 x86_64-unknown-linux-gnu。
- musl 客户端：不支持，musl 静态程序无法 dlopen 这个引擎，所以客户端必须是 glibc 动态链接。
- 3 个 IPv6 单元测试在本容器里一直失败（容器没有 IPv6，`EAFNOSUPPORT`），这次改动之前就是
  这样，属于环境问题；IPv6 路径需要在有 IPv6 的机器上再跑一遍。
- 长时间运行的稳定性（内存、句柄泄漏）：没有做长跑测试。

## 技术选择记录

- 引擎从 NaiveProxy 的源码树构建，而不是 Chromium 官方的 gclient 流程：googlesource 和 CIPD 在
  构建环境里不可达，NaiveProxy 的 GitHub 源码包可以拉到；GN 用 GitHub 上的镜像源码自编，
  Clang 从 commondatastorage 下载。
- 引擎做成单独的 `.so`、只开 8 个函数的窄接口，而不是把 Chromium 静态链进 Rust：方便单独
  校验、单独替换，也把 `unsafe` 关在一个 crate 里。
- 引擎关掉了 PartitionAlloc 当 malloc 和 allocator shim，因为它被加载进一个由 Rust 管内存分配
  的进程。
- 桥接保留，理由见上面的测量。
