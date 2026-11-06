# ACME 隔离实验入口

这套夹具使用本地测试 CA、合成账户/EAB/DNS 凭据和独立状态目录。生产默认构建不含新增 keylog、任务计数器或故障注入。通用合成 CA 客户端期限为5秒；专门的超时与晚提交实验使用800毫秒，操作级超时实验使用30秒总期限和45秒HTTP期限。`tests/acme_pebble.rs` 的 keylog 位于测试 CA 服务端，因而不依赖 integration test 对 library 启用 `cfg(test)`。

环境：Linux x86_64、可用的 unprivileged user/network namespace、`ip`、Python 3、Git、curl、Debian archive keyring，以及本仓库的 Rust/BoringSSL 构建依赖。`setup.sh` 在工作区下载官方 Go 1.27.3（固定 SHA-256）、固定 Pebble v2.8.0 commit，并从带签名的 Debian trixie 仓库下载/解包 tcpdump 和 tshark；不写系统包目录。分析器可选使用 Python `cryptography`，本次实际使用 50.0.0；缺少它时明确标记独立密码学验证未运行，仍可解密/解析流量。

```sh
# 首先启用本环境的 Rust/CMake/clang 构建环境；新机器应按仓库构建说明安装。
source /workspace/.moon-naive-tools/build-env.sh
./tools/acme-lab/setup.sh
source tools/acme-lab/env.sh
python3 tools/acme-lab/run.py --run /workspace/acme-lab-artifacts/my-run
python3 tools/acme-lab/analyze.py /workspace/acme-lab-artifacts/my-run
```

`--run` 必须是尚不存在的新目录。默认执行全部组，某组失败仍继续执行后续组，最后非零退出。`--only unit|pebble|vendor|live|legacy|resolver` 可缩小范围。运行器的 600 秒保险期限会终止整个实验进程组并记录 124，不会把超时标记为通过。

- unit：原样执行 `cargo test --locked -p moon-naive --lib acme::`。新增确定性缺陷测试属于默认测试，当前有已复现的失败；它们没有被忽略或改成“预期失败”。
- pebble：先构建，再在隔离网络 namespace 执行 `cargo test --locked --test acme_pebble -- --ignored --test-threads=1 --nocapture`。这组因依赖外部工具保留原有 ignored 入口，包含新增故障 case。不是跳过故障断言。
- vendor：独立锁文件，`--no-default-features --features time,x509-parser --lib`；target 缓存在 vendor 目录之外。
- live：在真实 serve 和控制线程持续运行时观察两次续期、H2/H3 握手、旧连接及 ECH outer 失效/恢复；另有 TLS-LOADED I/O 故障和控制线程 panic 实验。
- resolver：在独立网络 namespace 中把系统 nameserver 的 IPv4 地址映射到 lo；真实 libc A/AAAA 请求被本地 UDP 夹具保留，取消等待者并 shutdown runtime 后才回复 NXDOMAIN。需要 IPv4 nameserver。不会改系统 resolv.conf 或向公网发送请求。
- legacy：重新执行其余 workspace library 测试，明确过滤新实验组以独立检查已有回归。完整默认测试仍包含失败的缺陷测试。

Pebble 固定 commit `d52948ce25e7c1576bcd18ff0e20a1c24ec7c44b`；challtestsrv 来自该源码和其锁定 Go 模块。`pebble-lab.patch` 只添加服务端 TLS keylog、验证前 barrier 和超时 case 的订单响应 barrier。setup 拒绝未知的源码差异。环境变量：

```sh
export PEBBLE_SOURCE=/absolute/pebble-source
export PEBBLE_BIN=/absolute/pebble
export CHALLTESTSRV_BIN=/absolute/pebble-challtestsrv
export ACME_LAB_ARTIFACTS=/absolute/private-artifact-directory
```

普通 Pebble case 可用 `ACME_LAB_NONCE_REJECT`、`ACME_LAB_AUTHZ_REUSE` 参数化；专门的 100% 拒绝和 100% 授权复用 case 不要求失败签发成功，也不要求复用时再创建 TXT。可重复“前 N 次 badNonce”由 Rust HTTPS mock 计数，不依赖随机拒绝概率。`ACME_LAB_FORCE_DNS_TCP=1` 令权威 facade 返回 TC，再进行真实 TCP 回退；生产 AA/事务校验没有放宽。

每个 case 保留 manifest、实际端口、PID、UTC 与单调时间、命令/退出码、服务日志、完整合成 journal、pcap 和 TLS keys。tcpdump 使用真实端口过滤及 immediate mode。失败会留下原始错误，不把日志称作抓包。分析器生成 `timeline.json`，逐帧列出 method、URL、status、problem、nonce、Retry-After、JWS/CSR 和 DNS，并合并带来源标签的 journal/测试事件。

`tls.keys` 的 BoringSSL 回调显式补换行并串行写入；不依赖 `SSLKEYLOGFILE`。本地 CA 信任和主机名验证保持开启。运行目录 0700；这些工件足以恢复合成私钥和会话，必须留在工作区，**不要加入 Git**。`analyze.py --index <path>` 只输出工件路径、长度、SHA-256 和计数的索引，可随脱敏报告提交。

当前发现、实际结果、逐文件最小生产修复设计和未覆盖边界见 [ACME 专项报告](../../docs/ACME-LAB.md)。
