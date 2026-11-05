# 验证范围

已恢复 `857ec949` 中仍适用的第一方测试，并增加桥接恢复、地址回退、订单退役和文件读取回归测试。完整任务状态、执行结果及限制见[安全实施记录](security/REPORT.md)。测试通过不等于生产部署验收。

## 可重复检查

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo xtask test
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
cargo xtask audit-native
cargo xtask verify
```

`xtask test` 分别执行 core、ACME、网络和 CLI 套件，每组必须至少有一项通过；零测试视为失败。普通 workspace 测试还覆盖运行时、信任根和文档测试。`verify` 在本机执行这些关键套件、格式、Clippy、Release 构建和 CLI 冒烟检查；指定交叉编译 target 时不执行目标二进制测试。

## 测试类别

- 纯单元：认证绑定、头部清理、帧解析、地址策略、配置和证书验证。
- 确定性状态/故障：`site::generation` 使用暂停时钟验证重建、取消、冷却和截止时间；ACME 测试验证持久化、DNS 所有权及退役。
- 本地传输：`net::tests` 使用临时 CA 和回环源站覆盖 H1/H2/H3、WebSocket、CONNECT、转发、取消及连接池隔离。生产代码无回环白名单开关。
- 隔离 ACME/DNS：`tests/acme_pebble.rs` 启动本地 Pebble 和 challtestsrv，覆盖签发、EAB、重启、更新和 DNS 故障。
- 可选：外部浏览器/客户端、抓包和微基准默认忽略。未提供的新模糊测试及长期 soak 不算已验证。

```sh
export PEBBLE_SOURCE=/path/to/pebble-source
export PEBBLE_BIN=/path/to/pebble
export CHALLTESTSRV_BIN=/path/to/pebble-challtestsrv
cargo xtask test-isolated
```

本次使用 Pebble v2.8.0。隔离套件不访问公网 DNS 或真实 CA。测试工具属于开发环境，不进入运行时依赖。抓包测试需要另行提供其工具和输出目录；恢复测试源码不表示已恢复全部实验工具。

## 验证边界

本轮仅验证 Linux GNU 主机；未验证 musl 镜像、其他目标、声明的最低 Rust 版本、真实域名部署、长期稳定性或吞吐。历史抓包摘要 [packet-lab-results.json](packet-lab-results.json) 不代表当前版本测量。独立控制进程、双证书自动管理及容量预留尚未实现，不能宣称完成安全重构。
