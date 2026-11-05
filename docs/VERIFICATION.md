# 验证范围

当前源码为 0.7.0。项目测试和抓包实验源码已移除，第三方 vendor 测试夹具仍保留。历史测试通过数不表示当前源码仍含相应测试，也不能用零测试运行作为验收。

## 已执行的本地检查

在本次文档整理前的生产源码精简中，已完成 GNU/Linux Debug 构建、Clippy、格式检查、依赖来源审计、源码包校验及 CLI 配置冒烟检查。使用同版本、同平台 BoringSSL 库，并将 CMAKE 指向不存在的路径时，构建和 Clippy 通过。

0.7.0 ACME 重构时的工作区测试及两项 Pebble 集成测试曾通过；对应测试已从当前源码删除。历史版本可在 Git 中查询，结果不等于公网 GTS/Porkbun 签发验收。

## 可执行检查

```sh
cargo build --workspace --locked
cargo clippy --workspace --locked -- -D warnings
cargo fmt --all -- --check
cargo xtask audit-native
```

`cargo xtask verify` 还会构建 Release 并检查 CLI 行为，需要 rustfmt、Clippy 和原生编译依赖。静态产物可用 `cargo xtask check-elf <binary>` 校验；这只能证明 ELF 格式和链接属性。

## 尚未确认

- 精简后的 Docker musl 镜像：此前在 Alpine 软件源下载阶段被网络策略阻止。
- 真实域名的公网 CA/DNS 签发、目标 VPS 部署、24 小时稳定性及公网吞吐。
- 配套 Chromium 客户端、ECH 完整无人值守运维和真实 DPI 识别率。
- 连续多次 QUIC NAT 重绑定的完整连接 ID 生命周期；历史记录提示第二次端口变化可能超时。

旧抓包摘要保存在[机器可读记录](packet-lab-results.json)，仅供追溯；对应实验工具和原始抓包不在当前源码中。不得将旧测量或指纹差异表述为当前性能或安全保证。
