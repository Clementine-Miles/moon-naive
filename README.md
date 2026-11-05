# moon-naive

基于 **Rust、Pingora、BoringSSL 和 quiche** 的 H2/H3 代理服务端，当前版本 **0.7.0**，面向 Linux x86_64。支持固定源站反向代理，以及经过认证的 CONNECT 和 HTTP(S) 正向代理。

仅支持 **moon-naive 修订4协议**，与官方 Naïve 客户端不兼容；配套 Chromium 客户端尚未实现。

## 证书管理

内置 `instant-acme` 客户端，负责账户注册、EAB、DNS-01 签发及自动续期，无需安装 `acme.sh` 或配置 cron。Porkbun DNS 凭据、CA（Google Trust Services / Let's Encrypt）和代理设置集中于一份私有 TOML。程序持久化账户与订单，清理挑战记录，校验证书后原子安装并热更新；续期失败时继续使用仍有效的证书。

## 构建与运行

需要 Rust 1.89+、C/C++、CMake、libclang、Perl 和 pkg-config。

```sh
cargo build --release --locked -p moon-naive
./target/release/moon-naive config init /path/to/config.toml
# 按 config.example.toml 填写域名、用户、DNS/EAB 凭据和 website.origin，接受 CA 条款。
./target/release/moon-naive check-config /path/to/config.toml
./target/release/moon-naive serve /path/to/config.toml
```

配置文件权限须为 `0600`，父目录须已存在。默认监听 TCP/UDP 443；首次运行自动申请证书，网站请求转发至配置的源站。

## 开发工具

构建使用 Cargo；审计和源码打包统一使用 `cargo xtask audit-native`、`cargo xtask source dist`。Rust 工具位于 `tools/xtask/`。BoringSSL 仍需要上述 C/C++ 工具链，普通构建无需 Python、Go 或 Docker；同平台重复构建可[复用 BoringSSL](docs/VPS-GUIDE.md#复用-boringssl避免重复调用-cmake)，避免再次调用 CMake。

## 文档

- [配置与证书](docs/CONFIGURATION.md) · [VPS 部署](docs/VPS-GUIDE.md)
- [协议](docs/PROTOCOL.md) · [架构](docs/ARCHITECTURE.md)
- [验证范围与已知限制](docs/VERIFICATION.md)

本地测试不代表公网 CA 签发、长期稳定性或 DPI 不可识别。许可证：Apache-2.0。
