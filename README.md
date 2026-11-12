# moon-naive

基于 **Rust、Pingora、BoringSSL 和 quiche** 的 H2/H3 代理服务端，当前版本 **0.7.0**，面向 Linux x86_64。支持固定源站反向代理，以及经过认证的 CONNECT 和 HTTP(S) 正向代理。

简称 **mona**，仅支持 **[moon-naive 修订4协议](docs/PROTOCOL.md)**，与官方 Naïve 客户端不兼容；Android/Linux 实验客户端源码已导入并初步适配；完整构建和互通尚未验收，见[项目手册](docs/PROJECT.md#androidlinux-实验客户端)。

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

构建使用 Cargo；审计和源码打包统一使用 `cargo xtask audit-native`、`cargo xtask source dist`。Rust 工具位于 `tools/xtask/`。`cargo xtask verify` 包含实际测试；显式抓包实验统一从 `cargo xtask lab` 运行，前置工具和参数见[手册](docs/PROJECT.md#构建检查与维护边界)。BoringSSL 仍需要上述 C/C++ 工具链，普通构建无需实验工具或容器环境；同平台重复构建可[复用 BoringSSL](docs/PROJECT.md#复用-boringssl避免重复调用-cmake)，避免再次调用 CMake。

## 文档

配置、协议、ACME 恢复、原生构建与部署统一见 [项目手册](docs/PROJECT.md)。组件、认证流量路由、源码比例与 Go 边界见[架构解析](docs/PROJECT.md#当前组件与所有权2026-11-12)。

验证：`cargo test -p moon-naive-core --locked`、`cargo test -p moon-naive --lib --locked`。进度与已知差距见 [实现记录](docs/IMPLEMENTATION.md)。编译检查不等同运行验收。许可证：Apache-2.0。
