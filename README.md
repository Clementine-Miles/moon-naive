# moon-naive

**mona 0.7.0**：面向 Linux x86_64 的 Rust 服务端，使用 Pingora、BoringSSL 和 quiche，
提供真实网站反代、认证 H2/H3 CONNECT 与普通 HTTP(S) 正向代理，内置 DNS-01 证书续期。
仅支持 [moon-naive 修订 4](docs/PROTOCOL.md)，不兼容官方 NaiveProxy；生产客户端尚未完成。

需要 Rust 1.89+、C/C++、make、CMake、libclang、Perl、pkg-config；生产运行无需 Go/Python。

```sh
cargo build --release --locked -p moon-naive
./target/release/moon-naive config init /path/to/config.toml
# 填写真实域名、用户、源站与 DNS/EAB 凭据，阅读并接受 CA 条款；配置权限 0600。
./target/release/moon-naive check /path/to/config.toml
./target/release/moon-naive serve /path/to/config.toml
```

[项目手册](docs/PROJECT.md) 统一说明配置、组件与认证路由、证书恢复、部署、实验及许可。
唯一配置模板是 [config.example.toml](config.example.toml)；state_dir 必须持久保存。
开发入口：`cargo xtask verify`、`cargo xtask vectors --check`、`cargo xtask lab`。
[验证与待办](docs/PROJECT.md#维护与验证记录) 区分已执行测试和未验收能力。许可证：[Apache-2.0](LICENSE)。
