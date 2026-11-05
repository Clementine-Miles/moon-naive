# 开发工具

- `xtask/`：Rust 审计和发布工具，统一由 `cargo xtask` 调用。
- `xtask/build-support/`：Alpine musl host 的 Rust 编译包装器，仅静态构建需要。

常用命令（仓库根目录）：

```sh
cargo build --release --locked -p moon-naive
cargo xtask audit-native
cargo xtask check-elf /path/to/static-moon-naive
cargo xtask source dist
```

`source` / `dist` 使用 Rust 库生成 tar.gz、SHA-256 和 ELF 校验，无需额外安装 tar、gzip、sha256sum、file 或 readelf。源码文件清单仍通过 Git 获取，默认固定 Git 依赖也需要 Git。所有现有 `cargo run -p xtask -- ...` 命令仍可使用。

生产镜像保留 C/C++、make、CMake、libclang、Linux headers、Perl、pkg-config 和 Git；BoringSSL/bindgen 需要这些工具。rustfmt/Clippy 在需要开发检查时用 rustup 单独添加。Rust 依赖锁文件不变。
