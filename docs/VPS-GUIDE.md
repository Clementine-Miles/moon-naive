# 构建与部署

适用版本：0.7.0，Linux x86_64。程序在同一进程中管理证书、网站和 H2/H3 代理。配置字段见[配置指南](CONFIGURATION.md)，客户端要求见[协议](PROTOCOL.md)。

## 原生构建

首次构建需要 Rust 1.89+、C/C++、make、CMake、libclang、Perl、pkg-config、Git 和 CA bundle。系统包安装使用 root；Cargo 构建使用普通用户。

```sh
# Debian 12/13
apt-get update
apt-get install -y build-essential cmake libclang-dev perl pkg-config git ca-certificates

# Alpine 3.22
apk add --no-cache build-base cmake clang19-libclang linux-headers perl pkgconf git ca-certificates

# Arch Linux
pacman -S --needed base-devel cmake clang perl pkgconf git ca-certificates
```

使用已安装的 Rust 工具链；若需固定最低版本，先用 rustup 安装：

```sh
rustup toolchain install 1.89.0 --profile minimal
```

进入包含 Cargo.toml 的源码目录。源码包为 moon-naive-0.7.0-source.tar.gz；Git checkout 使用仓库根目录。

```sh
cargo +1.89.0 build --release --locked -j 2 -p moon-naive
./target/release/moon-naive --version
```

GNU 构建通常依赖目标系统的 glibc/libstdc++，不能直接用于 Alpine。

## musl 静态构建

推荐使用固定工具链的可选 Docker 镜像：

```sh
docker build -f deploy/Dockerfile.musl --target export --output type=local,dest=out/musl .
cargo xtask check-elf out/musl/moon-naive
```

若网络需要额外 CA，向构建命令加入 `--secret id=system_ca,src=/path/to/combined-ca-bundle.crt`，保持 TLS 校验开启。Docker 只用于构建，运行服务不需要 Docker。

在 Alpine 直接构建时，host build script 需要加载 libclang，目标程序保持静态链接：

```sh
mkdir -p target/build-support
rustc +1.89.0 --edition=2024 -C target-feature=-crt-static \
  tools/xtask/build-support/musl-host-rustc.rs \
  -o target/build-support/moon-naive-rustc-wrapper

moon_naive_gcc_headers="$(gcc -print-file-name=include)"
RUSTC_WRAPPER="$PWD/target/build-support/moon-naive-rustc-wrapper" \
LIBCLANG_PATH=/usr/lib/llvm19/lib \
BINDGEN_EXTRA_CLANG_ARGS="-isystem $moon_naive_gcc_headers" \
RUSTFLAGS="-C target-feature=+crt-static" \
cargo +1.89.0 build --target x86_64-unknown-linux-musl --release --locked -j 2 -p moon-naive
```

其他 Alpine/LLVM 版本应调整 libclang 路径。静态程序仍需系统 CA bundle；ELF 检查不等于目标发行版运行验收。

## 安装与配置

先准备服务用户。Debian/Arch 可用 `useradd --system --user-group --home-dir /var/lib/moon-naive --shell /bin/false moon-naive`；Alpine 使用对应的 addgroup/adduser 命令。已有用户和配置应保留。

以下以 GNU 构建为例；musl 构建改用对应二进制路径。

```sh
install -m 0755 target/release/moon-naive /usr/local/bin/moon-naive
install -d -m 0750 -o root -g moon-naive /etc/moon-naive
install -d -m 0700 -o moon-naive -g moon-naive /var/lib/moon-naive
moon-naive config init /etc/moon-naive/config.toml
chown moon-naive:moon-naive /etc/moon-naive/config.toml
chmod 0600 /etc/moon-naive/config.toml
```

编辑域名、用户、源站、DNS/EAB 凭据并接受 CA 条款。预先设置 A/AAAA，开放 TCP/UDP 443；启用明文跳转才需要 TCP 80。DNS-01 本身不需要入站 80。源站需实际运行。

以服务用户执行 check-config、check，再启动服务。`check-config` 是结构校验；`check` 会读取本地状态并要求接受条款；二者均不申请公网证书。

## 服务管理

systemd：

```sh
install -m 0644 deploy/moon-naive.service /etc/systemd/system/moon-naive.service
systemctl daemon-reload
systemctl enable --now moon-naive
journalctl -u moon-naive -f
```

OpenRC：

```sh
install -d -m 0750 -o moon-naive -g moon-naive /var/log/moon-naive
install -m 0755 deploy/moon-naive.openrc /etc/init.d/moon-naive
setcap cap_net_bind_service=+ep /usr/local/bin/moon-naive
rc-update add moon-naive default
rc-service moon-naive start
```

OpenRC 的 setcap 需要系统的 libcap 工具包；替换程序后重新设置。systemd 单元已声明低端口 capability。首次签发等待期间业务端口未监听；systemd 的启动等待由服务单元设置。修改默认排空期限时同步调整停止时限。

## 检查与发布工具

```sh
rustup component add rustfmt clippy
cargo fmt --all -- --check
cargo clippy --workspace --locked -- -D warnings
cargo xtask audit-native
cargo xtask verify
cargo xtask source dist
cargo xtask dist out/musl/moon-naive dist
```

`verify` 执行格式、Clippy、Release 构建及 CLI 冒烟检查；项目测试已移除。`source` / `dist` 生成确定性的 tar.gz 和 SHA-256，拒绝覆盖同名产物。源码文件清单依赖 Git；无 Git 元数据的解包副本需先建立基线。vendor 文件始终按校验清单收集。

`check-elf` / `dist` 使用 Rust 检查静态 x86_64 ELF，不需要 file/readelf。`platform-smoke` 是可选 Docker 运行检查，不能代表完整服务验收。验证结果与限制见[验证记录](VERIFICATION.md)。

## CPU 与传输诊断

`moon-naive status` 或 `moon-naive check-transport /etc/moon-naive/config.toml` 输出 CPU 能力、窗口和拥塞策略。memchr 与 BoringSSL 使用各自的运行时硬件检测；不需要额外 CPU 配置。

TCP BBR 依赖宿主内核，QUIC BBRv2 由 quiche 实现。程序不修改系统 sysctl/qdisc；算法、流控和实际公网吞吐应分别核对。内核版本参照诊断不能证明发行版是否回补安全修复，应以发行版公告为准。

## 复用 BoringSSL，避免重复调用 CMake

首次从源码构建仍需要 CMake、C/C++ 和 Perl；它们来自 boring-sys 的 BoringSSL 构建流程。quiche 已使用 boringssl-boring-crate，共用同一份 BoringSSL。

重复构建可使用 boring-sys 官方支持的预编译目录：

```sh
BORING_BSSL_PATH=/absolute/path/to/matching-boringssl-libs \
BORING_BSSL_INCLUDE_PATH=/absolute/path/to/matching-boringssl-headers \
cargo build --release --locked -p moon-naive
```

库目录需包含 libssl.a、libcrypto.a（或放在其 lib 子目录），头文件目录需包含 openssl/。仅复用由当前锁定 boring-sys 5.2.0、相同补丁、目标架构和 C 运行库构建的产物；GNU 与 musl 不可混用。不要设置 ASSUME_PATCHED 绕过来源要求。仍需 libclang 生成 Rust 绑定和系统链接器。此模式避免调用 CMake，但 Cargo 的传递构建依赖仍保留 cmake crate。

本机已用当前构建出的匹配库验证该模式，并将 CMAKE 指向不存在的路径以确认没有调用它；未验证跨平台预编译包。
