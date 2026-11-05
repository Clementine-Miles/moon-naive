# 项目结构

0.7.0 使用一个 Cargo workspace 和锁文件，共三个包：moon-naive、moon-naive-core、xtask。

| 路径 | 职责 |
| --- | --- |
| [src](../src/) | 服务端 CLI、运行时、证书控制面及网络入口 |
| [src/acme/account.rs](../src/acme/account.rs) | instant-acme 账户创建、恢复及 EAB 协调 |
| [src/acme/manager.rs](../src/acme/manager.rs) | DNS-01 订单、续期、退避及恢复 |
| [src/acme/eab.rs](../src/acme/eab.rs) | EAB 导入和 instant-acme 注册适配 |
| [src/acme/state.rs](../src/acme/state.rs) / [store.rs](../src/acme/store.rs) | 日志、私有权限、证书 generation 和 CURRENT |
| [src/net](../src/net/) | TLS、H2/H3、隧道、ACL 拨号及固定下一跳 |
| [src/net/site](../src/net/site/) | 共用 Pingora 网站/正向代理、上游池和 WebSocket |
| [core/src](../core/src/) | 配置、认证、记录 codec、准入及额度策略 |
| [tools/xtask](../tools/xtask/) | Rust 审计、构建检查及发布打包 |
| [deploy](../deploy/) | systemd、OpenRC 和可选 musl 构建镜像 |
| [config.example.toml](../config.example.toml) | 唯一运行配置模板，config init 内嵌同一文件 |
| [assets](../assets/) | 对应内置 staging CA 的公开根证书 |
| [vendor/pingora](../vendor/pingora/) | 固定 Pingora 源码、补丁和校验清单 |
| [vendor/instant-acme](../vendor/instant-acme/) | 固定 instant-acme 源码及持久化私钥注册接口补丁 |
| [licenses](../licenses/) | 第三方许可文本 |
| [docs](./) | 使用、设计、限制与历史摘要 |

第一方单元、传输及隔离 ACME 测试已恢复；`tests/` 保存 CLI 和 Pebble 集成测试。HANDOFF 和外部抓包工具未恢复。vendor 中的公开测试夹具属于受校验的上游快照，不能直接清理。target、reports、dist 为生成目录，不属于运行依赖。

构建入口见[工具说明](../tools/README.md)，运行模型见[架构](ARCHITECTURE.md)。
