# 变更摘要

历史实现与测试代码可通过 Git 历史查询；旧文件名、命令和工作区路径不作为当前使用说明。

- 0.6.0：整合单进程证书管理、网站反代及 H2/H3 隧道；引入修订4认证、可选填充和传输调度改进。
- 0.7.0：ACME 账户管理独立成模块，EAB 注册统一由 instant-acme 处理，兼容已持久化账户。
- 后续精简：Rust 工具迁至 tools/xtask，新增 cargo xtask 入口；移除项目测试、实验工具和交接文件，保留 vendor 来源及校验清单。

当前使用说明见[部署](VPS-GUIDE.md)、[配置](CONFIGURATION.md)和[协议](PROTOCOL.md)。验证边界见[验证记录](VERIFICATION.md)。
