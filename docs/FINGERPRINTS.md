# 网络可观察性与限制

moon-naive 0.7.0 使用 BoringSSL、Pingora 和 quiche。组件选择不代表与浏览器或其他服务器具有相同指纹，也不证明更难识别。

- TLS/QUIC 握手、SNI、ALPN、HTTP 设置、包长、方向和时序均可能成为观察信号。
- 修订4认证绑定 TLS exporter、流 ID 和请求字段；认证不是流量隐藏机制。
- CONNECT 的有限初期填充或稀疏后段不生成空闲流量，也不能消除 TLS-in-TLS、关联或长度信号。
- 真实网站使用固定源站反代。网站与隧道的负载及关闭语义仍可能不同。
- 实验性 ECH 隐藏内部 ClientHello 名称，不隐藏 IP、公开名称、长度或时序；DNS、公开名称证书和轮换需要部署者管理。

线格式见[协议](PROTOCOL.md)，配置见[ECH 说明](CONFIGURATION.md#ech)。旧实验结果仅作为[历史测量摘要](packet-lab-results.json)保留；工具已移除，未完成真实 Chromium 客户端或公网 DPI 验收。验证边界见[验证记录](VERIFICATION.md)。
