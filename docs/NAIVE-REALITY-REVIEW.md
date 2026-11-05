# NaïveProxy 与 REALITY 对照摘要

moon-naive 采用自己的修订4认证，与官方 NaïveProxy 客户端不兼容，也没有实现 REALITY 的目标站握手校准。第三方版本和社区问题的历史分析不作为当前漏洞状态公告。

## 请求准入

认证 H2/H3 请求才可连接任意目标；网站 WebSocket 仅连接固定路由的源站。普通网站访问与认证失败流量使用同一网站引擎，但协议错误仍可能产生不同响应。

固定网站回源可以携带由服务端生成的转发元数据；通用 HTTP(S) 正向代理清理相应身份字段和 Via。动态压缩尊重请求和响应的 no-transform。实现见[网站引擎](../src/net/site/mod.rs)与[WebSocket 路由](../src/net/site/websocket.rs)。

认证、填充和客户端约束见[协议](PROTOCOL.md)；未完成的验收见[验证记录](VERIFICATION.md)。
