# moon-naive 项目手册

适用版本 0.7.0。本文统一原配置、协议、部署、ACME 生命周期、构建工具与信任根说明；仓库原有目录是 `docs`，没有 `docx`。主配置模板仍以 [config.example.toml](../config.example.toml) 为准。

本项目基于 Rust、Pingora、BoringSSL 和 quiche，面向 Linux x86_64。仅实现 moon-naive revision 4；官方 Naïve 客户端不兼容，已引入 Android/Linux Chromium 实验客户端源码，完整构建与互通尚未验收。

第一方离线/loopback 测试正在恢复；执行状态见 [实现记录](IMPLEMENTATION.md)，协议以 [mona revision 4](PROTOCOL.md) 为准。

- [配置与迁移](#配置与迁移)
- [协议与架构](#协议与架构)
- [ACME 状态与 TLS 激活](#acme-状态与-tls-激活)
- [原生构建与部署](#原生构建与部署)
- [构建检查与维护边界](#构建检查与维护边界)
- [Android/Linux 实验客户端](#androidlinux-实验客户端)
- [历史审阅与实验记录](#历史审阅与实验记录清理前)
- [Staging 信任根来源](#staging-信任根来源)

## 配置与迁移

只维护一份 [config.example.toml](../config.example.toml)。模板包含基础字段和高级参数。`schema_version` 默认2，仍兼容旧1/2；配置更新需要重启，证书续期和热更新自动完成。

### 最短使用流程

先按 [原生构建与部署](#原生构建与部署) 安装程序、服务用户和系统 CA。以服务用户在可信、可写目录执行：

```sh
moon-naive config init /path/to/config.toml
# 编辑配置，填入自己的域名、用户、源站、Porkbun API 和 GTS EAB，并接受 CA 条款。
moon-naive check-config /path/to/config.toml
moon-naive check /path/to/config.toml
moon-naive serve /path/to/config.toml
```

`config init` 只生成模板，0600、原子发布且拒绝覆盖文件/软链接，不访问网络。生产安装通常使用 `/etc/moon-naive/config.toml`；若该目录只有 root 可写，由 root 生成后交给服务用户所有。二进制内嵌同一模板，安装后不需要保留源码目录。

| 基础字段 | 填写内容 |
| --- | --- |
| `domain` | 代理/网站主机名，例如 `proxy.example.dev`；预先设置 A/AAAA 指向可达的 VPS |
| `proxy.users` | 一个或多个用户名和独立长随机密码 |
| `website.origin` | 固定源站，如 `http://127.0.0.1:8080` 或 `https://origin.example.net` |
| `acme.issuer` / `environment` | 示例显式选择 `google` / `production`；测试时用 `staging` 和对应测试 EAB |
| `acme.contact` | 联系邮箱，不带 `mailto:` 前缀 |
| `acme.dns_zone` | Porkbun DNS zone，例如 `example.dev`；保留显式填写，避免把 `co.uk` 等公共后缀误猜成 zone |
| `acme.dns_credentials` | `apikey` 与 `secretapikey`，两项都需要 |
| `acme.eab` | GTS 返回的 `keyId` 填 `key_id`，`b64MacKey` 填 `b64_mac_key` |
| `acme.accept_terms` | 阅读所选 CA 条款后显式改为 `true`，默认 `false` 不允许签发 |

`check-config` 只做离线结构、字段及策略校验，允许尚未接受条款的模板通过，**不表示密钥已通过服务商验证**。`check` 额外读取本地凭据/证书、验证运行条件并初始化状态目录，不访问 CA/DNS、不绑定端口；它与实际 ACME 工作一样要求接受条款。`serve` 首次签发成功后才监听，之后自动续期；无需另一份证书配置、手工搬运 PEM、certbot 或 cron。

#### 可以省略的配置

- `schema_version=2`、`state_dir="/var/lib/moon-naive"`；后者需服务用户可写并持久保存。
- 整个 `[listener]`：IPv4 TCP/UDP 443，H1网站/H2/H3开启，80跳转默认关闭。H2/H3仍必须开启，H1仅网站；IPv6需显式配置监听地址。
- 整个 `[limits]`：100条流、128连接、64MiB共享接收窗口预算；完整数值见示例注释。
- `[acme]` 中的 `enabled=true`、`challenge="dns-01"`、`dns_provider="porkbun"` 和超时/续期/退避参数。
- `[transport]` 默认 `system/cubic`，无需先开启内核 BBR；按需覆盖为 `bbr/bbr2`。

省略 issuer 仍为 `letsencrypt`，省略 environment 仍为 `staging`，不会暗中将旧配置的 CA/账户切到 GTS 或 production。推荐保留示例中这两项显式选择。每个可选表允许只写需覆盖的字段；未知字段仍报错，不因默认值而默默吞掉拼写错误。

`website.origin` 展开为一个固定池和 `/` 路由，并将回源 Host 设为源站 authority（含显式端口）；HTTPS 默认以源站主机名进行 SNI 和证书校验。它只能包含 HTTP(S) scheme、主机、可选端口和可选末尾 `/`，不接受登录信息、子路径或 query。不能与 `website.upstreams/routes` 同时配置。没有 website 配置时仍可启动，但没有完整网站，通常返回404；推荐始终配置真实源站。

源站不能指回对外域名形成循环；程序不自动改写源站的 Location、Cookie、HTML 或脚本。需要按路径分流、自定义 Host/SNI/CA 时，删除 `origin`，使用下方高级路由表。

配置文件必须为服务用户所有的普通文件、权限0600；父目录可信，状态目录0700。拒绝软链接，解析错误不回显原始文本。`config init` 不填真实密钥，也不自动接受条款。

### 用户与可选下一跳

```toml
[[proxy.users]]
username = "alice"
password = "replace-with-a-unique-random-password"

[acme.dns_credentials]
apikey = "pk1_REPLACE_ME"
secretapikey = "sk1_REPLACE_ME"

[acme.eab]
key_id = "REPLACE_WITH_KEY_ID"
b64_mac_key = "REPLACE_WITH_BASE64URL_MAC_KEY"

# 可选：只支持一个下一跳；省略整表为直连。
[proxy.upstream]
kind = "https" # http / https / socks5
address = "upstream.example.net:443"
username = "upstream-user" # 不需要认证时连同 password 一起省略
password = "upstream-password"
# HTTPS 可选 tls_server_name、ca_file；始终校验证书和名称。
```

主配置已有这些表时编辑现有内容，不重复追加。用户数 1..256，用户名不重复，密码至少 16 字节，建议独立随机 32 字符以上。Cloudflare 使用 `[acme.dns_credentials] api_token`，不要混入 Porkbun 字段。Google EAB 为账户首次注册凭据，已有持久账户续期不重复消耗 EAB。

`[listener] h1 = true` 开启网站 HTTP/1.1 和无 ALPN 回退，**不开放 H1 正向代理**。H1 CONNECT 返回有正文的 404/405；H2/H3 认证 CONNECT 先完成目标连接再 200。`http_redirect = "0.0.0.0:80"` 是可选的纯 HTTP 308 跳转监听，仅接受配置域名，保留路径/query；删除字段即禁用。它与 TLS/QUIC 一同在证书就绪后启动，不负责 HTTP-01。网站响应 `Alt-Svc` 使用配置的 UDP 端口，防火墙/NAT 应对外保持该端口；不继承上游 Alt-Svc。

省略整个 `[listener]` 或其中的 `tcp`、`udp` 时，两者均默认为 `0.0.0.0:443`；显式地址仍优先。H1 请求头必须在 10 秒内完整到达（含等待首字节的 keepalive 空闲时间），每连接最多 1,000 个请求；请求体、SSE、WebSocket 使用各自的读写/空闲限制，不受这 10 秒头部期限截断。H3 完成 Retry 后也必须在 10 秒内完成 TLS，否则释放连接和接收窗口配额。

H1 拒绝 CL+TE、重复/逗号合并 Content-Length、重复/非单一 chunked 的 Transfer-Encoding、裸 LF、折行及超限请求头，返回 400 后关闭连接；普通浏览器的规范请求不受影响。已校验相等的 H2/H3 Content-Length 在送入网站反代时归一成单个十进制值。原始 H1 头与 H2/H3 解码头均受网站入口的 32 KiB / 128 字段限制；不是宣称第三方解析器所有临时内存也只有 32 KiB。

网站请求不向后端泄露 Proxy-Authorization、Naïve Padding、客户端伪造的 Forwarded/X-Forwarded-* 或 CGI 下划线别名；保留网站自己的 Authorization 和普通业务字段。`Proxy` 字段也被移除，避免 CGI 的 HTTP_PROXY/httpoxy 风险。头部与 trailers 同样执行清理。网站/上游响应移除代理元数据，保留正常正文、ETag、Cache-Control 等网站语义，不伪造其他服务器或 CDN 的身份。

`[transport] quic_congestion = "bbr2"` 使用 quiche BBRv2 与 pacing；`tcp_congestion = "bbr"` 在入站、代理拨号和网站上游 socket 上设置并读回内核 BBR。内核不支持则拒绝启动，程序不改 sysctl/qdisc，不声称内核 bbr 一定是 BBRv2。省略 transport 的兼容默认值为 cubic/system。Fast Open和0-RTT在实现中禁用；`fast_open`、`zero_rtt`旧字段已删除，运行配置拒绝它们。使用 `moon-naive config migrate old.toml new.toml` 可清除旧false字段；true或非布尔值拒绝迁移。

程序在TCP监听前设置BBR，使尚未被accept的子连接也继承该策略。保留内核管理的收发缓冲，没有用固定SO_SNDBUF/SO_RCVBUF关闭自动调整。Linux的QUIC驱动用一个timerfd等待quiche给出的发送期限，避免毫秒计时器限制微秒级pacing；UDP阻塞时等待可写事件，64包处理额度用完后主动续调度。两种拥塞控制独立工作，均不新增空闲假流量或扩大认证前接收额度。

`check-transport`额外输出新socket读回的`tcp_congestion_effective`，以及H2/H3初始流窗口、H3增长上限、连接窗口和总接收预算。`system`可能已经继承VPS启用的BBR；实际连接仍应使用`ss -tin`检查。H2初始流窗口是`min(max_early_data_bytes,max_buffer_bytes_per_stream)`，不会在认证后自动变成后者；H3根据实际读取增长，最高为后者。服务端接收窗口影响上传，客户端接收窗口影响下载。只提高服务端内存上限不能解除客户端窗口或公网瓶颈。

上游链先本地解析最终目标并执行公网 IP ACL，再向配置的下一跳建立 CONNECT/SOCKS5 通道，SOCKS5 发送已检查的 IP，不委托远端 DNS。HTTP(S) 支持 Basic，SOCKS5 支持无认证或用户名密码。上游错误不回退直连。不是多跳任意链，也不允许通过它放行内网。已认证 H2/H3 普通 HTTP 请求使用相同出站策略，连接池按用户和目标 origin 隔离；不提供 407 引导认证或 H1 通用代理。

HTTP、SOCKS5 下一跳协议本身不提供 TLS；不能把本服务的入口加密当作下一跳链路加密。对不可信网络应选校验 CA/名称的 HTTPS 下一跳，或由部署者提供受保护的承载。CONNECT 也不会替任意明文目标协议提供端到端身份验证。

普通 HTTPS 正向代理的系统 CA bundle（可由 `SSL_CERT_FILE` 指定）在每个应用实例首次使用时加载并共享，更新系统根证书后重启服务。仍验证目标证书链和名称；不需要新增 TOML 字段。这与网站自己的 ACME 证书自动续期/热更新无关。

固定HTTPS下一跳的CA文件和TLS上下文在启动预检的阻塞工作线程上构建一次，所有目标隧道共享这份只读上下文；每次仍创建独立TLS连接并校验证书链和名称。配置了不可读或无效的下一跳CA时，本地预检直接失败。更新下一跳CA/系统根证书后需要重启，不再在每次代理建连时重读；网站ACME证书仍按原机制热更新。HTTP/SOCKS5下一跳不初始化TLS上下文。

CPU加速自动使用部署主机的可用能力，无需增加TOML项。`moon-naive status` 或 `moon-naive check-transport /etc/moon-naive/config.toml` 输出架构、CPU能力和库的运行时分派方式。字节扫描采用memchr的AVX2/SSE2/通用路径，SHA-256与TLS分别保留sha2和BoringSSL的硬件检测；AVX-512检测为true不表示所有算法都会选用512位指令。诊断命令见[部署指南](#cpu-与传输诊断)。

### 兼容旧配置与安全合并

schema v1/v2 的主配置加独立 users/Porkbun/EAB TOML 继续支持；旧示例文件已移除，新部署统一使用单文件示例。每类凭据只能选内联或文件一种来源。旧 `users.toml` 用 `[[users]]`，Porkbun 用 `apikey/secretapikey`，EAB 用 `key_id/b64_mac_key`。旧私有文件仍须 0600。

```sh
moon-naive config migrate /etc/moon-naive/old.toml /etc/moon-naive/config.v2.toml
chown moon-naive:moon-naive /etc/moon-naive/config.v2.toml
# 检查内容和权限后，停服务并切换到新配置。
```

迁移命令读取旧文件并写出完整 schema v2 TOML，0600、原子且拒绝覆盖现有目标；不修改源文件、账户、订单、TXT journal 或证书 CURRENT。不要在终端打印合并后的配置。迁移后由服务用户拥有新文件。

`moon-naive acme import-eab private-gcloud-export.json new-eab.toml` 仍可把 gcloud 导出转换为私有 TOML，随后将两个字段合并到主配置 `[acme.eab]`，或作为兼容文件引用。该命令不注册账户、不访问网络、不覆盖目标。Staging/production 使用分别申请的 EAB；`.dev` 浏览器需要 production 受信任证书。

### 旧状态迁移

升级时停止旧进程，保留完整 state_dir（账户、订单、TXT 清理日志和证书 CURRENT），调整所有者和权限后再启动。不要清空状态来重试签发。运行配置使用 TOML，内部 ACME journal 和 API 报文仍使用 JSON。

### 网站与反代

网站仅支持固定源站反代。删除旧 `site_root`、`website.files`、`website.static_cache_secs` 字段；它们现在作为未知字段拒绝。推荐填写 website.origin，由程序展开为固定 upstream 和 `/` 路由；高级配置再显式填写 upstreams/routes。源站不可达时返回普通 502，不回退到内置页面或本地文件。

| 字段 | 默认 | 含义 |
| --- | --- | --- |
| compression_level | 5 | gzip 等级 0..6，0 关闭；Range/HEAD/SSE、请求或响应 no-transform 不动态压缩 |
| max_request_body_bytes | 67108864 | 最大请求体，支持至 1 GiB，显式长度与流式读取均检查 |
| connect_timeout_secs | 5 | 上游连接/DNS 时限 |
| read_timeout_secs / write_timeout_secs | 30 / 30 | 上游读/写时限 |
| upstream_idle_secs | 60 | 上游池空闲期限 |
| dns_ttl_secs | 60 | 固定上游解析缓存有效期 |

最多 32 个池、128 条路由，每池 1..16 个固定 `origins`。origin 只接受 HTTP/HTTPS 的 scheme/authority，无账号、路径或 query；客户端 authority 不能成为反代目标。路由按最长字面前缀匹配，不解码 `%xx`，`/api/` 不匹配 `/api`；`strip_prefix` 保留原始转义、重复斜杠和 query。

上游 `tls_server_name` 为 SNI/校验名称，`host_header` 为应用 Host，`ca_file` 为私有 CA bundle（最多 1 MiB）；没有关闭证书校验的开关。`http2 = true` 允许 HTTPS 协商 H2。不同池隔离连接；轮询和连接失败冷却 5 秒，仅安全方法的建连失败允许有限回退，最多两次尝试，不重放 POST。

代理认证/Padding 不转发给网站上游，客户端自报的 Forwarded/X-Forwarded-* 被清理，使用真实对端 IP 生成 X-Forwarded-For，并生成 https scheme 和网站 Host。目前没有可信前置代理列表，套在 CDN 后会看到 CDN 对端地址。管理员固定的私网上游与 Naïve 出站 ACL 分开。

`max_total_receive_bytes` 是连接接收信用预留总预算，不是 RSS 限额。默认总预算 64 MiB，按 128 个连接槽位分配每连接 512 KiB；实际容量及 QUIC 控制流保留额由 check-transport 报告。调整会改变资源和网络行为，应按目标负载测量。

### 高级网站协议与边界

固定网站路由支持 H1 WebSocket Upgrade，以及 H2/H3 `:protocol = websocket` 的扩展 CONNECT，转换为固定上游 H1 握手，校验接受值和子协议，保留握手后一并到达的数据。它无需代理密码，但只允许配置域名/路径/上游，不能变成任意目标隧道；不支持 MASQUE、CONNECT-UDP、WebTransport。

100/103 中间响应、请求/响应 trailers 在 H1/H2/H3 网站路径转发；H1 使用 chunked。删除 trailer 中的认证、路由及消息分帧字段。SSE 和 gRPC 不动态压缩，gRPC 使用支持 H2 的 HTTPS 网站 origin。普通 HTTP 请求受请求体大小上限约束；成功升级后的 WebSocket 不按累计字节套用该上限，仍受缓冲、连接/流预算及读写/空闲期限约束；长时间无数据的 SSE 应由上游定期发心跳或调大 read_timeout_secs。

保留路由、压缩、固定反代；未引入内置静态文件、管理 API、目录浏览、模板、动态任意路由、MASQUE 或插件加载。配置与用户修改需重启，证书自动热更新，网站内容由真实源站维护。该功能范围不等于 Caddy 全部生态。

### 网站路由示例

用下列内容替换主配置中的 `[website]`，并删除简写 `origin`，勿重复追加同名表。

```toml
# Merge this entire block into the main configuration. This is not a standalone config.
[website]
compression_level = 5
max_request_body_bytes = 67108864
connect_timeout_secs = 5
read_timeout_secs = 30
write_timeout_secs = 30
upstream_idle_secs = 60
dns_ttl_secs = 60

[[website.upstreams]]
name = "app"
origins = ["http://127.0.0.1:3000"]
# HTTPS origins verify both their certificate and name. Optional overrides:
# tls_server_name = "origin.example.dev"
# host_header = "origin.example.dev"
# ca_file = "/etc/moon-naive/origin-ca.pem"
http2 = true

[[website.routes]]
path_prefix = "/api/"
upstream = "app"
strip_prefix = true
# /api/users?limit=10 becomes /users?limit=10; unmatched paths return 404.
```

### ECH

实验性接入，默认关闭。

```toml
[ech]
public_name = "public.example.dev"
keys_file = "/var/lib/moon-naive/ech-keys.toml"
certificate_file = "/etc/moon-naive/public-fullchain.pem"
private_key_file = "/etc/moon-naive/public-key.pem"
```

公开名称必须由你控制且证书包含精确 DNS SAN。它仍在 ClientHelloOuter 中可见；使用与代理域名相同的名称不能隐藏该域名。公开名称证书目前需要外部签发/续期，现有自动 ACME 仍管理主域名。私钥和 ECH 密钥文件要求 0600；父目录必须由服务管理员控制。

`moon-naive ech init config.toml` 创建 X25519 ECH 密钥及 ECHConfig，拒绝覆盖已有文件。`ech check` 检查密钥、配置配对和公开证书期限/SAN/私钥；不验证 DNS 或公网证书信任。`ech dns` 输出主域名的 HTTPS RR，只有公有 ECHConfigList，没有私钥。命令不修改 Porkbun DNS。记录需与你已有 HTTPS RR 合并，不能盲目覆盖；使用非标准端口还需设置相应 port 参数。

启动或重启前先运行 `ech check`；服务端部署成功后才发布 DNS。客户端需要支持 ECH 并实际获取这条 HTTPS RR（建议可信的加密 DNS），仅携带 ECH GREASE 不代表成功。客户端必须检查 ECH accepted，正确处理经公开名称认证的 retry_configs，不能在要求 ECH 时静默明文 SNI 回退。当前未修改 Naive 客户端。

密钥文件为独立 0600 TOML，避免私钥被复制到 DNS：

```toml
[[keys]]
config = "BASE64_SINGLE_ECHCONFIG"
private_key = "BASE64_RAW_X25519_PRIVATE_KEY"
retry = true
```

最多八个唯一 config ID，至少一个 retry=true。轮换时可同时加载新旧密钥，旧密钥 retry=false 保持解密但不再公布，待 DNS TTL 和缓存宽限期后移除。当前仍需要管理员生成与部署新密钥、管理 DNS。维护线程每 5 秒检查 ECH 密钥集、公开证书、公开私钥内容；变化后验证并整体替换 TCP/QUIC TLS 上下文，失败保留旧配置。已有连接不被强制切断。部署时用原子文件替换，先将新旧密钥同时部署到所有实例，再更新 DNS，等待 TTL/缓存宽限期后移除旧密钥。路径或 public_name 的 TOML 修改仍需重启；这不是自动密钥生成/轮换或 DNS 发布。公开名称现已作为同一固定网站的别名接入 H1/H2/H3 反代及网站 WebSocket；正确代理凭据不会把该网站请求变成正向代理。明文跳转保留公开名称。其他未配置 Host 仍拒绝。源站如要求固定 Host，可配置 upstream 的 host_header；站内绝对链接、重定向和 Cookie Domain 需要源站正确适配。

TCP 与 QUIC 共用同一组 ECH 密钥，并在 ECH 解密后选择内部/公开名称证书。当前属于实验性服务端接入，不能称为完整无人值守 ECH。ECH 不隐藏服务器 IP、公开名称、包长、时序，也不替代内层 TLS 流量的 Padding。


### 自动证书

`moon-naive serve` 已集成自动 ACME：首次无有效证书时等待 DNS-01 签发，验证并安装后启动 H2/H3；随后自动续期和热更新，不再需要独立 ACME 服务。网络和控制面在同一进程的不同 runtime/线程运行。

推荐 Porkbun 注册、实际由 Porkbun 权威 DNS 托管的 `.dev` 域名，使用 Google Trust Services（GTS）。部署见 [VPS-GUIDE.md](#原生构建与部署)。`.dev` 浏览器访问需要正常受信任的 production 证书；staging 证书不会因此受信任。

#### Porkbun 与 GTS

在 Porkbun 为目标域名启用 API access，在私有主配置 `[acme.dns_credentials]` 中填写 `apikey`、`secretapikey`（兼容旧 `porkbun.toml` 引用）。配置 `dns_zone` 为注册 zone，例如 `example.dev`，不是完整代理主机名；程序检查实际 NS 委派，不会替你切换 DNS 服务商。

GTS 的首次账户绑定需要同一环境的 EAB。主配置 `[acme.eab]` 使用 `key_id`、`b64_mac_key`；可本地转换 gcloud 的私有导出：

```sh
moon-naive acme import-eab /private/gcloud-export.json /private/gts-eab.toml
```

输入须为私有文件，输出以 0600 创建且拒绝覆盖。导入只做本地格式转换，可将生成的两个字段合并进主配置 `[acme.eab]`，或保留兼容的外部引用，不能同时配置两种来源。Staging/production 的 EAB 不通用，首次注册后复用持久化账户；已持久化注册 key 时，账户注册响应丢失也会先按原 key 恢复，不会要求重复消耗 EAB。

建议先使用 staging 及对应 EAB，确认 DNS-01，再停止服务、完成待清理 TXT、切换 production 及对应 EAB。不同目录有不同 journal。设置 `accept_terms = true` 前自行接受 CA 条款；程序不替操作者接受条款。

若 zone 已设置 CAA，应允许 GTS 的 `pki.goog`；程序不覆盖 CAA。附带的 GTS/Let's Encrypt 测试根只用于对应内置 staging 证书校验，不加入 production 或 DNS-provider HTTPS 信任库。

#### 生命周期与恢复

管理器持久化账户 key/URL、订单/证书 key/CSR、DNS TXT 意图与所有权标记、退避、Retry-After 和 ARI 续期窗口。网络操作前写入意图，响应不确定时按标记恢复；只清理自己创建的记录，保留借用或他人的 TXT。权威传播检查验证 DNS 响应，截断时转 TCP。

证书经 BoringSSL 检查 SAN、私钥匹配、链、有效期、叶证书用途，再 fsync generation、原子更新 CURRENT。失败不替换仍有效的证书。CURRENT 未变化时不反复构造 TLS 上下文；变化后共同发布 H2/H3 generation，坏更新保留有效旧上下文，过期后拒绝新握手。

状态目录使用 kernel 文件锁，进程死亡后释放；不要删除状态目录或锁文件来绕过正在运行的服务。升级或移动目录时保留整个 `state_dir`，包括 pending 订单和待清理记录。

#### 维护命令

```sh
moon-naive status /etc/moon-naive/config.toml
moon-naive acme check-ca /etc/moon-naive/config.toml
moon-naive acme once /etc/moon-naive/config.toml
moon-naive acme cleanup /etc/moon-naive/config.toml
```

`status <config>` 本地重验已安装证书，并报告绑定 PID/启动时间/boot ID 的续期 worker 心跳；它不探测监听器。TLS-LOADED 是可过期的诊断观察，不能替代真实 H2/H3 握手。`check-ca` 只读 HTTPS directory，不创建账户或订单，不改 DNS。`once` 执行当前计划允许的一次协调，不强制提前续期；重试/无证书返回非零。`cleanup` 只重试 journal 记录的 DNS 清理。另有 `acme run` 供独立维护使用，不能与读取同一状态的 `serve` 同时运行。

当前支持单机单域名；Google/Let's Encrypt CA 与 Porkbun/Cloudflare DNS 独立选择。多 SAN/通配符、按需域名、分布式锁、多 CA 自动切换和 OCSP stapling 不在本版本范围。公网签发需要实际域名与私有凭据；本次本地测试不替代公网 CA/DNS 验收。

#### GTS EAB 获取步骤与官方依据

参考：[Google Public CA 教程](https://cloud.google.com/certificate-manager/docs/public-ca-tutorial)、[Porkbun API 入门](https://porkbun.com/llms/guides/getting-started)、[Porkbun DNS API](https://porkbun.com/llms/dns)。运行时 API 基址仍为 `https://api.porkbun.com/api/json/v3`；JSON 凭据字段为 `apikey/secretapikey`，TXT 创建/检索/删除接口及所有权 notes 与当前实现对应。

在自己的管理机器登录 gcloud，选择 Google Cloud 项目并具备 Public CA External Account Key Creator（`roles/publicca.externalAccountKeyCreator`）等相应权限；启用 API 还需要该项目的服务启用权限。运行：

```sh
gcloud config set project YOUR_PROJECT_ID
gcloud services enable publicca.googleapis.com
# production：先清除可能遗留的 staging API override。
gcloud config unset api_endpoint_overrides/publicca
gcloud publicca external-account-keys create --format=json
```

从私有输出中复制 `keyId`、`b64MacKey` 到主 TOML。GTS EAB 必须在生成后7天内用于首次注册，一次只能注册一个账户；持久化账户本身不会因为 EAB 过期而到期，后续自动续期不需要新 EAB。不要把 Google Cloud API key、服务账户 JSON、Porkbun key 或证书内容填入 EAB 字段。程序不从 Porkbun 下载其免费证书，而是向配置的 GTS ACME 目录申请证书。

若要测试 staging，使用独立的 gcloud 命名配置，避免把日常 production 命令留在测试端点：

```sh
gcloud config configurations create moon-naive-staging --no-activate
# 按你的 gcloud 环境为该配置选择已登录账号和项目。
gcloud --configuration=moon-naive-staging config set account YOUR_GOOGLE_ACCOUNT
gcloud --configuration=moon-naive-staging config set project YOUR_PROJECT_ID
gcloud --configuration=moon-naive-staging config set api_endpoint_overrides/publicca https://preprod-publicca.googleapis.com/
gcloud --configuration=moon-naive-staging publicca external-account-keys create --format=json
```

程序中改 `acme.environment="staging"` 并填写这组 EAB；证书不受浏览器信任。GTS production/staging 目录分别为 `https://dv.acme-v02.api.pki.goog/directory`、`https://dv.acme-v02.test-api.pki.goog/directory`。回到 production 前停止服务并清理待处理 TXT，再同时切换环境和对应 EAB，保留全部 state_dir。

Porkbun 除生成两项 API 凭据外，还需在目标域名 Details 中启用 API access。密钥需允许该域名的 NS读取及 DNS TXT 读写删除；仅在 Porkbun 注册但使用其他权威 DNS 不符合此 provider。程序保留委派检查、DNS传播校验和仅清理本程序拥有记录的规则，不自动扩大密钥权限。

#### 其他 CA/DNS 组合

现有 Let's Encrypt / Cloudflare 支持保留。例如编辑已有 `[acme]` 及其凭据表：

```toml
[acme]
issuer = "letsencrypt"
environment = "staging"
dns_provider = "cloudflare"
dns_zone_id = "0123456789abcdef0123456789abcdef" # 替换为真实 Zone ID，不是 Account ID。
contact = "operator@example.net"
accept_terms = false # 使用前接受该 CA 条款并改 true。

[acme.dns_credentials]
api_token = "REPLACE_WITH_SCOPED_API_TOKEN"
```

删除原 Porkbun 两项字段及 GTS EAB 表，其他主配置保留；CA 与 DNS provider 是独立选择。自建/私有 CA 可显式设置 `directory_url`、`directory_ca_file`、`certificate_ca_file`，分别控制 ACME API 与所签证书的信任，不会把测试根加入生产信任库。

#### 常见配置问题

| 现象 | 核对项 |
| --- | --- |
| 配置文件不私有或不可读 | 确认服务用户拥有文件、0600、父目录可访问，编辑器没有改成软链接/0644 |
| `accept_terms` 拒绝启动 | 接受当前 CA 条款后在已有 `[acme]` 中设 true；check-config 通过不表示已同意 |
| EAB base64url 错误 | 复制 b64MacKey 原文，不填 JSON/PEM，不夹杂空格；线上注册失败还需核对环境与7天有效期 |
| 首次一直等待证书 | 检查日志中的失败阶段、API access/权限、真实 NS、CAA、DNS传播及 HTTPS/DNS 出站；保留退避与状态，不删目录 |
| 网站502或跳转到源站 | 检查 origin可达性、证书和虚拟主机配置；绝对跳转/链接不自动改写 |
| 官方 NaïveProxy 客户端连不上 | 本项目协议修订4不兼容官方旧认证，配置简化不改变此事实 |


### instant-acme 账户实现

ACME 协议请求（包括 EAB JWS、nonce 重试、订单和 ARI）统一由 instant-acme 处理，DNS 操作由内置 Porkbun 或 Cloudflare 适配器完成，无 shell hooks。账户私钥在联网前持久化；遇到一次性 EAB 注册响应丢失，先用同一私钥查找既有账户，再决定是否注册。旧版仅保存 account_id/key 的日志仍可恢复。

固定版本的 instant-acme 已随 vendor 提供。本地 API 补丁允许使用已保存的私钥和 EAB 调用其原有注册实现，来源与差异见[接口补丁说明](../vendor/instant-acme/MOON-PATCH.md)。无需删除状态目录或重新申请 EAB。

### 资源与恢复配置

`[limits]` 新增可选项：`max_pending_requests=100`、
`max_tunnels_per_user=100`、`max_total_buffer_bytes=67108864`。
旧配置省略这些字段时采用上述默认值。正在处理的请求总名额仍为
`2 * max_streams`；等待名额是它的子集，活跃 tunnel 和网站 WebSocket
共享 `max_streams` 名额；逐用户上限适用于认证 CONNECT，不是连接登录状态。

连接滚动接收窗口为
`clamp(stream_window * max_streams, 65535, clamp(total_receive/max_connections,65535,16MiB))`。
默认每连接预留 512 KiB、全局 64 MiB，保守容量为 128 条 H2/H3 连接，
仍受 listener 连接名额约束。H1 和未完成 TCP TLS 握手不预留 H2 信用；
QUIC 经 Retry 验证后申请信用。信用由连接持有至协议状态销毁，
不会因认证流结束而退款。H2 初始连接窗口的 65535 下界不可调低。

QUIC 请求流窗口另受 `(connection_window-control_reserve)/max_streams` 约束，
control reserve 为 `min(connection_window/4,64KiB)`；初始窗口还不超过 early-data
上限。QPACK 动态表和 blocked streams 显式为零。调整的是流控/容量策略，
不改变 revision 4 的认证与 framing，也不代表吞吐提升。并发多、窗口小的
吞吐及尾延迟需要部署方测量，再决定是否提高预算或降低连接槽位。

`max_total_buffer_bytes` 独立覆盖应用持有的 tunnel DATA、H3 网站 bridge
队列和 pending DATA；额度跟随 Bytes 的克隆和切片，在最后持有者释放时归还。
满额时保留背压。它不是 RSS 硬上限：H1/H2 网站的 Pingora 内部缓冲、
头部、codec 状态、TLS/QUIC 元数据、内核缓冲分别受原有大小/并发限制约束。
`check-transport` 输出实际连接、等待、tunnel、H3 信用和缓冲池容量。

`[listener] public_addresses=[]` 可列出 NAT 公网入口地址。固定源站使用
具体解析地址检查自反代，包括本机地址、mapped IPv6 和这些公网地址；
合法的不同端口本地后端继续可用。无法从本地接口推导的 NAT 地址必须显式配置。

ECH outer 到期时，已配置 ECH 的服务暂停所有新 TLS/QUIC 握手；不静默关闭 ECH。
已有连接按原有 idle/grace 规则运行。inner 续期仍可载入，outer 修复后使用最新
inner。outer 也执行 SAN、密钥、用途、链验证。`certificates/TLS-LOADED`
记录进程 ID、载入 generation、有效期和新握手准入状态；它可能陈旧，不是实时
握手证明。`status` 会明确标注这一点。刷新错误限速输出。

ACME journal 写入版本 3，保留版本 1/2 的保守读取迁移。创建结果不确定且查询为空
不会删除 lease；必须继续对账，已发现创建先持久化再进入 DeleteUncertain。
这可能在无法证明远端操作终结时阻止后续签发，不能通过清空 journal 解决。
遇到此情况应先向 provider 核实最终结果并保留 marker/订单证据。

永久错误或原因不确定的 completed certificate 会保留原始长度、完整响应摘要、最多 16 KiB 的公有证书前缀和
分类，暂停重复下载；future notBefore 验证后等到时间再重试；obsolete 仍持久
退役和冷却。链错误可能来自材料或本地信任配置，不自动归责于 CA。
修正信任配置并调查后，可停止运行中的控制器，执行
`moon-naive acme retry-certificate <config.toml>`，显式重试原订单的验证。
该命令不自动创建替代订单。回滚到旧二进制前必须处理 journal v3 迁移，
不能让旧程序丢弃 DNS lease 或 blocked certificate。

## 协议与架构

### 当前组件与所有权（2026-11-12）

生产交付是一个 Rust `moon-naive` 服务进程。数据面使用 Tokio 多线程异步运行时；
ACME/DNS 控制面在同进程的独立 OS 线程和单线程 Tokio runtime 上运行，避免控制面
网络等待和持久化 fsync 占用数据面线程。它不是多个语言服务之间的 RPC 架构。

| 组件 | 实际职责与边界 |
| --- | --- |
| `core/src` | 配置、每流认证、能力协商、记录编解码、入口分派、目标地址策略；纯 Rust 协议逻辑，不负责拨号或证书 IO |
| `src/net/h2.rs` | TCP/TLS 接入，Pingora H2 session 适配；未协商 H2 时按配置提供 H1 网站入口 |
| `src/net/h3.rs` | UDP/QUIC/H3 接入、quiche 驱动、流状态和传输信用；H3 自带 TLS 1.3 |
| `src/net/mod.rs` | 共享 App、认证后路由决策与准入；并非另一个公网代理服务 |
| `src/net/site` | Pingora 网站/普通正向代理、固定源站池、头部清理、流式响应、压缩与 WebSocket；H3 网站/正向请求通过有界内存 H2 bridge 复用 Pingora，不另开公网 H2 端口 |
| `src/net/tunnel.rs` | mona CONNECT 的双向字节流、填充记录、背压、半关闭与空闲期限；普通网站和 WebSocket 不用该记录格式 |
| `src/net/egress.rs`、`src/resolve.rs` | 有界解析和拨号、具体 IP 候选检查、本机接口检查、HTTP/HTTPS/SOCKS5 下一跳；配置下一跳失败不会静默改为直连 |
| `resources.rs`、`forward_cache.rs` | 全局/用户/连接与缓冲额度；按用户和 origin 隔离的 128 项 LRU、惰性 300 秒 TTL 和单次初始化，初始化不持有全局缓存锁 |
| `src/net/tls.rs`、`src/trust.rs` | BoringSSL TLS/ECH、信任根、不可变 TLS generation；旧连接保留旧代，新代验证后原子替换 |
| `src/acme` | instant-acme 的 JWS/nonce/EAB/订单协议，加 Rust DNS provider、持久 journal、证书安装和私有健康诊断；发布证书、网络加载和写状态文件是不同事实 |
| `src/runtime.rs`、`src/cli.rs` | 启动、readiness、控制线程、SIGTERM 排空、本地配置/证书运维命令 |
| `tools/xtask` | Rust 验证、依赖/源码审计和按提交打包；Python 仅用于独立向量和实验编排/抓包密码验证 |
| `client/naiveproxy` | 导入的 C++/Chromium 与 Kotlin Android 实验客户端，不进入服务端 Cargo 构建；不是已验收的生产客户端 |

### 未认证与已认证流量怎样走

```mermaid
flowchart TD
    U[HTTPS 请求] --> T{入口}
    T -->|H1 网站| W[固定网站策略 / Pingora]
    T -->|H2 / H3| V[HTTP 格式、首部、流额度检查]
    V --> X{网站 extended CONNECT WebSocket?}
    X -->|是，网站域名与路由合法| S[网站 WebSocket / 固定源站 / 共享 tunnel 额度]
    X -->|否| A{当前流 mona 认证有效?}
    A -->|缺失或失败| W
    A -->|有效| R{请求类型}
    R -->|普通 CONNECT| C[用户与全局额度 / 解析 / 具体 IP 策略 / 拨号]
    C --> P[响应认证确认 / mona 双向隧道]
    R -->|普通 HTTP，非本站目标| F[独立 forward 策略 / 用户额度 / Pingora]
    R -->|普通 HTTP，本站目标| W
    W --> O[配置中的源站池]
    F --> E[受限公网候选 / 可选下一跳]
```

- 认证是 **每个 H2/H3 请求流** 的事实，基于真实 TLS exporter、真实 stream ID 和请求上下文；
  同一连接上的后一条流仍须认证。H2 网站可以使用 TLS 1.2，但认证代理要求 TLS 1.3；
  H1 不提供 mona 认证代理入口。标准 ALPN 仍为 h2/h3，没有产品专用 ALPN。
- 缺失、重复、畸形、重放或上下文不匹配的认证不会获得任意出站权限；代理认证首部会被清除，
  然后交给普通网站逻辑。普通网站按本站域名/路径处理，因此结果可能是正常内容、404 或 405，
  并非保证所有错误请求都返回 200。HTTP 语法错误、额度或协议错误也可能先行拒绝。
- 未认证请求可以触发**已配置固定网站源站**的正常解析与连接；不能把请求 authority 当任意拨号目标。
  固定源站允许受信任的私网后端；任意正向/CONNECT 目标使用不同的公网与自连接防护策略，
  对解析出的具体 IP 检查并拨该候选。网站 WebSocket 是公共站点功能，也只通向固定路由。
- 有效普通 CONNECT 在目标拨通后才返回成功与响应证明，随后使用协商的 mona framing。
  有效普通 HTTP(S) 请求若目标非本站，才走独立 `[proxy.forward]` 策略；并非复用网站上传限额。
  有效认证本身不会让本站域名绕开网站配置，也不会取消目标 ACL 或全局/用户额度。
- TLS 终止型 CDN/反代会改变 TLS exporter；不能把客户端的通道绑定认证直接透传为本服务的认证。

### 技术栈比例与 Go 边界

统计基准为合入的 `a5a6207`。使用 `git ls-files`，按扩展名统计 `.rs/.c/.cc/.cpp/.cxx/
.h/.hpp/.py/.sh/.kt/.java/.go` 文件的原始物理行数（含空行、注释和内嵌测试），排除文档、
JSON/TOML/YAML、补丁文本、构建产物及仓库外依赖源码。这是源码构成，不是二进制体积、CPU
占比或依赖完整源码占比；不同范围不能混算。

| 范围 | 实际统计 |
| --- | --- |
| 自有服务端 `src/` + `core/src/` | 47 个 Rust 文件，25,416 行：Rust 100%；含测试夹具，并非纯生产逻辑 LOC |
| 自有服务端与工具 `src/` + `core/` + `tools/` | Rust 26,456 行（98.05%），Python 525 行（1.95%）；52 个 Rust、3 个 Python 文件 |
| 全部 Git 跟踪源码，含 vendor 与实验客户端 | 共 96,954 行；Rust 91,057（93.92%），C++ 3,903（4.03%），C/C++ 头文件 1,146（1.18%），Python 621（0.64%），Kotlin 227（0.23%） |
| Git 跟踪的 Go 源码/模块 | `.go`、`go.mod`、`go.sum` 均为 0 |

服务端网络、认证、策略、控制和运维逻辑是 Rust；TLS/密码学刻意使用 **C/C++ BoringSSL**，
并经 Rust boring/tokio-boring 绑定。quiche、Pingora、instant-acme 为 Rust。BoringSSL 与 quiche
完整依赖源码不都在 Git 跟踪树中，故全仓比例不能用来宣称最终程序的原生代码仅占上述比例。
`rustls-pki-types` 用于证书/密钥数据类型，不等于启用 Rustls TLS 后端；native audit 验证所选后端。

**生产运行、普通 Cargo 构建、默认 `cargo test --workspace` 和现有默认 CI 都不依赖 Go。**
唯一有意保留的 Go 相关部分是可选的真实 ACME 实验：仓库外 Pebble/challtestsrv 测试 CA 和
仓库内 129 行 `tools/acme-lab/pebble-lab.patch`，Rust 的 cfg(test) 夹具调用这些外部测试进程。
它们不会链接进或随服务端启动，不是生产 sidecar。构建该 CA 及记录其 Go 构建信息需要 Go。
完整 `cargo xtask lab` 默认包括 Pebble；不使用 Go 时选择普通 workspace 测试或
`cargo xtask lab --only acme`（Rust 合成 CA/provider，抓包分析使用 Python、tcpdump、tshark）。
保留真实 CA 实验有助于发现仅用自有 mock 无法覆盖的状态机问题；无需为避免测试工具的 Go
而新增一套自研 CA。`xtask` 也已有禁止生产构建目录混入 Go 源码/模块的审计。

当前版本 **0.7.0**，认证域与 exporter 使用修订4。**不产生空闲假流量，不为真实反代添加Padding首部或改写正文**。采用认证协商的8/16条初期窗口，可选低比例后段填充。旧moon-naive和官方Naïve客户端不兼容；实验客户端初步适配见下文；尚未通过完整构建与互通验收。

### 路由与连接

H1始终进入固定网站反代；H2/H3逐请求验证认证，失败同样进入固定网站，不发407，不拨请求中的任意目标。畸形HTTP请求在解析/校验阶段拒绝。成功认证CONNECT依次经过目标语法、ACL、额度、DNS和拨号检查，拨通后才返回200。认证普通HTTP正向代理由Pingora转发；网站WebSocket使用标准升级路径，都不插入隧道记录。

一个CONNECT对应一个目标TCP连接；多个CONNECT在同一个H2/H3外层连接上复用。每个目标TCP连接独立保持字节流、背压和半关闭，不能把不同网站目标TCP连接合并成一条。网页、TCP连接、CONNECT流并非一一对应。

服务器不主动新增外层连接，不发假请求/假CONNECT，也不为每条应用记录重新拨号。H2共享TCP拥塞控制和队头阻塞；H3使用独立QUIC流与quiche拥塞控制。Pingora网站上游连接池继续复用同一源站的可复用连接；来源/认证隔离、响应完整性和池上限不能为了减少连接而取消。新Chromium客户端应复用已有外层会话，达到流上限才按调度需要扩容，不按标签页新建代理TLS连接。

默认隧道任一方向实际进展更新600秒空闲期限。上传FIN只关闭目标写方向，下载可继续；reset、错误、空闲超时取消任务并释放额度。关闭的目标TCP不能由服务端透明“接续”，重新请求需要新的CONNECT；外层连接仍可复用，若外层也关闭则重新握手和认证。网站连接池另有自己的上游空闲期限。

认证、协商、记录格式、EOF 和错误规则以唯一权威 [mona 协议规范](PROTOCOL.md) 为准。独立向量及生成器见该文档。

### 真实网站与配置

反代正文、正常首部、ETag、Range、压缩、SSE/gRPC和WebSocket维持既有行为。本轮撤回试验中的反代Padding首部和空闲假流量，没有保留可开启它们的配置/协商位，也不让填充成为目标业务内容。

在现有唯一config.toml中可增加：

```toml
[traffic]
initial_records = 16 # 8或16，服务端选择偏好
sparse_padding = true # 客户端也提议0x04才生效
```

以上为缺省值；设sparse_padding=false可仅使用有限模式。所有填充只在成功协商的CONNECT内应用。无需分散创建额外TOML。旧客户端不会因配置变更自动兼容。

### 外部包组成与限制

H2：`IP / TCP / 外层TLS记录{HTTP/2 DATA头(9B) + 应用流片段} / AEAD标签`。

H3：`IP / UDP / QUIC包{STREAM帧 + HTTP/3 DATA帧 + 应用流片段} / AEAD标签`。H3应用数据没有额外TLS record封装，TLS用于QUIC握手。CONNECT传递目标TCP的payload，不携带目标IP/TCP包头；内层HTTPS的payload可能本身是TLS记录。

MAC只位于请求/确认首部，应用记录没有新的自制加密或逐记录MAC。目标TCP的原始字节经去填充后完整恢复。物理包长还受MTU、ACK、拥塞控制、窗口、重传和其他流复用影响；应用层参数不能精确指定每个线上包的大小和时序。

此策略没有网页抓包分布拟合或DPI识别率测试依据，不能承诺等同真实网页。保留真实反代、自然读写时序和现有连接复用，避免加入新的定时假流量模式。ECH不隐藏IP/外层公开名称/长度/时序，也不消除TLS-in-TLS。BoringSSL服务端不等于Chromium浏览器栈。

### 实现位置和客户端后续工作

认证协商在core/src/auth.rs，预算与借用解码在core/src/codec.rs，采样/缓冲/空闲期限在src/net/tunnel.rs，H2/H3适配分别使用Pingora/quiche。没有新增运行依赖或Go栈。

客户端应保留Chromium证书策略、TLS/H2/H3栈，在实际分配流ID后签名，验证协商后初始化双向codec；复用外层会话，禁止H1代理回退、0-RTT和Fast Open。验证范围见[VERIFICATION.md](#构建检查与维护边界)。


### 服务端架构

0.7.0 由根包构建 moon-naive；core 提供协议与配置逻辑，tools/xtask 提供构建及发布工具。运行时只需服务端程序、配置、持久化状态和所需系统信任根。

#### 生命周期

CLI 先校验配置、用户、网站和传输条件。ACME 控制面运行在独立线程的 Tokio runtime，隔离 DNS、日志写入和 fsync 对数据面执行器的影响；线程仍共享同一进程/UID。没有有效证书时等待 DNS-01 签发，验证、安装后绑定 TCP/UDP，并通知 systemd 就绪。

账户操作使用 instant-acme；Porkbun/Cloudflare 适配器管理 TXT，日志记录未完成操作。证书经 SAN、私钥、链、有效期等检查后写入 generation，原子更新 CURRENT。续期失败保留仍有效的证书；轮换后新连接使用新上下文，已有连接继续。

SIGTERM/SIGINT 停止接入并排空连接，随后限时对账本进程拥有的 TXT；验证仍在进行或创建结果不确定时保留 lease。状态使用单写锁；升级时应保留整个 state_dir。

#### 请求路径

- TCP：BoringSSL 处理 TLS；H1 提供网站，Pingora H2 支持网站与认证代理。
- UDP：quiche 处理 QUIC/H3；网站通过有界内存 H2 桥进入同一 Pingora 引擎。
- 代理仅在 TLS 1.3 H2/H3 上启用。每条请求绑定 exporter、流 ID 和请求字段验证；CONNECT 经 ACL、预算和目标拨号后才返回 200 与响应证明。
- 未认证请求进入固定网站路由；固定网站与任意目标正向代理使用不同的路由、元数据和连接池隔离规则。

实现见[网络入口](../src/net/mod.rs)、[网站引擎](../src/net/site/mod.rs)及[内存桥](../src/net/site/bridge.rs)。认证和记录格式以[协议](#协议与架构)为准。

#### 连接与资源

每条 CONNECT 对应一条目标 TCP 连接，外层 H2/H3 连接可以复用。隧道保留背压、半关闭、取消和额度释放；任一方向实际进展更新空闲期限，默认 600 秒。

网站支持固定源站池、最长前缀路由、gzip、SSE/gRPC、trailers 和固定路由 WebSocket。HTTPS 回源校验证书及名称；安全方法的建连失败可有限回退，不重放 POST。正向出站先检查 DNS/IP ACL，可使用一个 HTTP、HTTPS 或 SOCKS5 下一跳，失败不回退直连。

连接/流窗口和共享接收预算约束内存，接收预算不等于 RSS 上限。TCP 拥塞由内核处理，QUIC 拥塞由 quiche 处理；Linux timerfd 为 QUIC 提供发送期限等待，UDP 阻塞时等待可写。

#### 依赖与边界

TLS 共用 BoringSSL；quiche 使用 boring crate 后端。gzip 由 Rust miniz_oxide 处理。源码打包、SHA-256 和 ELF 检查由 tools/xtask 的 Rust 库完成；首次 BoringSSL 构建仍需要原生工具链。

固定 Pingora 与 instant-acme 补丁随 vendor 提供并校验；后者提供持久化私钥注册、请求错误归因和 Retry-After 处理，继续复用上游 JWS/nonce/EAB 实现。

不提供管理 API、动态任意网站路由、多 SAN 自动证书、分布式状态或多 CA 自动切换。ECH 为实验性功能。配置详见[配置指南](#配置与迁移)，未验收范围见[验证记录](#构建检查与维护边界)，网络可观察性见[可观察性与兼容性](#可观察性与兼容性)。


#### 恢复边界

H3 内存桥使用可替换代际。任一驱动退出会通知当前交换失败；后续请求经有界、单次构建及冷却后获得新桥。不会重放应用请求。DATA 长度在进入共享 H2 连接前检查，长度不符只重置该流。

CONNECT、HTTP 转发及固定网站源站复用有界 TCP 候选拨号，最多同时尝试两个地址。固定源站允许显式配置的私网地址，任意转发目标仍应用公共目标策略。源站选择与其地址回退分开；固定源站在 HTTP 发送前可推进 TCP/TLS 候选，并把 DNS、建连和会话初始化纳入连接期限；已发送的应用请求不隐式重放。

上述改动没有完成控制面进程隔离、双身份自动证书管理、原子多路径激活或认证容量预留。当前真实实现及验收差距见[实施报告](#构建检查与维护边界)。


### 项目结构

0.7.0 使用一个 Cargo workspace 和锁文件，共三个包：moon-naive、moon-naive-core、xtask。

| 路径 | 职责 |
| --- | --- |
| [src](../src/) | 服务端 CLI、运行时、证书控制面及网络入口 |
| [src/acme/account.rs](../src/acme/account.rs) | instant-acme 账户创建、恢复及 EAB 导入/注册 |
| [src/acme/manager.rs](../src/acme/manager.rs) | DNS-01 订单、续期、退避及恢复 |
| [src/acme/persist.rs](../src/acme/persist.rs) | 日志、私有权限、证书 generation 和 CURRENT |
| [src/net](../src/net/) | TLS、H2/H3、隧道、ACL 拨号及固定下一跳 |
| [src/net/site](../src/net/site/) | 共用 Pingora 网站/正向代理、上游池和 WebSocket |
| [core/src](../core/src/) | 配置、认证、记录 codec、准入及额度策略 |
| [tools/xtask](../tools/xtask/) | Rust 审计、构建检查及发布打包 |
| [deploy](../deploy/) | systemd、OpenRC 服务定义 |
| [config.example.toml](../config.example.toml) | 唯一运行配置模板，config init 内嵌同一文件 |
| [assets](../assets/) | 对应内置 staging CA 的公开根证书 |
| [vendor/pingora](../vendor/pingora/) | 固定 Pingora 源码、补丁和校验清单 |
| [vendor/instant-acme](../vendor/instant-acme/) | 固定 instant-acme 源码及持久化私钥注册接口补丁 |
| [licenses](../licenses/) | 第三方许可文本 |
| [docs](./) | 使用、设计、限制与历史摘要 |

运行时不依赖 target、reports 或 dist；当前源码只保留服务端、生产库与构建/审计/发布工具。

### 可观察性与兼容性

BoringSSL、Pingora、quiche 的组合不代表浏览器指纹，也不证明更难识别。TLS/QUIC 握手、SNI、ALPN、HTTP 设置、包长、方向和时序仍可被观察；认证和填充不能消除 TLS-in-TLS、关联或长度信号。ECH 不隐藏 IP、公开名称、长度或时序，证书及 DNS 发布边界见[配置](#ech)。

本项目不兼容官方 NaïveProxy 客户端，未实现 REALITY 的目标站握手校准。AnyTLS 等协议的历史对照不代表当前上游漏洞状态，也不能用于推导本项目的安全性或识别率。桥接上传失败、最终响应、半关闭和取消分别处理；固定网站可携带服务端生成的转发元数据，任意目标正向代理清理身份字段及 Via，动态压缩尊重 no-transform。

历史抓包和审阅结果只对应当时提交，不构成当前互通性、性能或不可识别性证明。

## ACME 状态与 TLS 激活

生产 instant-acme 固定为 0.9.0、commit `4a9b80fdc22f23ab39b78dfd20ff5d4c92938e52`，关闭默认后端，仅启用 time/x509-parser。自有 BoringSSL CryptoProvider 与 HTTPS HttpClient 负责密码操作和传输；DER CSR 直接交给 finalize_csr。JWS、nonce、badNonce 重签和 EAB 仍由库处理；rustls-pki-types 仅是 DER/密钥类型。

账户 PKCS#8 密钥先于注册请求持久化；一次性 EAB 响应丢失时先用原 key 查找已存在账户。恢复订单只依据原订单 POST-as-GET 的方法、URL、HTTP 状态退役；HEAD newNonce 的 404 不能证明订单消失。原订单 URL、key、CSR 保留到有证据的终态。

Retry-After 区分缺失、非法、可表示绝对时间与不可表示值。所有远端时间加法检查溢出，不持久化 u64::MAX。finalize、恢复和 refresh 的等待先保存 UTC next_attempt，再使用单调时钟等待；超过本轮期限时延期，不提前轮询、不重新下单，也不重复 finalize Processing/Valid 订单。缺失有效等待头时保留 250 ms、倍增退避；DNS 传播使用自己的 poll_interval。ARI 正常重查限于 60 秒到 24 小时，订单及 429/503 的有效等待不受此上限截短。

DNS 单域名单订单状态为 `Preparing → CreateUncertain → Created → Validating → DeleteUncertain → removed`。只读 zone/NS/列表发现失败可重试；创建 intent 在写请求前持久化。确认无副作用的权限拒绝才回到准备阶段；超时或断连仍不确定。borrowed 记录不删除，foreign TXT 保留，owned 记录按 marker/ID 对账。

必须保留 durable-intent/send 崩溃间隙：持久化后、POST 前崩溃与 POST 后响应丢失可留下同一状态。一次空列表不是未发送证明；没有服务端提交/幂等承诺时继续保留调查与对账，不能清 journal 或删除所有同名 TXT。

Validating 在 challenge ACK 前持久化；取消、超时和重启不能自动删除 CA 仍需验证的 TXT。清理由原 order/authz/challenge 状态决定；仍 Pending/Processing 则保留。重复 set_ready 本身不是协议错误，但 Processing/Valid 订单不重新 finalize。

HTTP 响应上限 4 MiB，证书材料上限 1 MiB，journal 上限 8 MiB。诊断在复制/序列化前仅保留最多 16 KiB 前缀、完整 body SHA-256、原始长度、分类与 retry_at。错误 SAN/key/EKU/材料、本地 I/O/信任问题、原因待调查的链失败、future notBefore、暂态网络及真正持久化不确定分别处理；future notBefore 沿原订单延期，不能盲目换订单。

Manager 直接拥有本地 VerifiedBundle；网络另持有共享不可变 TLS/ECH generation。发布 CURRENT、内存替换和写 TLS-LOADED 是不同事实。先完整构建/验证 H2/H3/ECH 后原子替换；状态文件写失败独立报告并清理临时文件，不阻止有效新 generation 载入，也不掩盖已完成的激活。磁盘文件不能代替真实新握手取得的 leaf serial/fingerprint。

已有有效身份时，普通续期失败降级续期健康；控制错误或 panic 停止该 Manager，不自动恢复或重放未知副作用。网络继续有效期与 ECH 准入检查；启动后的控制清理错误独立报告，正常网络关闭结果不取决于 shutdown/control 的先后顺序。无有效初始身份仍不能启动；身份到期仍拒绝新握手。

outer 到期暂停所有新握手但不静默关闭 ECH；inner 更新仍可载入，outer 恢复后重新准入；旧连接按原生命周期继续。控制线程不构成 OS 权限边界，DNS/ACME 密钥隔离、独立进程/UID、自动 outer 签发仍未实现。

journal 当前写入 v3，读取 v1/v2 后保守迁移。回滚必须使用完整备份并对账，不得降级版本号、删除 lease 或清空状态。源码嵌入者需使用 acme/account、acme/persist、根 Error/Result 和 Manager::current；测试专用 HTTP 明文构造器及 vendor 测试辅助 API 已移除。

## 原生构建与部署

适用版本：0.7.0，Linux x86_64。程序在同一进程中管理证书、网站和 H2/H3 代理。配置字段见[配置指南](#配置与迁移)，客户端要求见[协议](#协议与架构)。

### 原生构建

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

### musl 静态构建

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

### 安装与配置

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

### 服务管理

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

### 检查与发布工具

```sh
rustup component add rustfmt clippy
cargo fmt --all -- --check
cargo clippy --workspace --locked -- -D warnings
cargo xtask audit-native
cargo xtask verify
cargo xtask source dist
cargo xtask dist out/musl/moon-naive dist
```

`verify` 只执行源码/依赖审计、格式、Clippy 和 Release 编译；指定 target 时为 compile-only，不执行目标程序。`source` / `dist` 生成确定性的 tar.gz 和 SHA-256，拒绝覆盖同名产物。源码文件清单依赖 Git；无 Git 元数据的解包副本需先建立基线。vendor 文件始终按校验清单收集。

`check-elf` / `dist` 使用 Rust 检查静态 x86_64 ELF，不需要 file/readelf；结构检查不等同目标发行版运行验证。

### CPU 与传输诊断

`moon-naive status` 或 `moon-naive check-transport /etc/moon-naive/config.toml` 输出 CPU 能力、窗口和拥塞策略。memchr 与 BoringSSL 使用各自的运行时硬件检测；不需要额外 CPU 配置。

TCP BBR 依赖宿主内核，QUIC BBRv2 由 quiche 实现。程序不修改系统 sysctl/qdisc；算法、流控和实际公网吞吐应分别核对。内核版本参照诊断不能证明发行版是否回补安全修复，应以发行版公告为准。

### 复用 BoringSSL，避免重复调用 CMake

首次从源码构建仍需要 CMake、C/C++ 和 Perl；它们来自 boring-sys 的 BoringSSL 构建流程。quiche 已使用 boringssl-boring-crate，共用同一份 BoringSSL。

重复构建可使用 boring-sys 官方支持的预编译目录：

```sh
BORING_BSSL_PATH=/absolute/path/to/matching-boringssl-libs \
BORING_BSSL_INCLUDE_PATH=/absolute/path/to/matching-boringssl-headers \
cargo build --release --locked -p moon-naive
```

库目录需包含 libssl.a、libcrypto.a（或放在其 lib 子目录），头文件目录需包含 openssl/。仅复用由当前锁定 boring-sys 5.2.0、相同补丁、目标架构和 C 运行库构建的产物；GNU 与 musl 不可混用。不要设置 ASSUME_PATCHED 绕过来源要求。仍需 libclang 生成 Rust 绑定和系统链接器。此模式避免调用 CMake，但 Cargo 的传递构建依赖仍保留 cmake crate。



### 恢复与激活的运维影响

H3 内部桥接失败时，当前请求失败且不自动重放；后续请求可触发重建。重建最多等待 3 秒，连续尝试间隔至少 1 秒，等待人数不超过 `limits.max_streams`。停止接收服务后禁止创建新桥接代际。

ACME 已完成订单的证书若已过期或进入更新窗口，先验证身份、密钥、用途和信任链，再持久化退役及至少一小时的冷却时间。验证错误继续保留订单供排查，不盲目重新签发。磁盘写入不确定时仍需重启后恢复。新 `retired_order` 日志字段不受旧版本支持；不要通过删除日志来降级，否则会丢失 DNS 清理状态。证书私钥不会写入退役摘要。

账户日志、DNS/EAB 凭据仍要求所有者专用权限；文件读取拒绝符号链接最终组件、FIFO、过大和非私有文件。父目录必须由可信管理员控制。本轮尚未实现独立进程和发布目录权限分离，现有 `serve` 仍内嵌控制线程，ECH 外层证书仍需按原流程管理。不要把这些局部修复当成完整权限隔离部署方案。

## 构建检查与维护边界

当前已恢复 core/server 单元与真实 loopback 集成测试。`cargo xtask verify` 执行格式、Clippy、工作区测试及 release 构建；跨目标运行需该目标可执行。`cargo xtask lab` 是唯一公开实验入口，委托 `tools/acme-lab/run.py` 的单一 suite 定义；私有 Python 保留抓包和独立密码分析，`result.json` 为唯一机器判定结果。默认测试无需抓包；显式 lab 模式要求所选场景、抓包和解码验证全部存在且成功。

- 快速：`cargo test --locked -p moon-naive-core`，`python3 tools/vectors/generate.py --check`。
- 普通集成：`cargo test --locked --workspace`。
- 证据判定反例：`cargo xtask lab --only oracles --run /tmp/mona-oracles-UNIQUE`。
- 隔离实验：`cargo xtask lab --only acme --run /tmp/mona-acme-UNIQUE --tcpdump /path/to/tcpdump --tshark /path/to/tshark`。输出目录必须全新且在源码树之外。
- Pebble：同一入口 `--only pebble`，另指定 `--pebble`、`--challtestsrv`、`--pebble-source`；测试 pin 为 `d52948ce25e7c1576bcd18ff0e20a1c24ec7c44b`，在外部 checkout 应用 `tools/acme-lab/pebble-lab.patch` 后构建。它只修改测试 CA，不进入生产。
- Linux 实验需要 `unshare` 用户/网络命名空间、`iproute2`、tcpdump、tshark，以及 Python cryptography。缺前置工具会失败，不报告跳过为通过。安装与工具路径由操作者提供，不隐式下载未验证工具。

固定 Pin：Pingora `4487f7b2ab50f159e4a2cf4f6a6b813f61bb6e19`，quiche `925b225825e2188f8e58e359114150500557bf61`，instant-acme 如上。删除测试辅助依赖不会升级生产包。vendor 是保留 pin 的运行库裁剪副本，裁剪范围和生产补丁分别记录于 [Pingora](../vendor/pingora/MOON-NAIVE-PATCHES.md) 与 [instant-acme](../vendor/instant-acme/MOON-PATCH.md)。修改后同步各 vendor SHA256SUMS 及根清单，保留上游版权和许可证。

构建依赖 C/C++、make、CMake、libclang、Linux headers、Perl、pkg-config、Git 与系统 CA；同平台 BoringSSL 复用方法见原生构建章节。构建、摘要、tar.gz、ELF 检查由 tools/xtask 的 Rust 工具完成，不依赖实验 Python/Go 程序。

本轮实际执行结果见 [实施检查点](IMPLEMENTATION.md)；下文历史记录不等同于当前测试结果。实验客户端的真实互通、其他目标/MSRV、长期运行、公网 CA/DNS、性能与 DPI 可识别性不能由编译成功推导。

合并前的审阅与实验记录保留于 Git 提交 [bcf418e](https://github.com/Clementine-Miles/moon-naive/tree/bcf418ea1f99900da64ed2abbee292d2484dbbc7/docs)，对应当时源码；不得作为当前提交的测试执行成功。仓库外既有抓包、密钥和 journal 工件未纳入源代码归档。

## Android/Linux 实验客户端

### 来源与裁剪

官方来源为 [klzgrad/naiveproxy](https://github.com/klzgrad/naiveproxy)，固定发布标签 `v154.0.8037.49-5`、commit `d04efe1ea4477c2db24a7d0e2f068b3bee931e45`、Chromium `154.0.8037.49`。不跟随会重写历史的 master；来源以 [UPSTREAM_REVISION](../client/naiveproxy/UPSTREAM_REVISION) 为准。

[client/naiveproxy](../client/naiveproxy/) 保留 Linux/Android 共用的 Naïve CLI、SOCKS/HTTP 本地入口、连接搬运、记录适配及 Android 原生插件源码。没有引入 Windows、macOS、iOS、OpenWrt 的发布脚本、CI、测试、Docker、预编译客户端、上游签名 keystore 或整棵 Chromium 通用依赖。旧 preamble getter 及连接级 padding 缓存已删除。

这是**源码 overlay 与精确 Chromium 补丁**，不是脱离 Chromium 的独立 C++ 程序。通用 Chromium/BoringSSL/GN 依赖在仓库外按固定 commit 获取；它们为两平台共用的构建依赖，不能按文件名随意裁剪再声称可构建。保留的上游源码有 BSD 许可和版权；Android 插件 Kotlin 文件为 GPL-3.0-or-later，随附 apk/COPYING；新增 moon-naive 文件使用项目 Apache-2.0。Android 包名改为 `org.moonnaive.plugin`，插件 ID 为 `moon-naive-plugin`，与官方插件分开；宿主应用需要支持这个新 ID。本仓库不提供完整 Android VPN GUI。

### 本次适配边界

- 仅一个有凭据的 HTTPS 下一跳、TLS 1.3、H2 普通 CONNECT；缺少 proxy、直接连接、QUIC、多跳、extra-headers、密钥日志和旧 tunnel-timeout 配置均拒绝。不会退回官方 Naïve Basic 认证协议。
- [chromium.patch](../client/naiveproxy/chromium.patch) 在 ActivateCreatedStream 分配实际流 ID 后、序列化 HEADERS 前生成请求证明。exporter 显式空 context、label、转录字段和响应域均保持服务端 revision 4 原样；每个 socket/流独立保存绑定，不把 TLS 连接标记为已登录。
- Basic 凭据只用于读取 Chromium 原有本地凭据缓存、派生共享 key，随后清除临时明文和认证字段；线上只有 `moon-naive 02.<proof>`。CONNECT 只生成 method、authority 与证明，不发送 preamble、旧 Padding/FastOpen 或额外浏览器首部。两条 HPACK 编码路径在查找动态表前强制 Proxy-Authorization 使用 never-index。
- 200 和唯一的 Proxy-Authentication-Info 验证通过后才报告外层 CONNECT 成功；认证、字段、连接、流 ID 或目标不匹配都失败。H1 fallback 在生成认证前拒绝；QUIC 与 early data 显式关闭。证书、主机名和原有信任验证继续由 Chromium 执行。
- 初步只提议 02：双向有限 16 条记录，各自独立计数；发送 N≤16309、P=0，接收校验 N/P/零填充和任意分片，第 16 条 padding 消费完成后精确切换 raw。发送保留原有有限缓冲及短写 drain。未实现 8 条或稀疏模式提议，未添加兼容协议。
- 使用 Chromium 默认接收窗口，删除上游 CLI 的超大窗口覆盖；没有据此宣称吞吐或指纹改善。服务端 Rust 源码、预算、ACL、CONNECT 时序与协议均未修改。

### 准备、构建与 Android 打包

唯一准备入口为 [prepare.py](../client/naiveproxy/prepare.py)。Python 3.10+ 和 Git 为准备阶段依赖；完整 native 构建另需匹配上游 DEPS 的 Chromium Clang、GN、Ninja、系统构建依赖，Android 还需对应 NDK。构建目录必须位于本仓库外且为空；入口拒绝覆盖已有工作区。默认只准备源码，不安装依赖、不编译、不执行目标程序。

```sh
python3 client/naiveproxy/prepare.py --work-dir /absolute/build/moon-linux \
  --target-os linux --target-cpu x64
# 已有固定上游 checkout 时，只检查 pin 和补丁适用性：
python3 client/naiveproxy/prepare.py --check-source /absolute/pinned-naiveproxy
# 已提供匹配工具链时显式编译；也可提供 --gn /path/gn --ninja /path/ninja。
python3 client/naiveproxy/prepare.py --work-dir /absolute/build/moon-android \
  --target-os android --target-cpu arm64 --build
```

准备入口取固定 commit、检查并应用补丁，再覆盖保留的客户端源码；构建使用 args.gn 和显式目标参数，关闭组件/PGO 构建。输出为外部目录 `src/out/moon-<os>-<cpu>/naive`。官方工具下载方式见固定 commit 的 src/get-clang.sh/src/DEPS；若下载域名或工具链不可用，入口以非零退出，保留准备目录供调查，不换 TLS 后端或修改服务端来绕过。

成功构建后的配置示例（仅实验，使用高熵凭据及正常可信证书）：

```json
{"listen":"socks://127.0.0.1:1080","proxy":"https://user:replace-with-high-entropy-secret@proxy.example:443"}
```

Android 使用相同 patched native 程序。将对应 ABI 的 Android 产物放到 `client/naiveproxy/apk/app/libs/<ABI>/libnaive.so`；arm64→arm64-v8a、arm→armeabi-v7a、x64→x86_64、x86→x86。使用 JDK 21、Gradle 8.14.2、Android SDK/build-tools 36，并在 apk 目录运行 `APK_ABI=arm64-v8a gradle assembleDebug`。缺少 native 文件时打包拒绝；release 默认不签名，发行者使用自己的签名配置。未保存 Gradle wrapper 二进制和上游签名密钥。不能拿 Linux ELF 作为 Android native 产物，也不能把交叉编译当作设备执行。

### 已执行检查与未完成事项

本次在仓库外 `/workspace/client-adaptation-evidence/` 编译了协议模块，实际链接现有 BoringSSL libcrypto；与**当前** Rust core 的 authorization/confirmation 对照 stream ID 1、3、255、2147483647，检查不同 exporter/目标/流、反射和重复响应证明拒绝。decoder 检查 1/2/3/4/7/17/127/16384/大块分片、16 条后同输入 raw、越界长度、空记录、padding 超限/非零、截断边界和输出容量不足，均通过。校验程序和构建输出在仓库外，没有重新添加测试源码或 Docker。prepare.py pin/patch 检查、Python 语法及 Android manifest XML 解析通过；这些不是网络互通证据。另实际执行 Linux --build 准备入口：固定源码下载、补丁和 overlay 安装完成，随后因缺少 GN/Ninja/匹配 Clang 按预期以 1 退出，编译阶段没有执行；原始退出码和日志保留于 prepare-linux.exit / prepare-linux.log。

**完整客户端仍属未验收的源级初步适配。**本环境访问官方 GN 下载域名 chrome-infra-packages.appspot.com 时收到代理 CONNECT 403，尚无对应 GN/Chromium Clang/Android SDK 的完整构建、APK 安装、新 H2/QUIC 握手或真实 Chromium 客户端续期/ECH/复用结果。H3 未适配，不能使用 quic://。上游连接搬运仍把 EOF 转为整条连接关闭，尚未满足 moon-naive 的双向半关闭验收；不能据本次纯模块检查将其作为可靠客户端发布。后续必须完成两个平台编译、半关闭接口/生命周期、真实服务端握手与认证失败路径、复用、取消/背压/额度回收、证书/ECH 和 POST 不重放验收，再解除实验状态。

## 历史审阅与实验记录（清理前）

以下内容合并自清理前的 ACME-LAB.md，描述提交 `bcf418ea1f99900da64ed2abbee292d2484dbbc7` 中已有的记录。**本次没有重跑这些测试或实验**；所述测试、实验入口和部分路径现已删除。历史命令与结果只供追溯，不能作为当前源码的验收结果；原实验启动说明由上文的维护边界替代。

审阅和修改基线为 `d0f6a082eeaabd7dac2e976fff09e6c7baf3fbe5`。开始时 HEAD 与参考提交相同，工作区干净；没有额外的 AGENTS.md。先核对旧报告、生产代码和测试判据，再修改。旧报告的失败数不是独立缺陷数，也不是该次执行结果；旧版本可直接从该提交读取。

该次实现生产修复、回归修正和模块合并。revision 4、逐流认证、exporter/transcript/proof、成功拨号后才回复 CONNECT、ACL、证书验证和请求不可隐式重放的约束保留。没有新增代理协议、TLS 后端、provider 注册表或工作流框架。

### 固定集成契约

| 项目 | 当时实现与验证契约 |
|---|---|
| instant-acme | 0.9.0，`UPSTREAM_REVISION=4a9b80fdc22f23ab39b78dfd20ff5d4c92938e52`；两个 Cargo.lock 和 features 不变；`default-features=false`，仅 `time,x509-parser` |
| 本地补丁 | [MOON-PATCH.md](../vendor/instant-acme/MOON-PATCH.md)：持久密钥注册、请求归因、可检查的 Retry-After 与轮询时序；源码摘要同步更新 |
| CryptoProvider | [crypto.rs](../src/acme/crypto.rs)：BoringSSL P-256/ES256，JOSE 原始 64 字节 r\|\|s、PKCS#8 恢复、JWK thumbprint；继续使用库内 nonce/JWS/EAB |
| HTTP | [http.rs](../src/acme/http.rs)：BoringSSL/Tokio/Hyper HTTP/1；保留 CA/主机名校验、HTTPS CONNECT 代理、path/query；请求期限覆盖 DNS、TCP、TLS、头和有限 body；取消释放 driver/socket |
| CSR/EAB | [certificate.rs](../src/acme/certificate.rs) 生成带 DNS SAN 的 DER CSR，原样传入 finalize_csr；[account.rs](../src/acme/account.rs) 管理持久账户 key、一次性 EAB/HS256 和恢复 |
| 类型依赖 | rustls-pki-types 仅用于 DER/密钥类型；没有启用 ring、rcgen、hyper-rustls 或第二套运行时 TLS |
| 本地 CA | Pebble v2.8.0，commit `d52948ce25e7c1576bcd18ff0e20a1c24ec7c44b`；[测试补丁](https://github.com/Clementine-Miles/moon-naive/blob/bcf418ea1f99900da64ed2abbee292d2484dbbc7/tools/acme-lab/pebble-lab.patch) 只提供 keylog、验证/查询屏障及修正 0% 授权复用的随机边界，不进入服务端生产依赖 |

规范依据：[RFC 8555 的 nonce、POST-as-GET、挑战与订单](https://www.rfc-editor.org/rfc/rfc8555)、[RFC 9110 Retry-After](https://www.rfc-editor.org/rfc/rfc9110#section-10.2.3)、[RFC 9773 ARI](https://www.rfc-editor.org/rfc/rfc9773)。下文的 ARI 上下界和证据预算是项目本地政策，不宣称由协议规定。

### 已修复行为

| 条件与原故障 | 当时边界及结果 | 对应回归 |
|---|---|---|
| 恢复订单前 HEAD newNonce 返回 404，被共享 last_status 误认成订单消失 | [account.rs](../vendor/instant-acme/src/account.rs) 在真正订单 POST-as-GET 的响应处附加 `Error::Response {method,url,status,source}`；[Manager::reconcile](../src/acme/manager.rs) 只凭该订单 URL 的 POST 404 退役。适配器继续把 ACME Problem/badNonce 交给库处理 | nonce404 保留 URL/key/CSR；order404 对照确实请求订单端点 |
| Retry-After 极大数导致时间加法 panic，外层又饱和保存极大时间 | [RetryAfter](../vendor/instant-acme/src/lib.rs) 区分 Absent/Malformed/At/Unrepresentable；库与 HTTP 共用解析，检查 SystemTime/Instant 和指数退避算术；不持久化溢出值 | 秒数、HTTP-date、过去/缺失/非法值、u64::MAX 与超过 u64；order/ARI 路径 |
| finalize/recovery 丢失等待头；首次 poll 提前；等待中重启可丢失调度 | [order.rs](../vendor/instant-acme/src/order.rs) 保留各响应等待；[Manager::poll_order](../src/acme/manager.rs) 每次刷新后的等待先写 UTC next_attempt，再用单调时钟等待。该次剩余期限不足则持久延期；保留原订单，不重复 finalize Processing/Valid | 120 秒首轮等待、超出 operation budget、恢复首轮、等待中取消后重开不产生请求 |
| 只读发现/列表失败也留下 CreateUncertain | [dns.rs](../src/acme/dns.rs)、[porkbun.rs](../src/acme/porkbun.rs)：prepare 只读，Preparing 可恢复；写入 CreateUncertain 后才调用 present。只有结构化 401/403 权限拒绝才确认为无副作用 | 两真实 provider 的发现、列表、拒绝、准备取消、真实持久 intent/send gap、晚提交/空 cleanup/重启 |
| challenge ACK 后超时/退出立即删除 TXT | [Manager::cleanup](../src/acme/manager.rs) 查询原 order/authz/challenge；Pending/Processing 验证继续保留，确定终态才清理。Validating 在 ACK 前持久化；Pending ACK 间隙可以重发 set_ready，Processing 不重发 | Pebble 屏障下 timeout、SIGTERM、SIGKILL/重启；先观测保留，再释放 CA，最后检查原订单进度和持久清理 |
| HTTP 内的异常证书经 Vec JSON 膨胀超过 journal 上限 | [BlockedCertificate::evidence](../src/acme/persist.rs) 在复制/序列化前仅取 16 KiB prefix，保存原长、完整 body SHA-256、分类和 retry_at。HTTP 4 MiB、证书 1 MiB、journal 8 MiB 各自保留；正常拒绝不再误作持久化不确定 | 可解析/不可解析材料的 1 MiB、+1、2/3/4 MiB、4 MiB+1；完整摘要、长度、journal <128 KiB、旧证书可用 |
| control panic/error 停止仍有有效证书的 listener | [runtime.rs](../src/runtime.rs) 捕获 unwind，丢弃失败 Manager，结束控制 runtime；已有网络继续有效性准入并报告 renewal_stopped，不自动恢复潜在不一致的 Manager。初始无证书仍无法启动；已启动后的控制清理错误独立报告，不因 shutdown/control 先后顺序改变正常网络关闭的返回值 | invalid renewal 和 control panic 后真实新 H2/H3 握手仍取旧有效身份，driver 为零，显式关闭成功 |
| TLS-LOADED 写失败阻止加载或掩盖已完成的替换 | [Slot::refresh](../src/net/tls.rs) 构建/验证完整不可变 H2/H3/ECH generation 后原子替换，独立尽力写诊断。report 错误单独记录，失败清理临时文件 | create/rename/fsync 命名故障必须命中；实际 rename 失败时新 H2/H3 leaf 已改变；持续两次续期 |
| H1 网站 Upgrade 没有与 H2/H3 共用 tunnel 准入 | [Router::request_filter](../src/net/site/mod.rs) 在合法网站路由/Upgrade 校验后、打开 upstream 前取共享 lease；Context 保持至完整双工结束。[Pingora 补丁](../vendor/pingora/MOON-NAIVE-PATCHES.md) 保留 Upgrade 两个半方向 | max_streams=1、足量连接；H1/H2/H3 混用，满额不打开源站，拒绝/reset/EOF 回收，upload 半关闭仍占用 |
| H3 本地队列的四项预算耗尽后依赖新的外部事件，合并通知可留下已排队工作 | [drive_stream/drive_website](../src/net/h3.rs) 返回本地工作是否用尽预算；driver 主动 yield 后继续。空队列、流控阻塞与已关闭方向不忙轮询；四项预算不变 | 九个不产生 QUIC 包的合法 Body 任务：旧行为处理四个后不再调度；新行为有界排空且恢复 request/active 资源 |

DNS read-only prepare/传播各有 15 秒总预算；候选解析最多 5 秒，传播候选最多 1 秒，最多 32 个地址。HTTP 控制请求也改用根 resolver 的独立控制预算。已运行的系统阻塞解析 job 持有 permit 至实际结束；取消 async waiter 不会提前返还。同步 fsync 不能被普通 async timeout 抢占。

ARI 成功响应的重新检查间隔限制为 60 秒至 24 小时；429/503 的有效 Retry-After 不套用该 cap。订单和限流等待同样不受 ARI 本地上界截断。没有可用等待头时保留原库 250 ms、倍增退避，DNS 传播另用 poll_interval。无法表示的远端时间返回错误并保留订单，随后按有界错误退避重试，不转换成 u64::MAX。

证书 invalid-material、本地 I/O/trust-config、链或本地信任待调查、future-notBefore、暂态 HTTP 与真实 durability uncertainty 分开处理。future-notBefore 保留原订单/key/CSR；永久异常材料有界阻塞供调查，不无限下载/创建订单。链错误无法单凭验证失败归责远端或本地；保留待调查分类。持久化不确定令 Manager suspended，不继续副作用；网络独立检查身份有效性。

outer 文件不变也继续按时间检查；outer 到期暂停新握手，inner 更新仍可加载，恢复 outer 后重新准入；不静默关闭 ECH，旧连接按原生命周期继续。CURRENT、内存 loaded generation 和 TLS-LOADED 是三种事实，status writer 明示未进行握手探测。

### 状态、所有权与合并

DNS 单域名单订单状态为 `Preparing → CreateUncertain → Created → Validating → DeleteUncertain → removed`。可借用记录保留 borrowed，始终不删除；marker/record ID 仅允许清理自己记录，foreign TXT 保留。默认 recover 也拒绝无证据的不确定创建。两 provider 共用 adopt/recover/cleanup 所有权政策，保留各自认证与 API 语义。

必须保留崩溃间隙：持久 intent 后、POST 前崩溃，与 POST 后响应丢失可能磁盘状态相同。空列表不是未发送证明；无服务端幂等/提交期限承诺时保留对账和人工调查路径，不清 journal、不删除所有同名 TXT。

Manager 直接拥有本地 `Option<VerifiedBundle>`；只有网络 TLS generation 仍需共享不可变 Arc。持久化模块保留 journal、generation/CURRENT 提交、no-overwrite import 三类不同失败语义，没有把它们伪装成一个事务。

| 删除/迁移的源文件 | 现在的职责位置 |
|---|---|
| acme/eab.rs | acme/account.rs：账户、EAB 导入/注册 |
| acme/state.rs + acme/store.rs | acme/persist.rs：锁、journal、发布、私密导入 |
| net/outbound.rs | net/egress.rs：已验证候选、固定下一跳、Stream |
| net/site/forward.rs | net/site/upstream.rs：共用 peer/timeout/TLS 构建，公共转发 ACL 与配置源站政策仍不同 |
| net/site/generation.rs | net/site/bridge.rs：有界 single-flight 重建、冷却、共享 shutdown、无重放 |
| net/resolve.rs | src/resolve.rs：控制/数据独立预算，没有中间转发层 |
| tools/acme-lab/env.sh | 私有 run.py 的工具发现和参数；没有第二套 suite 定义 |
| tools/acme-lab/README.md | 本文的运行说明 |
| 四个 docs/acme-lab-*-index.json | 先归档可用原始工件，再移出维护源码；不计为生产复杂度下降 |

公共 Rust 路径随合并调整：`acme::eab` 改为 account 中的函数，state/store 改为 persist；通用 Error/Result 在 crate 根；Http.last_status 与 certificate::CertificateSlot 移除；Manager::slot 改为 current(now)。本包 publish=false，但源码嵌入者需更新调用。CLI 配置和 revision 4 wire 不变。vendor 新 Error 变体影响穷尽匹配，轮询等待现在遵守响应头。

journal 写入版本 3，读取旧版本 1/2 并保守迁移未标注 lease；旧全文证据在读入后截断再保存。旧二进制不能安全读取新状态；回滚必须使用事先备份并对账的完整状态目录，不能降级版本号或只删除 lease。已经超过旧 8 MiB 读取限额的历史损坏文件仍需保留调查，不能自动清空。

### 源码计量

按 Git 基线文件与当时文件逐项计数（不含 target/reports/外部工件），物理行用 `len(bytes.splitlines())`，包含注释和空白。src/core 中 runtime-bearing Rust 与独立测试文件分开；内联 cfg(test) 项/字段/语句及 test 项按 Rust AST 区间单列，不能把它们算作生产代码增长。旧 codec 的 `&raw` 解析器诊断位于完整排除的未改测试模块，已核对边界。

| 类别 | 文件数：前 → 后 | 物理行：前 → 后 |
|---|---:|---:|
| 运行相关 Rust（含内联测试） | 41 → 36 | 14571 → 15083 |
| 独立测试 Rust | 12 → 12 | 10433 → 11214 |
| 工具及其说明 | 12 → 10 | 1655 → 1747 |
| 生成 JSON（含未改的 packet-lab-results） | 5 → 1 | 46968 → 36856 |
| vendor（含其测试/文档/清单） | 474 → 474 | 204942 → 205048 |

运行相关文件中，内联测试为 3788 → 3928 行；扣除后的生产物理行估计为 10783 → 11155（增加 372）。生产正确性修复增加了代码；该次减少的是文件数、重复职责和无用共享所有权，不声称生产代码整体缩短。另有 28 个配置/文档/许可等第一方文件；第一方文件合计 98 → 87。生成索引单独减少 4 文件/10112 行，不能计作生产简化。

工具行数增加包含严格证据失败判据；删除重复的 Rust 隔离编排和 env.sh，保留唯一 Python orchestrator，避免维护两套流程。完整逐文件计量及一次性计数脚本在外部 `source-metrics.json`/`measure.py`，没有新增维护中的计量系统。

### 回归判据修正

- keylog 现在不再暗中把测试客户端接收窗口从 64 KiB 扩大至 1 MiB；网站/codec 抓包沿用原窗口和 5 秒断言。旧 packet-lab 摘要属于旧 profile，不作当时性能对照。
- intent_cancel 现在取消显式只读 prepare；另两个 case 单独保留真正 durable-intent/send 间隙。后者空查询必须仍不确定。
- Pebble 重启先等待 control_restored，不等待本不应发生的 cleanup。释放验证屏障前检查 TXT/lease 和删除标记；释放后同时等待 provider 完成与 journal 持久清空，避免把两者间隙误判成未清理。
- 隔离 mock 的“确定未发送”故障位于 prepare；不再用默认 recover=Ok 假装恢复创建。生产 Cloudflare/Porkbun 的实际恢复路径由单独 HTTPS mock 覆盖。
- retry_case 必须到达 finalize、返回预期 Tick、且等待 case 真正发生 poll；None 不满足计时断言。溢出 case 则必须有界延期。
- panic 测试改为有效网络继续、控制器不自动复活；Drop 屏障固定“用户关闭先于控制退出”，仍保留命中和真实握手断言；命名 IO/API/nonce 故障均断言实际命中，避免重构绕开故障点。
- 保留既有 codec、认证、预算、取消、半关闭、桥重建/POST 不重放、证书及权限回归；不以 ignored、通用重试或延长 sleep 隐藏失败。

### 该次执行与工件

最终命令均实际执行于应用该次改动的工作树，HEAD 仍为审阅基线；工件的 src SHA-256 已逐项与最终源码核对一致。提交只封装该已验证源码。没有将旧报告的结果算入该次成功。

| 实际命令/检查 | 该次结果 |
|---|---|
| `cargo test --locked --workspace`（由 `cargo xtask lab` 调用） | server 198、CLI 2、core 30、xtask 1 通过，0 失败；10 个 server 可选项、7 个 Pebble 项在普通 workspace 中 ignored |
| `cargo test --locked --test acme_pebble -- --ignored --test-threads=1 --nocapture` | 7 通过，0 失败；包含 nonce 100% 拒绝的预期有界失败，而非要求签发成功 |
| `cargo test --manifest-path vendor/instant-acme/Cargo.toml --locked --no-default-features --features time,x509-parser --lib` | 9 通过，0 失败 |
| `actual_system_dns_cancellation -- --ignored --nocapture` | 1 通过；隔离 namespace 中实际 libc DNS 请求、取消及 permit 回收 |
| Python evidence oracles | 3 通过；空抓包、decoder 失败、密码验证失败/未执行，以及原命令失败/零测试/缺 suite 不能被索引覆盖 |
| `cargo clippy --locked --workspace --all-targets -- -D warnings`；`cargo fmt --all -- --check`；`cargo xtask audit-native` | 各通过；正常依赖图、源 pin 和 vendor 摘要通过；图审计本身不等于原生编译 |
| `cargo check --locked -p moon-naive --lib`；`cargo build --locked --release -p moon-naive` | 各通过；GNU host 产物，不是 musl 发布物 |
| release CLI `--help/--version/status/config init/check-config/serve` 冒烟 | 成功；配置私密/no-overwrite，默认未授权 ACME 的 serve 拒绝且未开 listener |

最终入口的 oracles/workspace/Pebble/vendor/resolver 原始退出码全部为 0，verification errors=[]。74 份 pcap 解码得到 1641 条 HTTP/DNS 行、独立验证 372 个 JOSE 签名和 1 个 EAB HS256，错误签名和 protected.url 不一致均为 0；有 164 条 DNS 帧。214 是解码的证书项数，包含链和重复项，不等同握手次数或性能样本。

以下帧号局限于对应 case 的 wire.pcap；源为 pcap 的字段与测试日志事件在 timeline 中明确区分：

| case | 该次可核对证据 |
|---|---|
| `nonce404-133161-1793961001795973598` | 帧 63 HEAD newNonce →65 HTTP 404；没有 POST /order/1；journal 前后 URL/key/CSR 相同 |
| `retry-after-133161-1793960881042076612` | finalize 帧 97→99，Processing、Retry-After:120；下一次 order POST 为114；服务端单调实测 120073 ms，Installed |
| `retry-after-beyond-deadline-133161-1793961015122193112` | finalize 97→99；没有后续 order poll，日志为 RetryScheduled，保留原订单和 UTC next_attempt=1793961136 |
| `dns-cloudflare-late-133161-1793960865136986665` | 创建提交 epoch 1793960865.820851；空 cleanup 的 journal 在 1793960866.594318；远端提交在 1793960867.022518，重开后按原 marker 对账，foreign TXT 保留 |
| `live-renew-outer-133161-1793961055564780278` | 实际新 H2/H3 leaf serial 均为 11→12→13，CURRENT/TLS-LOADED 跟随 generation，旧连接持续请求；handshake-analysis 有独立解码的证书项 |

试运行目录 `pebble-corrected`、`final-lab`、`verified-consolidation`、`acceptance` 的非零退出码全部保留；分别暴露了 provider mock/清理观察时序、我引入的备用等待间隔错误、control/shutdown 顺序竞态及旧 H3 时限反例。`coalesced-wake-before.log` 为确定性队列反例 0 通过/1 失败，修复后通过；不是按失败条数累加独立缺陷。
- 当时证据目录：`/workspace/consolidation-evidence/`（私密，源码树外）。
- 历史原始工件及被删除的四索引：`baseline-evidence.tar.gz`；本环境中旧报告引用的六组原始资料均可归档。旧结果仍属于旧提交。
- 最终入口输出：`verification-final/result.json` 与 `verification-final.tar.gz`；pcap、测试 keylog、完整 journal 只在外部私密工件，不进入 Git/source archives。
- 每个 case 的 timeline 明确区分 `pcap` 帧和 `test_log` 事件；网络激活依据实际新 H2/H3 握手 leaf serial/fingerprint，文件/Manager 变化不足以证明激活。

### 验证边界

旧网站和 codec 用例各出现过一次间歇 H3 超时。补齐原窗口抓包后的 20 次隔离诊断均通过，未捕获同一次停滞；有界队列进度缺陷另由确定性组件反例证实并修复。不能据此证明该修复解释了所有时限失败，或以后不会复现；原始失败与诊断工件保留。

独立 Pingora 上游全套、其他 target/MSRV/musl 静态 ELF 门禁该次未执行；改动的三个 Pingora 文件由本仓库真实网络回归覆盖。

该次主机为 Linux GNU x86_64、Rust 1.93.0。真实 Chromium revision 4 配套客户端仍未实现；没有用官方 Naive、TLS 成功或少量 pcap 推断兼容性或不可识别。没有真实 CA/DNS、生产凭据、独立进程/UID、自动 outer 签发、其他 target、长期 soak 或 release 性能实验。

控制线程仍与网络同进程/UID，不能视为密钥权限隔离。静态 bounded 设计和测试 RSS/FD 观测不是吞吐优化证明。性能基线仍需匹配硬件/内核/编译/配置，测成功率、p50/p95/p99、吞吐、CPU/RSS/FD、task/queue、连接/stream/permit 和 bridge generation；没有这些测量，该次不宣称提升，也不建议改队列/复制/批处理。

## Staging 信任根来源

`le-staging-roots.crt` contains public CA certificates, not private keys.
Retrieved over verified HTTPS on 2026-10-21:

| Source | SHA-256 certificate fingerprint |
| --- | --- |
| https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem | E70570A989F8565AABDF7CAE27ABD1621872D6A3F811E3FEF27E3DBA02912198 |
| https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2.pem | 9B2A339FE6A3E85585C4CD75536CB8C1CF7CD603B9A64BEC2521858AE48DA85D |

These additional roots are used **only** to validate issued certificates when
the configured directory is the built-in Let's Encrypt staging directory.
They are not added to the CA API HTTPS client, the Cloudflare API client, or the
production certificate validator. Staging certificates are not browser trusted.

`gts-test-roots.crt` contains the two public Google test roots, retrieved over
verified HTTPS from https://pki.goog/test_roots.pem on 2026-10-21.
Bundle SHA-256: `70548cf799245900c44e46a19513f59eb67badc9a5170ce9c9f04ffe1c7238b1`.

| Subject CN | SHA-256 certificate fingerprint |
| --- | --- |
| Test GTS Root ECC | 036649D176EF17B766CF4F44F4A9B6B86C95513E748355EFF1193332194D87BF |
| Test GTS Root | 77321BF854FD9C18C04C7EEACF4F5BDB2B946620BFC57BD70518BDECA05C90C7 |

Google test roots apply only to the built-in Google staging directory with
`issuer = "google"`. They are not added to production, custom directories,
the CA API HTTPS client or any DNS-provider HTTPS client. Trust selection is restricted by issuer/environment/directory in the runtime validator. These are not production trust roots.

## mona server implementation update

The authoritative wire contract is [PROTOCOL.md](PROTOCOL.md). The current
implementation and verification checkpoint is [IMPLEMENTATION.md](IMPLEMENTATION.md).
Production client development is deferred; restored clients are test fixtures.

Ordinary authenticated forwarding now uses `[proxy.forward]`, independent of
`[website]`: maximum unique upload 1 GiB, connect deadline 10 seconds, upstream
read/write timeouts 120 seconds, idle pooled connections 30 seconds, per-user
concurrent forwards 32. Limits apply while streaming, without whole-body buffering.
Older configurations remain parseable but no longer inherit website upload/time
limits. Set explicit forward values to retain the previous effective policy.
CONNECT continues using `[limits]`; configured fixed private website origins remain
separate from public-destination egress policy. Forward requests acquire global
active-stream and per-user admission before DNS and retain it through completion.

Incomplete H3 request headers have an absolute 10-second deadline starting when
request stream bytes become readable, before the H3 parser consumes them. Other
traffic does not extend it. Expiry closes that connection (0x107), including other
streams, to release partial parser state. This is a bounded-ownership choice,
not a claim that an unbounded-memory vulnerability was established.

Fast validation: `python3 tools/vectors/generate.py --check` and
`cargo test --locked -p moon-naive-core`. Native loopback validation:
`cargo test --locked -p moon-naive --lib -- --test-threads=4`. The synthetic ACME
suite includes a real 120-second Retry-After test. Ignored experiments are not
part of the passing runtime acceptance count. Rust 1.89 core tests and server
compilation were checked; final change validation status is in the checkpoint.

### Private renewal health

`moon-naive status config.toml` reads the private `state_dir/acme/WORKER`
observation in addition to validating the installed certificate. It reports
worker running versus stopped/stale, process identity, heartbeat age, last
successful installation, next attempt, failure phase and reconciliation flag.
Heartbeat freshness uses Linux uptime, process start ticks and boot identity;
a stale file or recycled PID cannot establish worker liveness. This is separate
from data-plane readiness and does not perform a network handshake. Heartbeats
run every five seconds while a renewal operation waits; observations older than
15 seconds are stale. The last-success field is scoped to this worker run.
Worker panic/stoppage does not disable a valid already-serving TLS generation.
A persistence failure can stop renewal; inspect the journal and service logs.

If a confirmed TXT record disappears or changes during propagation, the provider
now reports that operator reconciliation is required and retains ownership. It
does not recreate or adopt a foreign replacement. An uncertain creation with an
empty listing remains uncertain. Do not clear journals to force issuance.

### Source snapshots

`cargo xtask source dist HEAD` resolves HEAD to a commit once and packages Git
objects, including tracked vendor sources and licenses. An explicit commit may
replace HEAD. Tracked worktree/index changes are rejected; untracked files are
excluded, including untracked files under vendor. Symlinks and submodules are
rejected. Executable bits are retained; SOURCE_REVISION records the resolved
commit and SHA256SUMS is regenerated for the archive contents. The archive has
its own checksum sidecar. This does not establish runtime correctness or sign
its provenance. Commit reviewed changes before packaging; never add credentials
just to make them eligible for an archive.
