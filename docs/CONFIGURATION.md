# 单文件配置、自动证书与迁移

只维护一份 [config.example.toml](../config.example.toml)。三个旧示例已合并；内含中文说明、基础字段和可取消注释的高级参数。`schema_version` 默认2，仍兼容旧1/2；配置更新需要重启，证书续期和热更新自动完成。

## 最短使用流程

先按 [VPS-GUIDE.md](VPS-GUIDE.md) 安装程序、服务用户和系统 CA。以服务用户在可信、可写目录执行：

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

### 可以省略的配置

- `schema_version=2`、`state_dir="/var/lib/moon-naive"`；后者需服务用户可写并持久保存。
- 整个 `[listener]`：IPv4 TCP/UDP 443，H1网站/H2/H3开启，80跳转默认关闭。H2/H3仍必须开启，H1仅网站；IPv6需显式配置监听地址。
- 整个 `[limits]`：100条流、128连接、64MiB共享接收窗口预算；完整数值见示例注释。
- `[acme]` 中的 `enabled=true`、`challenge="dns-01"`、`dns_provider="porkbun"` 和超时/续期/退避参数。
- `[transport]` 默认 `system/cubic`，无需先开启内核 BBR；按需覆盖为 `bbr/bbr2`。

省略 issuer 仍为 `letsencrypt`，省略 environment 仍为 `staging`，不会暗中将旧配置的 CA/账户切到 GTS 或 production。推荐保留示例中这两项显式选择。每个可选表允许只写需覆盖的字段；未知字段仍报错，不因默认值而默默吞掉拼写错误。

`website.origin` 展开为一个固定池和 `/` 路由，并将回源 Host 设为源站 authority（含显式端口）；HTTPS 默认以源站主机名进行 SNI 和证书校验。它只能包含 HTTP(S) scheme、主机、可选端口和可选末尾 `/`，不接受登录信息、子路径或 query。不能与 `website.upstreams/routes` 同时配置。没有 website 配置时仍可启动，但没有完整网站，通常返回404；推荐始终配置真实源站。

源站不能指回对外域名形成循环；程序不自动改写源站的 Location、Cookie、HTML 或脚本。需要按路径分流、自定义 Host/SNI/CA 时，删除 `origin`，使用下方高级路由表。

配置文件必须为服务用户所有的普通文件、权限0600；父目录可信，状态目录0700。拒绝软链接，解析错误不回显原始文本。`config init` 不填真实密钥，也不自动接受条款。

## 用户与可选下一跳

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

0.6.0进一步在TCP监听前设置BBR，使尚未被accept的子连接也继承该策略。保留内核管理的收发缓冲，没有用固定SO_SNDBUF/SO_RCVBUF关闭自动调整。Linux的QUIC驱动用一个timerfd等待quiche给出的发送期限，避免毫秒计时器限制微秒级pacing；UDP阻塞时等待可写事件，64包处理额度用完后主动续调度。两种拥塞控制独立工作，均不新增空闲假流量或扩大认证前接收额度。

`check-transport`额外输出新socket读回的`tcp_congestion_effective`，以及H2/H3初始流窗口、H3增长上限、连接窗口和总接收预算。`system`可能已经继承VPS启用的BBR；实际连接仍应使用`ss -tin`检查。H2初始流窗口是`min(max_early_data_bytes,max_buffer_bytes_per_stream)`，不会在认证后自动变成后者；H3根据实际读取增长，最高为后者。服务端接收窗口影响上传，客户端接收窗口影响下载。只提高服务端内存上限不能解除客户端窗口或公网瓶颈。

上游链先本地解析最终目标并执行公网 IP ACL，再向配置的下一跳建立 CONNECT/SOCKS5 通道，SOCKS5 发送已检查的 IP，不委托远端 DNS。HTTP(S) 支持 Basic，SOCKS5 支持无认证或用户名密码。上游错误不回退直连。不是多跳任意链，也不允许通过它放行内网。已认证 H2/H3 普通 HTTP 请求使用相同出站策略，连接池按用户和目标 origin 隔离；不提供 407 引导认证或 H1 通用代理。

HTTP、SOCKS5 下一跳协议本身不提供 TLS；不能把本服务的入口加密当作下一跳链路加密。对不可信网络应选校验 CA/名称的 HTTPS 下一跳，或由部署者提供受保护的承载。CONNECT 也不会替任意明文目标协议提供端到端身份验证。

普通 HTTPS 正向代理的系统 CA bundle（可由 `SSL_CERT_FILE` 指定）在每个应用实例首次使用时加载并共享，更新系统根证书后重启服务。仍验证目标证书链和名称；不需要新增 TOML 字段。这与网站自己的 ACME 证书自动续期/热更新无关。

0.6.0起，固定HTTPS下一跳的CA文件和TLS上下文在启动预检的阻塞工作线程上构建一次，所有目标隧道共享这份只读上下文；每次仍创建独立TLS连接并校验证书链和名称。配置了不可读或无效的下一跳CA时，本地预检直接失败。更新下一跳CA/系统根证书后需要重启，不再在每次代理建连时重读；网站ACME证书仍按原机制热更新。HTTP/SOCKS5下一跳不初始化TLS上下文。

CPU加速自动使用部署主机的可用能力，无需增加TOML项。`moon-naive status` 或 `moon-naive check-transport /etc/moon-naive/config.toml` 输出架构、CPU能力和库的运行时分派方式。字节扫描采用memchr的AVX2/SSE2/通用路径，SHA-256与TLS分别保留sha2和BoringSSL的硬件检测；AVX-512检测为true不表示所有算法都会选用512位指令。说明与测量见[VPS-GUIDE.md](VPS-GUIDE.md#cpu-自动适配与延迟优化060)。

## 兼容旧配置与安全合并

schema v1/v2 的主配置加独立 users/Porkbun/EAB TOML 继续支持；旧示例文件已移除，新部署统一使用单文件示例。每类凭据只能选内联或文件一种来源。旧 `users.toml` 用 `[[users]]`，Porkbun 用 `apikey/secretapikey`，EAB 用 `key_id/b64_mac_key`。旧私有文件仍须 0600。

```sh
moon-naive config migrate /etc/moon-naive/old.toml /etc/moon-naive/config.v2.toml
chown moon-naive:moon-naive /etc/moon-naive/config.v2.toml
# 检查内容和权限后，停服务并切换到新配置。
```

迁移命令读取旧文件并写出完整 schema v2 TOML，0600、原子且拒绝覆盖现有目标；不修改源文件、账户、订单、TXT journal 或证书 CURRENT。不要在终端打印合并后的配置。迁移后由服务用户拥有新文件。

`moon-naive acme import-eab private-gcloud-export.json new-eab.toml` 仍可把 gcloud 导出转换为私有 TOML，随后将两个字段合并到主配置 `[acme.eab]`，或作为兼容文件引用。该命令不注册账户、不访问网络、不覆盖目标。Staging/production 使用分别申请的 EAB；`.dev` 浏览器需要 production 受信任证书。

## 从 pinaive 迁移

1. 只构建/安装 `moon-naive`，停止旧 moon-naive-net 与独立 ACME 服务，更新 ExecStart 为 `moon-naive serve <config.toml>`。
2. 更早的 JSON/纯文本凭据先转换为合法 TOML，再使用 config migrate 合并。不能仅修改扩展名。
3. 配置目录、站点目录与 state_dir 的路径都允许自定义。可以继续指向原目录；若改为 /etc/moon-naive、/srv/moon-naive、/var/lib/moon-naive，先停旧进程，完整迁移并保持私有权限与服务用户可访问性。
4. **保留整个旧 state_dir**，包括账户 journal、待清理 TXT、退避信息、证书 generations、CURRENT 和锁文件。更名不改变 journal namespace 或证书磁盘格式，已有账户无需重新绑定 EAB。不要清空状态以重试。
5. 运行 check-config、check、status，确认本地设置，再启动单一服务。没有旧版实验闸门；安装步骤见 [VPS-GUIDE.md](VPS-GUIDE.md)。

内部 ACME journal 继续使用 JSON，账户/订单/API 报文也遵循 ACME、Porkbun、Cloudflare 要求的 JSON；它们不是由用户编辑的运行配置。该兼容决定避免更名/配置格式调整导致账户或 DNS 清理状态丢失。历史 reports 和旧验证说明中的旧名保留原样，当前示例和命令均使用 moon-naive。

## 网站与反代

网站仅支持固定源站反代。删除旧 `site_root`、`website.files`、`website.static_cache_secs` 字段；它们现在作为未知字段拒绝。必须配置 upstream 和 route，建议用 `/` 覆盖整个网站。源站不可达时返回普通 502，不回退到内置页面或本地文件。

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

`max_total_receive_bytes` 是连接接收窗口预留总预算，不是 RSS 限额。默认连接窗口最多 16 MiB、总预算 64 MiB，因此可能先触发四个连接的窗口预算，再达到 max_connections。调整这些值会改变资源和网络行为，应按目标负载测量。

## 高级网站协议与边界

固定网站路由支持 H1 WebSocket Upgrade，以及 H2/H3 `:protocol = websocket` 的扩展 CONNECT，转换为固定上游 H1 握手，校验接受值和子协议，保留握手后一并到达的数据。它无需代理密码，但只允许配置域名/路径/上游，不能变成任意目标隧道；不支持 MASQUE、CONNECT-UDP、WebTransport。

100/103 中间响应、请求/响应 trailers 在 H1/H2/H3 网站路径转发；H1 使用 chunked。删除 trailer 中的认证、路由及消息分帧字段。SSE 和 gRPC 不动态压缩，gRPC 使用支持 H2 的 HTTPS 网站 origin。普通 HTTP 请求受请求体大小上限约束；成功升级后的 WebSocket 不按累计字节套用该上限，仍受缓冲、连接/流预算及读写/空闲期限约束；长时间无数据的 SSE 应由上游定期发心跳或调大 read_timeout_secs。

保留路由、压缩、固定反代；未引入内置静态文件、管理 API、目录浏览、模板、动态任意路由、MASQUE 或插件加载。配置与用户修改需重启，证书自动热更新，网站内容由真实源站维护。该功能范围不等于 Caddy 全部生态。

## 网站路由示例

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

## ECH（实验性接入，默认关闭）

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


## moon-naive：与旧客户端不兼容

当前采用认证协商的8/16条初期窗口及可选稀疏后段；满载读块停止附加填充，不生成空闲假流量或修改真实反代内容。预算、线格式与客户端要求见[PROTOCOL.md](PROTOCOL.md)。

H1 和 TLS1.2 H2 继续提供网站。ECH 配置不决定代理记录格式；开启 ECH 也不能替代客户端证书验证。现有 TOML schema v2 与moon-naive内部认证域修订3 是不同层次。

## RC4 压缩配置兼容

无需新 TOML 字段。`website.compression_level` 仍控制 gzip，后端改为 Rust miniz_oxide；`0` 禁用前端动态压缩，可由真实源站提供预压缩内容。RC4 不再构建本地 Brotli/Zstandard 编码器，接受 gzip 的请求可回退到 gzip，`gzip;q=0` 不会触发 gzip，显式更偏好的 identity 保持原文。已有 Content-Encoding 的源站响应继续透传；这不是将源站的 Brotli/Zstandard 内容重新编码。新后端的 CPU、输出字节和压缩率可能变化，不能据此宣称指纹更好。

## CONNECT填充协商

可在同一配置文件追加`[traffic]`：`initial_records = 16`（只允许8或16）及`sparse_padding = true`。这是服务端选择偏好和允许范围；实际模式须由每条CONNECT的请求/响应证明共同确认。没有空闲假流量或反代Padding开关。完整算法及协议版本见[PROTOCOL.md](PROTOCOL.md)。


## 自动证书

`moon-naive serve` 已集成自动 ACME：首次无有效证书时等待 DNS-01 签发，验证并安装后启动 H2/H3；随后自动续期和热更新，不再需要独立 ACME 服务。网络和控制面在同一进程的不同 runtime/线程运行。

推荐 Porkbun 注册、实际由 Porkbun 权威 DNS 托管的 `.dev` 域名，使用 Google Trust Services（GTS）。配置见 [CONFIGURATION.md](CONFIGURATION.md)，部署见 [VPS-GUIDE.md](VPS-GUIDE.md)。`.dev` 浏览器访问需要正常受信任的 production 证书；staging 证书不会因此受信任。

### Porkbun 与 GTS

在 Porkbun 为目标域名启用 API access，在私有主配置 `[acme.dns_credentials]` 中填写 `apikey`、`secretapikey`（兼容旧 `porkbun.toml` 引用）。配置 `dns_zone` 为注册 zone，例如 `example.dev`，不是完整代理主机名；程序检查实际 NS 委派，不会替你切换 DNS 服务商。

GTS 的首次账户绑定需要同一环境的 EAB。主配置 `[acme.eab]` 使用 `key_id`、`b64_mac_key`；可本地转换 gcloud 的私有导出：

```sh
moon-naive acme import-eab /private/gcloud-export.json /private/gts-eab.toml
```

输入须为私有文件，输出以 0600 创建且拒绝覆盖。导入只做本地格式转换，可将生成的两个字段合并进主配置 `[acme.eab]`，或保留兼容的外部引用，不能同时配置两种来源。Staging/production 的 EAB 不通用，首次注册后复用持久化账户；已持久化注册 key 时，账户注册响应丢失也会先按原 key 恢复，不会要求重复消耗 EAB。

建议先使用 staging 及对应 EAB，确认 DNS-01，再停止服务、完成待清理 TXT、切换 production 及对应 EAB。不同目录有不同 journal。设置 `accept_terms = true` 前自行接受 CA 条款；程序不替操作者接受条款。

若 zone 已设置 CAA，应允许 GTS 的 `pki.goog`；程序不覆盖 CAA。附带的 GTS/Let's Encrypt 测试根只用于对应内置 staging 证书校验，不加入 production 或 DNS-provider HTTPS 信任库。

### 生命周期与恢复

管理器持久化账户 key/URL、订单/证书 key/CSR、DNS TXT 意图与所有权标记、退避、Retry-After 和 ARI 续期窗口。网络操作前写入意图，响应不确定时按标记恢复；只清理自己创建的记录，保留借用或他人的 TXT。权威传播检查验证 DNS 响应，截断时转 TCP。

证书经 BoringSSL 检查 SAN、私钥匹配、链、有效期、叶证书用途，再 fsync generation、原子更新 CURRENT。失败不替换仍有效的证书。CURRENT 未变化时不反复构造 TLS 上下文；变化后共同发布 H2/H3 generation，坏更新保留有效旧上下文，过期后拒绝新握手。

状态目录使用 kernel 文件锁，进程死亡后释放；不要删除状态目录或锁文件来绕过正在运行的服务。升级或移动目录时保留整个 `state_dir`，包括 pending 订单和待清理记录。

### 维护命令

```sh
moon-naive status /etc/moon-naive/config.toml
moon-naive acme check-ca /etc/moon-naive/config.toml
moon-naive acme once /etc/moon-naive/config.toml
moon-naive acme cleanup /etc/moon-naive/config.toml
```

`status` 本地重验已安装证书，不报告进程是否在运行。`check-ca` 只读 HTTPS directory，不创建账户或订单，不改 DNS。`once` 执行当前计划允许的一次协调，不强制提前续期；重试/无证书返回非零。`cleanup` 只重试 journal 记录的 DNS 清理。另有 `acme run` 供独立维护使用，不能与读取同一状态的 `serve` 同时运行。

当前支持单机单域名、GTS/Porkbun 与 Let's Encrypt/Cloudflare。多 SAN/通配符、按需域名、分布式锁、多 CA 自动切换和 OCSP stapling 不在本版本范围。公网签发需要实际域名与私有凭据；本次本地测试不替代公网 CA/DNS 验收。

### GTS EAB 获取步骤与官方依据

以下核对于2026-11-02：[Google Public CA 教程](https://cloud.google.com/certificate-manager/docs/public-ca-tutorial)、[Porkbun API 入门](https://porkbun.com/llms/guides/getting-started)、[Porkbun DNS API](https://porkbun.com/llms/dns)。还以只读 HTTPS GET 验证了 GTS production/staging directory，两者均返回 newNonce/newAccount/newOrder 和当前条款 https://pki.goog/GTS-SA.pdf；没有创建账户、订单或修改 DNS。运行时 API 基址仍为 `https://api.porkbun.com/api/json/v3`；JSON 凭据字段为 `apikey/secretapikey`，TXT 创建/检索/删除接口及所有权 notes 与当前实现对应。

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

### 其他 CA/DNS 组合

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

### 常见配置问题

| 现象 | 核对项 |
| --- | --- |
| 配置文件不私有或不可读 | 确认服务用户拥有文件、0600、父目录可访问，编辑器没有改成软链接/0644 |
| `accept_terms` 拒绝启动 | 接受当前 CA 条款后在已有 `[acme]` 中设 true；check-config 通过不表示已同意 |
| EAB base64url 错误 | 复制 b64MacKey 原文，不填 JSON/PEM，不夹杂空格；线上注册失败还需核对环境与7天有效期 |
| 首次一直等待证书 | 检查日志中的失败阶段、API access/权限、真实 NS、CAA、DNS传播及 HTTPS/DNS 出站；保留退避与状态，不删目录 |
| 网站502或跳转到源站 | 检查 origin可达性、证书和虚拟主机配置；绝对跳转/链接不自动改写 |
| 官方 NaïveProxy 客户端连不上 | 本项目协议修订4不兼容官方旧认证，配置简化不改变此事实 |


## instant-acme 账户实现

ACME 协议请求（包括 EAB JWS、nonce 重试、订单和 ARI）统一由 instant-acme 处理，DNS 操作仍由内置 Porkbun 适配器完成，无 shell hooks。账户私钥在联网前持久化；遇到一次性 EAB 注册响应丢失，先用同一私钥查找既有账户，再决定是否注册。旧版仅保存 account_id/key 的日志仍可恢复。

固定版本的 instant-acme 已随 vendor 提供。唯一 API 补丁允许使用已保存的私钥和 EAB 调用其原有注册实现，来源与差异见 vendor/instant-acme/MOON-PATCH.md。无需删除状态目录或重新申请 EAB。
