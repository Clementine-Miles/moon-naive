# OpenGFW 离线对照实验

2026-10-28。实验工具不属于 moon-naive 生产依赖，也不进入生产包。

## 来源与版本

原 `apernet/OpenGFW` GitHub URL 当前返回404。维护者在[HyNetworks/OpenGFW README](https://github.com/HyNetworks/OpenGFW/blob/dcf8348118c6184fe950fcd7da714227ac4ea7a0/README.md)说明重新公开项目。本次固定[官方v0.4.3](https://github.com/HyNetworks/OpenGFW/releases/tag/v0.4.3)，commit `dcf8348118c6184fe950fcd7da714227ac4ea7a0`，MPL-2.0，源码在 `/workspace/OpenGFW-reference`，未修改。`OpenGFW` 是该release的linux-amd64二进制，SHA-256 `718c34cbf1b0de6cd166eb8d394dd27c4f459292fd8fdfef50199edcd1db857f`，与GitHub API的asset digest一致。版本后main分支的ESNI改动不在本次实验范围。

上游CLI只有NFQUEUE输入，没有离线PCAP模式。本目录 `opengfw-pcap` 是小型外部适配器，复用原版 `engine.NewEngine`、gopacket TCP重组、Expr规则引擎及全部原版分析器；仅替换 `PacketIO` 与JSON日志。原版NFQUEUE实现虽为Go包依赖，但没有实例化。没有更改分析器、阈值或服务端，也没有修改iptables/nftables、注册NFQUEUE或主动探测公网。

适配器按文件顺序读PCAP/PCAPNG，剥去链路头，按双向五元组分配stream ID；每包等待worker完成，EOF前排空。单worker避免离线乱序。上游PacketIO接口只有IP字节，不接收捕获时间，因此这里不模拟真实时延、丢包时钟或NFQUEUE性能；Trojan分类器本身使用重组数据的方向/长度。只接收完整捕获包，遇截断报错；需要单链路类型的PCAPNG。它不能替代真实链路或真实GFW。

## 固定规则与证据

`rules.yaml`只记录，不提前allow/block；否则在TLS识别时allow会阻止后续Trojan分析。规则SHA-256 `55af2822dbff1a8de29604eb05b0d10bf5e671f8fd6b155cfb9bf10e6659851f`。没有按moon-naive结果反向调规则。

- TLS / QUIC：读取明文或Initial可恢复的ClientHello、外层SNI、ALPN、版本、ECH扩展存在标记。ECH存在可能是GREASE；它无法确认ECH接受，也无法解密内层名字。
- HTTP：只解析明文HTTP，不解密TLS后的H1/H2/H3头部；没有密钥输入。
- FET：仅根据第一个重组payload及已知TLS/HTTP前缀等豁免条件判断。正常TLS ClientHello会触发豁免 `ex5=true, yes=false`；这不证明padding有效，更不代表降低TLS密文熵。
- Trojan：原版包含TLS-in-TLS长度决策树，等待客户端payload以六字节CCS模式开头后，累计四段交替方向字节量，在第五段出现时判定。不是可靠的通用TLS-in-TLS检测，不专门支持H2多路复用或QUIC；未见CCS边界/方向切换不足/配额耗尽会无结论。上游注释也明确反对仅凭阳性直接封禁。**缺少 `trojan.yes` 必须记作无结论，不能记阴性。**
- 固定SNI/HTTP Host `blocked.test`是本地正对照条件，不是对真实审查黑名单的复现。

`make-controls.py`生成8项独立分类器对照，`verify-controls.py`断言：TLS SNI正/负、HTTP Host正/负、FET正例、Trojan决策树正/负、上游Chromium153分片QUIC样本。TLS ClientHello有正确字段；Trojan四flight是人工长度输入，并非完成的加密会话。QUIC payload来自固定上游的testdata。所有包都有Ethernet/IPv4/TCP/UDP及有效校验和。原始日志和结果在 `controls.jsonl` / `controls.result.json`。这些只证明适配器和规则确实工作，不能作为真实代理被检出率。

## 重现

源码包不包含二进制。先按下文构建适配器；离线分析无需root。

```sh
cd tools/packet-lab/opengfw
./opengfw-pcap -pcap /absolute/path/sample.pcapng -rules rules.yaml -port 443 > sample.jsonl
python3 summarize.py sample.jsonl --output sample.summary.json

python3 make-controls.py
./opengfw-pcap -pcap controls.pcap -rules rules.yaml > controls.jsonl
python3 verify-controls.py
```

省略 `-port` 会分析捕获的所有TCP/UDP端口。摘要按双向五元组汇总，不把关闭后的纯ACK生成的空重组对象算成新连接；原始engine ID仍保留。不应把五元组数直接等同于用户请求数。

在仓库根目录准备固定版本的外部分析器（只用于实验，不参与 Rust 服务端构建）：

```sh
git clone https://github.com/HyNetworks/OpenGFW target/packet-lab/OpenGFW
git -C target/packet-lab/OpenGFW checkout dcf8348118c6184fe950fcd7da714227ac4ea7a0
cd tools/packet-lab/opengfw/adapter
go build -trimpath -o ../opengfw-pcap .
```

适配器使用 Go 1.27；go.mod 的本地 replace 指向仓库内 target/packet-lab/OpenGFW，保留该布局。
`make-controls.py`也使用该路径，或使用`OPENGFW_SOURCE`指定同一版本的源码。
所有Go代码仅用于离线实验，moon-naive运行与构建不使用它。摘要不能确认真实Chromium代理端到端指纹，也不能证明抵抗真实审查设备。

## 额外非 TLS 对照

`python3 verify-nontls-control.py` 使用普通 TCP 包模拟首段 `NOT_TLS_START`，后接人工 CCS 和 `[300,100,300,100]` 的四段长度。固定的原版引擎返回 `trojan.yes=true`，同时没有 TLS 解析结果，原始 PCAP/JSONL 为 `nontls-control.pcap`/`nontls-control.jsonl`。它验证了该启发式可能对非 TLS 输入产生阳性，而不是完整 TLS 连接的实验。此版本 `analyzer/tcp/trojan.go` 的 `first` 默认为 false，未被初始化为 true，其首段 TLS 检查分支不会执行；没有修改上游代码。规则应与其他协议事实结合判断，不能将单个 Trojan 阴性/阳性视为安全或封锁结论。

对已完成、验证了包尾完整性的抓包阶段，可运行 `python3 analyze-captures.py baseline-complete` 生成每场景原始事件、摘要和 `opengfw-matrix.json`。旧的 `baseline/` 被标为不完整，工具会拒绝使用；真实 GFW 行为、真实 Chromium 用户行为和真实链路时延均不在这个离线实验中。
