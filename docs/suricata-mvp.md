# Suricata MVP 方案

## 目标

用 Suricata 快速获取稳定网络事件，验证防代理风险模型。

## 输入

Suricata EVE JSON，优先关注以下事件类型：

- `flow`
- `dns`
- `tls`
- `http`
- `quic`
- `alert`

## 首轮测试机

`192.168.0.30` 作为首轮镜像流量测试机。测试流程见 [192.168.0.30 Suricata 镜像流量测试](testing-192.168.0.30-suricata.md)。

本轮只验证 Suricata EVE JSON 信号覆盖和 fixture 准备，不接风险引擎，不执行任何处罚动作。

## 适配器

`suricata-adapter` 负责：

- 从文件、stdin 或 Unix socket 读取 EVE JSON。
- 将不同事件转换为标准事件。
- 对无法识别字段做容错。
- 保留 `raw_ref` 或原始摘要，便于回放。

## 最小命令形态

```bash
proxy-sentinel adapter suricata --input eve.json --output events.jsonl
proxy-sentinel replay --input events.jsonl
proxy-sentinel evidence --input events.jsonl --output evidence.json
proxy-sentinel risk batch --input evidence.json --output risk-snapshots.json
proxy-sentinel risk list --input risk-snapshots.json --min-level suspicious
proxy-sentinel risk inspect --input evidence.json --ip 10.1.2.3
proxy-sentinel shadow run --eve /var/log/suricata/eve.json --state data/shadow/state.json --out-dir data/shadow
proxy-sentinel control-plane serve --addr :8080 --shadow-dir data/shadow --frontend-dir frontend/dist --read-only
```

当前已实现前两条命令：

```bash
go run ./cmd/proxy-sentinel adapter suricata \
  --input examples/suricata/eve-mirror-20260724-131645-redacted.jsonl \
  --output /tmp/proxy-sentinel-normalized.jsonl \
  --sensor-id lab-30

go run ./cmd/proxy-sentinel replay \
  --input /tmp/proxy-sentinel-normalized.jsonl \
  --output /tmp/proxy-sentinel-replay-summary.json

go run ./cmd/proxy-sentinel evidence \
  --input /tmp/proxy-sentinel-normalized.jsonl \
  --output /tmp/proxy-sentinel-evidence.json \
  --window 10m

go run ./cmd/proxy-sentinel risk inspect \
  --input /tmp/proxy-sentinel-evidence.json \
  --ip 10.255.0.3

go run ./cmd/proxy-sentinel shadow run \
  --eve /var/log/suricata/eve.json \
  --state data/shadow/state.json \
  --out-dir data/shadow \
  --sensor-id office-30 \
  --window 10m
```

`adapter suricata` 支持 `flow`、`dns`、`tls`、`http`，会跳过无法解析的 JSONL
行和暂不支持的 Suricata 事件类型，并在 stderr 输出转换统计。

`replay` 只读取标准事件，不依赖 Suricata 原始字段。它会按 `subject.ip`
聚合 1m、5m、10m、1h 窗口，并输出事件数、事件类型分布、域名基数、UA
基数、JA3/JA4 基数和目的端口基数。窗口结束时间取输入中的最新事件时间，
保证固定 fixture 多次回放结果一致。

`evidence` 在标准事件上生成可解释证据。当前支持 `multi_user_agent`、
`multi_ja3_ja4`、`domain_diversity` 和 `port_distribution`。`ttl_clusters`
需要标准事件先提供 TTL 信号，暂不在证据层伪造。

`risk inspect` 只读取证据输出，生成单个 IP 的风险快照。当前推荐动作全部为
影子动作，不触发降速、踢线或封禁。

`shadow run` 读取 Suricata EVE 的增量内容，每轮输出 `normalized.jsonl`、
`evidence.json`、`risk-snapshots.json`、`risk-list-suspicious.json` 和
`run-summary.json`，并用 state 文件记录上次 byte offset。默认保留最近 7 天
run 目录。

`control-plane serve` 读取 shadow run 产物，提供只读 `/api/v1` 接口和可选
前端静态文件服务。第一版不保存标注，不执行规则热加载，只返回 shadow/read-only
状态。

## 最小事件覆盖

| Suricata 事件 | 标准事件 | 必要字段 |
| --- | --- | --- |
| flow | flow | src_ip、dst_ip、src_port、dst_port、proto、bytes、pkts、start、end |
| dns | dns | query、qtype、rcode、answers |
| tls | tls | sni、ja3、ja4、version、alpn |
| http | http | host、method、url、user_agent |
| quic | quic | sni、alpn、version |

## MVP 风险规则

- 同一 IP 在 10 分钟内出现多个明显不同 UA。
- 同一 IP 在 10 分钟内出现多个 JA3/JA4。
- 同一 IP 的 DNS/SNI 基数异常高。
- 同一 IP 的目的端口分布异常。
- 同一 IP 出现多设备指纹。

## 影子模式

MVP 默认不处罚，只输出：

- 风险等级。
- 风险分。
- 证据列表。
- 原始事件样本。
- 建议动作。
