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
proxy-sentinel risk inspect --ip 10.1.2.3
```

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
