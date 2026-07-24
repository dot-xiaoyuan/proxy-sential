# 架构设计

## 背景

旧版 `dpi-analyze` 的主要问题不是 Go 语言本身，而是抓包、协议解析、特征统计、设备聚合和策略处罚混在同一条链路里。随着规则增加，系统会越来越难调优，也难以解释误报。

Proxy Sentinel 的新架构采用三段式：

1. 采集后端负责拿到网络事件。
2. 标准事件层负责屏蔽不同后端差异。
3. 风险引擎负责证据化判断和策略输出。

## 分层

```text
capture-backend
  Suricata / Zeek / AF_XDP / DPDK / pcap

adapter
  将不同来源转换为标准事件

event-bus
  Redis Stream / Kafka / NATS / 本地文件回放

evidence
  滑动窗口、去重、基数统计、指纹关联、负证据识别

risk
  风险评分、等级判定、解释生成

decision
  白名单、用户组策略、冷却、灰度、动作编排

control-plane
  API、管理页面、规则配置、标注、审计
```

## 数据流

```text
Packet
  -> Capture Backend
  -> Raw Event
  -> Adapter
  -> Normalized Event
  -> Evidence Aggregator
  -> Risk Snapshot
  -> Decision
  -> Action
```

## 核心模块

### adapters

采集适配层。第一阶段实现 `suricata-adapter`。

职责：

- 读取 Suricata EVE JSON。
- 解析 flow、dns、tls、http、quic 事件。
- 转换为标准事件。
- 保留原始事件摘要，方便回放和审计。

### evidence

证据聚合层。

职责：

- 按 IP、用户、VLAN、时间窗口聚合事件。
- 识别多 UA、多 JA3/JA4、多 TTL 簇、多设备指纹、异常域名基数。
- 生成可解释 Evidence。

### risk

风险评分层。

职责：

- 将 Evidence 转换为风险分。
- 输出风险等级。
- 生成解释文本。
- 保留每个分数的来源，便于人工复核。

### decision

策略决策层。

职责：

- 接入用户信息、白名单、产品组、用户组。
- 根据风险等级决定动作。
- 支持影子模式和灰度。
- 所有动作写入审计日志。

## 后端可替换性

采集后端可以按阶段替换：

| 阶段 | 后端 | 目的 |
| --- | --- | --- |
| MVP | Suricata | 快速拿到稳定协议事件 |
| 增强 | Suricata + Zeek | 补充高质量行为日志和审计 |
| 性能版 | Rust + AF_XDP | 控制热路径和低延迟 |
| 极限版 | DPDK | 专用硬件和高带宽场景 |

风险引擎不能直接读取后端原始结构，只能读取标准事件。

