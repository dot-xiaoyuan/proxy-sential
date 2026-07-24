# ADR 0002: 第一阶段使用 Suricata 验证 MVP

## 状态

Accepted

## 背景

直接开发 Rust/AF_XDP 或 DPDK 数据面会带来较高工程和运维成本。在风险模型尚未验证前，过早投入底层性能优化可能偏离主要问题。

## 决策

第一阶段使用 Suricata 输出 EVE JSON，Proxy Sentinel 只做适配、证据聚合和风险评分。

## 后果

收益：

- 快速获得 DNS、TLS、HTTP、QUIC、flow 等成熟事件。
- 快速验证防代理信号有效性。
- 降低早期开发风险。

代价：

- Suricata 输出字段不一定完全满足定制需求。
- 极低延迟和极高吞吐场景可能需要后续 AF_XDP/Rust sensor。

