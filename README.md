# Proxy Sentinel

Proxy Sentinel 是下一代防代理/共享上网检测系统，目标是替代旧版 `dpi-analyze` 中以 gopacket、静态阈值和设备数量触发为主的实现。

项目中文名：代理哨兵。

## 目标

- 用成熟采集后端快速获得稳定网络事件，避免一开始就重写 DPI 数据面。
- 通过标准事件模型解耦 Suricata、Zeek、AF_XDP、DPDK 等采集方案。
- 用证据聚合和风险评分替代单特征阈值触发。
- 每一次判定都必须可解释、可回放、可灰度。
- 保留未来自研 Rust/AF_XDP 数据面的迁移空间。

## 推荐路线

第一阶段使用 Suricata 作为采集和协议解析后端，输出 EVE JSON，再由 Proxy Sentinel 适配为标准事件。

后续如果 Suricata 的性能、延迟或定制化能力不足，再并行开发 Rust + AF_XDP sensor。风险引擎只依赖标准事件，因此采集后端可以替换。

```text
Suricata / Zeek / AF_XDP / DPDK / pcap
        |
        v
Normalized Events
        |
        v
Evidence Aggregator
        |
        v
Risk Engine
        |
        v
Decision / Policy
        |
        v
Notify / Slowdown / Offline
```

## 当前内容

- [架构设计](docs/architecture.md)
- [开发时间线](docs/roadmap.md)
- [技术选型评估](docs/stack-evaluation.md)
- [标准事件模型](docs/event-model.md)
- [证据与风险评分](docs/risk-engine.md)
- [Suricata MVP 方案](docs/suricata-mvp.md)
- [192.168.0.30 Suricata 镜像流量测试](docs/testing-192.168.0.30-suricata.md)
- [项目协作 Skill](skills/anti-proxy-v2/SKILL.md)

## 开发原则

- 先验证有效信号，再追求极限性能。
- 先影子模式，再策略处罚。
- 所有风险结果必须包含证据列表。
- 热路径只做必要解析和投递，业务判断不进入抓包热路径。
- 采集后端可以多选并存，不把系统绑定在单一框架上。

## 第一阶段验收

8 周内完成可运行 MVP：

- 能消费 Suricata EVE JSON。
- 能统一输出 flow、dns、tls、http、quic 等标准事件。
- 能按 IP 聚合证据。
- 能输出风险等级、分数、证据列表。
- 能以影子模式接入真实镜像流量。
- 能通过标注数据评估误报和漏报。
