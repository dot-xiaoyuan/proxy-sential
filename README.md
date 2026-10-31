# Proxy Sentinel

Proxy Sentinel 是下一代防代理/共享上网检测系统，目标是替代旧版 `dpi-analyze` 中以 gopacket、静态阈值和设备数量触发为主的实现。

项目中文名：代理哨兵。

## 目标

- 用成熟采集后端快速获得稳定网络事件，避免一开始就重写 DPI 数据面。
- 通过标准事件模型解耦 Suricata、Zeek、AF_XDP、DPDK 等采集方案。
- 用证据聚合和风险评分替代单特征阈值触发。
- 每一次判定都必须可解释、可回放、可灰度。
- 保留未来自研 Rust/AF_XDP 数据面的迁移空间。

## 当前架构

```text
镜像流量 / Suricata / Zeek
        |
        v
标准事件与发现证据
        |
        v
eventbus（Redpanda）
        |
        v
ClickHouse 事件 / PostgreSQL 当前态 / Redis 热态
        |
        v
发现页、设备中心、风险与策略
```

发现页当前只采信镜像证据；精确 OS、交换机物理端口、全量服务端口和 SNMP/NDM 事件需要额外数据源，不能由被动流量稳定得到。

## 当前内容

- [文档索引](docs/README.md)
- [当前工作与下一步（2026-10-31）](docs/current-work-20261031.md)
- [发现数据重置与采集窗口](docs/discovery-data-reset-20261031.md)
- [高性能流式存储与投影方案](docs/high-performance-streaming-architecture-20261030.md)
- [架构设计](docs/architecture.md)
- [标准事件模型](docs/event-model.md)
- [网络设备发现](docs/network-discovery.md)
- [被动哑终端识别边界](docs/passive-dumb-terminal-identification.md)
- [前端架构](docs/frontend-architecture.md)
- [现场运维](docs/university-production-operations.md)

## 当前阶段

当前现场只使用镜像流量做被动发现，不依赖 SNMP/NDM 凭据。已接入：

- ARP、DHCP、DNS-SD、SSDP、LLDP 被动发现；
- eventbus → ClickHouse/PG 影子事实 → current 表 → 发现页；
- OUI 厂商、主机名类型/OS 线索、TTL/DHCP 被动信号、DNS-SD/SSDP 服务公告；
- 发现页终端台账、服务端口列、设备详情和证据历史。

不以主动扫描或伪造字段补齐 OS、交换机端口、全量服务端口。后续任务见当前工作文档。

## 开发原则

- 先验证有效信号，再追求极限性能。
- 先影子模式，再策略处罚。
- 所有风险结果必须包含证据列表。
- 热路径只做必要解析和投递，业务判断不进入抓包热路径。
- 采集后端可以多选并存，不把系统绑定在单一框架上。

## 当前验收边界

- 发现数据只来自镜像流量；
- 精确 OS 版本、交换机物理端口、全量开放端口和 SNMP/NDM 事件不在当前被动能力内；
- 发现页结论必须区分证据、线索和确定值；
- 具体验收项和命令见[当前工作](docs/current-work-20261031.md)。
