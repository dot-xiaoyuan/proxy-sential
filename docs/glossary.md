# 术语表

## Capture Backend

采集后端，负责从网卡、镜像口、pcap 或日志中拿到网络事件。候选包括 Suricata、Zeek、AF_XDP、DPDK 和 pcap。

## Adapter

适配器，将采集后端的原始事件转换为 Proxy Sentinel 标准事件。

## Normalized Event

标准事件，是风险引擎唯一允许依赖的输入格式。

## Signal

原始信号，例如一次 TLS SNI、一次 DNS query、一次 HTTP User-Agent、一次 flow。

## Evidence

证据，由多个 Signal 在时间窗口内聚合得到，例如“同一 IP 出现多个差异明显 UA”。

## Risk Snapshot

某个 IP 在某个时间窗口内的风险快照，包含分数、等级、证据列表和解释。

## Decision

策略决策，将风险结果结合用户组、白名单、冷却时间和灰度策略，转换为动作。

## Shadow Mode

影子模式，只计算和记录风险，不真实处罚用户。

## Negative Evidence

负证据，用于降低误报的信号，例如加速器、模拟器、白名单和校园网业务系统。

