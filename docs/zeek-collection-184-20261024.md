# 184 Zeek 修复与协议采集恢复

## 授权与范围

用户于 2026-10-24 要求按检查建议的顺序执行：修复 DHCP 富化、完成已有设备发现恢复观察、分批补充设备识别协议，再评估限定候选范围的 Zeek IoT 元数据。全量 conn/DNS/HTTP/SSL 和没有业务适配器的其他普通日志不在本轮扩量范围内。

仅操作 `root@222.204.3.184`、`/opt/proxy-sentinel`。不清队列、不跳任务、不改变处罚和上报的仅记录边界，不启动本地数据库栈。现场数据库不备份、不造数，所有离线 Zeek 回放使用独立临时目录且不接业务 ingest。

## 现场基线与协作

- 00:41 核对 current 为 `2026.10.24-discovery-recovery2`，previous 为 `2026.10.24-discovery-recovery1`。
- 发现为 `consume-only`、1 路；DHCP 发现消费者停止。实时剩余 5,246,665 条、回填剩余 2,896,007 条，消费重试和超时均为 0。
- Zeek 8.0.9 集群由 manager、logger、proxy 和 4 个 worker 组成，worker 分别使用 enp8s0f0–enp8s0f3。现场和已安装的 local.zeek 均通过绝对路径加载 current 的 `assets/zeek/local-device-signals.zeek`，BPF 只放行 DHCP 67/68 及单 VLAN。
- discovery-worker 使用 bond0、既有私网 CIDR；已有 collection 只启用 DNS-SD、SSDP、WS-Discovery。目前 consume-only 没有接收这些新输入。
- 原自动观察 `184` 已暂时暂停调度，现场只读观察单元继续运行。由本线程统一接管后续阶段，避免两个线程同时改变版本、并发和输入。
- 现场控制面和前端有本地源码未保存的改动。本次资产发布必须逐文件保留 recovery2 的全部二进制和前端，不用当前源码重建覆盖它们。

## DHCP 故障与修复要求

`DHCP::aggregate_msgs` 在 manager 聚合，而连接对象存在于 worker。原脚本在 manager 调用 `lookup_connection(id)`，随后访问缺失的 uid，导致 VLAN 后的 options、vendor class 和 ACK 时间富化失败。

修复在 worker 的 `dhcp_message` 阶段读取 VLAN，随 DHCP 消息传给 manager；聚合阶段读取消息元数据，不反查连接。区分缺少元数据与明确无 VLAN，并保留跨 VLAN 冲突标记。回放另外发现原 priority=4 晚于基础处理器 priority=5 的即时写日志，可能遗漏当前 ACK 时间；修正为 priority=6，在 log_info 初始化后、基础写日志前富化。测试包括实际 Broker 跨进程传输、无本地 connection 的聚合、选项和厂商字段、广播/单播 ACK、无标签/单标签/双标签及冲突。

## 发布与观察顺序

1. 完成上述离线回放、相关 Go 测试、构建和 vet。将 recovery2 已校验发布包作为不可变基底，构建唯一版本的资产增量包，保存基底清单与本次 overlay 的源码差异及 SHA256。全部二进制、前端及迁移须与基底一致。
2. 重新核对现场版本、服务预期、迁移账本和配置。在既有单路完整 1,800 秒观察结束且 evidence-check 通过后，记录结果再发布。如果提前发布导致消费者重启，必须保留原样本并重新执行完整单路观察，不能拼接不同代次。
3. 使用标准 application-only 更新脚本验证包、已应用迁移和活动服务。无需数据库迁移；不执行备份。保留 recovery2 目录，成功后 previous 指向 recovery2。
4. 应用升级不会重启 Zeek。必须单独执行 `zeekctl check` 和 `zeekctl deploy`，确认全部节点运行、新 PID、实际脚本路径、DHCP 新字段和 reporter 错误。此阶段不扩大 BPF。保存原 local.zeek、node.cfg、zeekctl.cfg、单元及阶段状态。
5. 若旧单路观察已通过，发布后将 discovery 设为 consume-only、2 路，按新的消费者代次和独立样本完整观察 1,800 秒；否则重新完成单路再进入两路。阶段状态仍以 `/tmp/discovery-recovery-20261024/stage.json` 为准。
6. 两路通过后，遵循 [已有恢复记录](discovery-recovery-184-20261024.md) 的固定恢复 ID、切点和每次最多 500 批审计迁移，把旧实时任务转入 backfill；总剩余不能因迁移减少。随后恢复原有 passive 输入和独立 DHCP-only 消费。
7. 原输入恢复后完整观察 7,200 秒，要求连续四个 15 分钟窗口净消化且无一致性错误。该阶段通过前不新增协议。
8. 新增协议按独立分阶段计划执行，逐批保留配置与回退入口，检查输入、处理、错误、积压、证据和资源。不得仅以日志产生或 HTTP ready 宣称端到端通过。

每阶段出现内容冲突立即停止新领取；连续 60 秒无进度、两个连续 5 分钟窗口超时率大于 1% 或控制面异常，停止扩量并保留证据。未通过时不能扩大超时预算、清理任务或称为完成。

## 回退

本次资产发布的应用回退目标是 recovery2，不能回到有产品哈希问题的 recovery1。按发布时的活动服务集合恢复 current 和进程，另执行 Zeek check/deploy 加载旧脚本；恢复本次更改的独立配置和 service-expectations。不要使用按 enabled 自动启动全部消费者的通用回退入口。迁移170、任务原文、偏移、回执和恢复清单保持原状。

## 验证记录

- 相关 Go 包 `internal/adapter/zeek`、`internal/store`、`internal/discovery`、`internal/realtime`、`internal/evidence` 测试通过。
- `go build ./...`、`go vet ./...` 通过。
- 发布 Python 测试 71 项中 65 项通过、6 项环境依赖跳过；原恢复观察脚本 3 项通过。协议配置规划器 8 项通过。差异检查通过。
- Zeek 8.0.9 离线回放 4 项通过：PCAP 8 个场景、真实双进程 Broker 9 个场景，分别使用默认 50 条与立即落日志的 2 条阈值。manager 每次收到 18 条消息，确认没有本地连接，reporter ERROR 为 0。旧脚本对照复现 36 条连接查询/uid 错误及缺失的富化字段。合成数据仅在临时目录处理，未进入业务库。
- 独立代码审查通过，重点核对 Broker 序列化、执行优先级、ACK 方向、VLAN 冲突及重复日志断言。
- 00:50 现场最近 500 条发现回执全部与原始归档哈希一致，缺失/冲突为 0。
- 现场 170 个 PostgreSQL、49 个 ClickHouse 迁移校验一致，无待执行迁移；发现服务预期与实际一致。身份桥 ready=true，但仍有既存 38 条无效在线记录、业务状态 degraded，不视为全面健康。
- 协议作用域和归档归属追加回放通过：普通 `zeek-dhcp` 在 realtime/backfill 均不重复写标准事件；旧发现回填保留原事件。DHCP 同域 binding 测试证明原文不变，冲突/无效范围拒绝。无 binding 仍可能被选入但缺 interface，必须做完整作用域验收。

## 01:08 发布与现场验收

- 已发布 `2026.10.24-zeek-dhcp1`，包 SHA256 为 `e934cd69457836380e202e23e9118482856018fe27defa8cb6c4202dfd510476`。DHCP 资产 SHA256 为 `0ebdd04f46999242ee5fad72f64662708bfe3556a90b0f38fc43de4ebf5d8f5f`。
- current 为 `/opt/proxy-sentinel/releases/2026.10.24-zeek-dhcp1`，previous 为 `/opt/proxy-sentinel/releases/2026.10.24-discovery-recovery2`。全部 9 个程序、70 个前端文件和 220 个迁移目录文件逐文件与基底一致。170/49 个数据库迁移校验一致，无新增迁移、未执行备份。
- 单路有效观察 1,800.03 秒通过，窗口净消化 151,380 条、84.10 条/秒，末尾剩余 8,069,545 条；两段五分钟超时率均为 0。切换前最近 500 条回执全部原文哈希匹配。只代表该单路窗口通过。
- 应用升级校验通过，活动服务实际可执行路径均已切换。身份桥重启后目录同步发生一次 HTTP409，30 秒重试后恢复 24 个控制、29 个产品、catalog healthy；ready=true，既有 38 条无效在线记录和 degraded 状态仍在。
- 首次 Zeek reload 于 00:59:58 开始，01:01:58 触发 systemd 120 秒总超时。ZeekControl 按 workers/proxy/manager/logger 串行、每组使用既有 60 秒停止预算；未扩大预算，分步停止剩余 manager/logger 后再次受管 reload 成功。至少一个旧 worker 被标准停止流程最终 KILL，不能描述为全部优雅退出。保守记录约 **01:00:00–01:07:20 的采集缺口**；终止统计另有 67 个 not processed 包，不能宣称停机期间无遗漏。
- Zeek 7 节点均于 01:07:15–01:07:20 重新启动，PID 已更新。local.zeek、node.cfg、zeekctl.cfg 哈希未变，BPF 仍为原 DHCP 范围。
- 01:08 现场新日志 65 条，requested_options 61 条、vendor_class 40 条、capture_vlan 65 条；47 条含 ACK 的记录全部包含 lease_observed_at，reporter ERROR 为 0。这是初始实流验证，持续观察仍在进行。
- 原配置、单元和阶段记录保存在 `/opt/proxy-sentinel/config/change-records/20261024-zeek-dhcp1`；发布与验收 JSON/日志在 `/tmp/zeek-collection-20261024`，本地副本在 `artifacts/zeek-collection-20261024/`。

## 当前阶段与继续执行

01:08:28 已进入 `consume-two`、2 路、consume-only，新输入仍关闭，独立 DHCP 消费者仍停止。观察单元 `proxy-sentinel-discovery-observe-two-dhcp1.service`，全新样本 `/tmp/discovery-recovery-20261024/consume-two-dhcp1.jsonl`，连续 1,800 秒；不同进程代次不混算。已通过的 consume-one 证据写入 stage.json 的 completed_phases。

用户提醒额度有限，后续 heartbeat 改为每 30 分钟检查一次；服务器观察器仍每 5 秒采样。正常等待不重复构建或读取全仓，只在阶段完成或异常时执行对应步骤。**尚未恢复原输入或开启新增协议，不能视为全部完成。**

两路通过后按原恢复清单迁移历史 lane，再恢复原输入；但必须采用 [分批计划中的 DHCP 恢复纠正](zeek-protocol-expansion-plan-184-20261024.md)：仅启动独立旧 DHCP consumer 不会产生 V2 任务，需同步开启 Zeek owner 的 dhcp，并配置与原 capture domain `bond0-router-minimal-overnight` 一致的 binding，不能强改为 `bond0-passive-pilot`。现场四个 Zeek 网口已核对均为 bond0 的 slave，仍须核对 source/sensor/site、采集配置有效期和真实任务证据后应用。保持原事件与 source_kind，不另造 discovery-v2 批次。后续新协议及 IoT 仍按计划逐批验证。
