# 当前工作与下一步（2026-10-31）

## 目标

在只有镜像流量、没有 SNMP/NDM 凭据的前提下，尽可能提升发现设备的识别覆盖率，并把识别结果以“终端台账”的方式展示出来。

要求：

- 不发起主动扫描；
- 不伪造操作系统、接入端口或服务端口；
- 每个结论必须能追溯到镜像证据；
- 低置信度结果明确标注为“线索”。

## 2026-11-01 现场进展（184 测试联调环境）

下方“本地进展、待部署”段落保留当时的实施记录；本节记录 2026-11-01 03:42（北京时间）前的现场检查，不代表长期容量验收。

- 应用 `2026.11.01-mirror-discovery-r9` 已部署到 `/opt/proxy-sentinel/current`，`previous` 保留 r8；源码提交 `36f4ce44`，发布包 SHA256 `183d0f404972d9c690213875e6f5da88496a6ea6140546df537807655fdaf577`。PostgreSQL 候选迁移 214 项、ClickHouse 59 项与现场账本校验一致；本次 r9 为应用更新，未重新执行迁移。此次工作已执行 PostgreSQL 212/213 与 ClickHouse 059 迁移，按测试环境约定跳过备份。
- DHCP 旧 `device_dhcp_binding.log` reader 已审计退役；逐消息源 `dhcp-message-fresh-20261101T180643Z` 使用 `zeek-dhcp-message-v1` 持续读取 `device_dhcp_message.log`。旧源未完成输入按固定截止点和逐批清单标记为取消、未处理，原始文件及既有有效租约事实保留。REQUEST 只产生客户端识别线索，ACK 才产生地址绑定。
- 发现列表现按已生成的 current 投影读取，详情证据单独读取。路由镜像中同一网关 MAC 会伴随多个 IP；服务公告和 TTL 线索现须匹配来源 IP，OUI 补全只用于直接 DHCP 客户端 MAC，避免把网关的厂商、服务或 OS 线索传播给多台终端。页面标明 DHCP“逐消息源已登记”，旧协议计数标为“旧链路累计”。
- 一段已归档但未确认的发现 journal 曾使 ARP/DNS-SD/SSDP 停滞；已用原始 token 核验的 `stream-repair` 只重放该段的 archive lane，未删除原文。恢复后协议最近成功时间继续前进，隔离未处理数为 0。历史重置后的 TTL/握手文件源与共享任务代次不一致，已以旧/新代次哈希审计关闭两条旧共享源并激活新源 `shared-history-reset-recovered-20261101`；旧共享待办取消数均为 0，两条 reader 恢复逐批确认。
- 03:02 的只读健康核对：Redpanda 健康、两个消费组 lag 均为 0、控制面 `/readyz` 为 200、发现隔离未处理数为 0，current 台账 26,845 行，`missing_stream=0`。03:04 的台账快照有 26,856 行、25,467 行带 IP 与 MAC、14,250 个不同 MAC、14,310 行带名称；这些是带代次和作用域的**台账行**，不能视为唯一物理设备数。数字随事实自然过期和持续输入变化。
- 390×844、1280×800、1440×900 的现场截图与 DOM 探针通过：页面宽度均等于文档滚动宽度，表格容器宽度分别为 336、982、1142 px，文字按钮未折成竖排，控制台 0 条消息；现场 DHCP 覆盖卡显示逐消息源。应用相关 Go 测试、构建、vet，前端测试、类型检查及生产构建通过。
- `2026.11.01-mirror-discovery-r11` 已按应用更新流程发布，`current` 为 r11、`previous` 为 r10；源码提交 `df641e31`，发布包 SHA256 `85ee1afcea424ae07b92043fe26c0ef1d1b74b0584dd6e80b1e144da2f45babf`。PostgreSQL 214 项、ClickHouse 59 项候选迁移均与现场账本匹配，未执行新迁移。现场登记 `/opt/proxy-sentinel/config/discovery-handshake-scope-map.json`，SHA256 `d22d685556878957f17ef6b46e6921a7ce3b721db6f065744822165bd2c808d5`；它仅把同一 `ncu-184-router-pilot` 传感器的发现域 `bond0-passive-pilot` 与握手域 `bond0-router-minimal-overnight` 在 `10.202.0.0/16` 内显式对应，已与两份采集范围配置逐字段核验。控制面 systemd drop-in `zzzzzz-mirror-handshake-r11.conf` 指向该映射文件；回退应用时可移除该 drop-in 与映射，再重载并重启控制面。
- 握手侧车已有的 HTTP User-Agent、JA3 原文现可在发现设备详情按当前 IP 受限读取：只查询活动代次、同传感器映射范围、最近 11 分钟的索引和已核验归档原文，最多展示 12 条，保留标准事件号与观测时间，明确标成 IP 弱线索。列表仍只读 current 投影。现场详情接口实际请求返回 200，浏览器记录的该次请求约 98 毫秒；但所选 IP 暂无可展示样本，尚不能宣称 UA/JA3 现场非空覆盖。r11 的 390×844、1280×800、1440×900 现场截图与 DOM 探针再次通过：文档宽度分别等于 390、1280、1440，表格容器宽 336、982、1142 px，文字按钮未竖排，控制台 0 条消息。

**仍需如实保留的缺口：** 旧 TTL/握手侧车在新共享代次恢复后正追读已积累的原始文件；03:41 时两个 reader 均在逐批确认，握手 cursor 在 1.65 GB 的轮转原文中到约 79%，TTL cursor 也仍在轮转原文中，不能宣称这两路已追平或详情已有 UA/JA3 非空覆盖。原始日志保留、reader 活动、后续处理进度需继续观察。当前 Zeek 采集过滤器仅含 DHCP 67/68，Suricata EVE 当前仅有 DNS 与统计事件；握手侧车原文**已有 HTTP User-Agent 与 JA3 样本**，详情读取需要这些样本进入活动时间窗后再核验。现场未见 JA4、SMB native OS 或非 DHCP observed flow，页面不推断精确 OS 版本、开放端口或物理接入端口。NCU 身份同步本机 `/18082/readyz` 仍为 503，属于本次发现链路之外的现场遗留问题；其现行 binary 没有文档提及的 `--read-only=true` 参数，需另行核对该项现场约定，不将本次发现验收写成整站全部服务通过。

03:15 复核：TTL cursor 已到约 26%；握手源在 03:14 按日志轮转规则重命名为 `handshake.jsonl-20261101-031402`，旧 inode 和 1.6 GiB 原文仍保留，reader 按文件身份继续读取，尚未读完；轮转后的新文件不能作为旧 cursor 的进度分母。恢复后两条 reader 的最终确认错误数仍为 0。现场 Suricata 的 BPF 仅纳入 ARP、发现类多播和指定 UDP/VRRP，Zeek 的 BPF 仅纳入 DHCP；对 `bond0` 上 TCP 80/443/445 的短时只读抓包可见大量报文，未做资源与丢包验收前不能直接放开全量 TCP 捕获。

## 当前已落地

### 数据链路

- 新发现代次：`discovery-fresh-20261031T092000Z`；
- 采集范围文件：`/opt/proxy-sentinel/config/discovery-capture-scope-layered-r7.json`，有效期已延长到 `2026-12-31T00:00:00Z`；
- 被动协议：ARP、DHCP、DNS-SD、SSDP、LLDP；
- LLDP 现场 0 包；SNMP 被动开关暂时关闭，避免 scope mismatch；
- eventbus current、发现页、服务线索和 TTL/DHCP 被动信号已接入。

### 发现页

路径：`/devices?tab=discovery`。

已具备：

- 顶部概览卡片：发现设备、哑终端线索、本页服务线索、本页近期活跃；
- 终端类型图标；
- 地址/名称/MAC、终端类型、制造商/型号、操作系统线索、网络位置、发现依据、服务/端口、证据状态、最近观测、操作；
- 服务/端口来自 DNS-SD/SSDP 镜像公告，例如 `_airplay._tcp · 7386`、`_lyra-mdns._udp · 5353`；
- 设备详情展示厂商、型号、VLAN、网络域、传感器、TTL、DHCP 主机名/厂商类/请求选项、服务线索和证据历史；
- MAC OUI 厂商补全；
- 主机名类型/OS 线索。

### 当前已知边界

- 精确 OS 版本无法从镜像稳定得到，只能给 OS 家族线索；
- 接入交换机物理端口需要 LLDP/FDB/SNMP，当前镜像位置不可得；
- 服务端口只能看到公告或实际流量，不能证明开放/关闭；
- SNMP/NDM 事件不在镜像中；
- 当前页面部分字段是低置信度线索，前端必须保留“线索”标识。

## 代码入口

- 发现页：`frontend/src/pages/PassiveDiscoveryPanel.tsx`
- 发现查询：`internal/discovery/eventbus_query.go`
- 被动信号 API：`internal/controlplane/passive_signals.go`
- 镜像握手详情读取与采集域映射：`internal/store/discovery_handshake_clues.go`、`internal/controlplane/discovery_handshake_scope.go`；现场映射由 `PROXY_SENTINEL_DISCOVERY_HANDSHAKE_SCOPE_MAP` 指定，未配置时不返回跨域握手线索。
- 服务线索读取：`internal/store/discovery_services.go`
- 当前切流/清库说明：`docs/discovery-data-reset-20261031.md`
- 高性能流式架构：`docs/high-performance-streaming-architecture-20261030.md`
- 设备中心查询设计：`docs/device-center-storage-query-design.md`

## 下一步任务（按优先级）

> **2026-10-31 本地进展，尚未部署或现场验收。** 发现台账合并了终端类型/厂商和证据状态/观测时间列，固定右侧操作列；390、1280、1440 三视口的 mock 截图和 DOM 探针通过。被动信号接口按 MAC 与 VLAN 聚合 TTL、DHCP REQUEST 的 option 55/60 线索，增加 15 秒日志尾部快照缓存、观测时间与 Windows/Android 家族线索；跨来源冲突在页面标为“线索冲突”，服务公告按类型和端口去重并在详情显示观测时间。上述改动没有把 DHCP REQUEST 当作地址绑定。
>
> **仍待完成：** HTTP User-Agent、TLS JA3/JA4、SMB native OS 和 observed flow 端口尚未进入此台账。现有快照只覆盖日志尾部，不能代替逐消息 REQUEST 的持久化被动信号投影，也未测量现场识别覆盖率。坏段隔离告警及现场验收仍待处理。后续接入时须按标准事件与证据语义实现，不能将访问端口表述为开放端口。

> **2026-10-31 后续本地进展与现场只读基线。** 184 在核对时 Kafka 两个消费组积压均为 0，但 67,580 条活跃流式设备状态中有 2,155 条尚未进入 65,059 条的 current 台账；现场应用仍为 `2026.10.29-stream-retry-r16b`。本地新增按代次、结果版本推进的有界补入游标，每轮最多 200 行和 8 MiB，同事务写入台账与进度；尚未迁移或部署，不能把上述缺口称作已修复。采集范围有效期由 API 检查，提前 14 天在发现页提示；现场文件有效期至 `2026-12-31T00:00:00Z`，目前不会触发提醒。当前逐消息 DHCP 文件约 5.7 MiB，TTL 文件约 577 MiB，后者只读尾部明显不足以覆盖完整观测历史。对应持久化投影仍是下一项工作。

> **2026-10-31 本地续进展，仍未部署。** current shadow 的 fact 变化和自然过期改为每轮各最多 1000 行的复合游标，更新受影响设备后同事务推进，删除了每次 fact 变化触发的全表聚合与清理。发现页按本页 MAC 从活跃流式 DHCP 事实取最近的持久线索与事件号，和近期 REQUEST 日志合并；这只覆盖已进入流式事实的 DHCP 观测，逐消息 REQUEST 尚未正式持久化。Zeek 回放确认 option 61 的客户端标识类型和硬件地址、option 93 的**出现状态**可保留到 ACK 绑定和标准事件；当前 Zeek 解析器不提供 option 93 的架构值，页面不推断该值。改动涉及的 Go 测试、构建、vet、前端测试/类型检查/构建及三视口 mock 检查通过；本机 Zeek 8.2 的集群回放基线因未配置 cluster backend 失败，单机包回放 3 项通过。现场索引增长、性能和识别覆盖仍未验收。

> **坏段处理的本地实现，仍待现场验证。** 对确定性的流式 fact scope/device 冲突，发现 worker 会在隔离目录为原始 segment 建立硬链接和内容哈希审计记录，保留原任务为“未处理”并停止该链路；重启时看到隔离记录会暂停，避免继续重试同一坏段。采集覆盖页与只读健康脚本显示隔离数量和处理缺口。其他错误仍遵循原有重试与恢复策略。切流后旧代次文档按设备键有界清理；未部署，不能将现有现场坏段或旧代次残留视为已处理。

> **后续本地核对。** 隔离清单改为同步临时文件后原子发布，避免崩溃留下半份审计记录。流式状态分配结果版本时加事务锁；eventbus fact 改用事务有序的变化版本游标，避免并发事务逆序提交令 current 台账永久漏行。迁移会一次性为现有 fact 补齐版本，后续由触发器维护。被动 DHCP、TTL 按传感器及 VLAN 合并；HTTP User-Agent 与 TLS JA3/JA4 从已有设备信号事实按传感器、当前 IP 限量读取，带最近事件号与时间，仅作为 IP 弱线索。MAC 设备不会仅凭 IP 上的 UA 推断操作系统。上述新改动完成本地单元、类型检查、构建和三视口 mock 检查；仍未部署、未测现场查询延迟与覆盖率。[Zeek 8.2 的类型定义](https://docs.zeek.org/en/v8.2.2/scripts/base/init-bare.zeek.html)仅在 SMB1 会话中提供 native OS 字段，当前尚未接入采集与台账。

> **current 切流复核。** 流式文档更新不再重复读取该设备全部 eventbus facts；旧代次按批退役时先移除旧流式事实，再从仍有效的 eventbus facts 恢复，并在 Redis 中先失效后回填。常规 eventbus fact 变更仍会重读该设备事实，后续需要增量计数与事实映射改造，不能将这一点视为已满足有界事实处理。逐消息 DHCP REQUEST 持久化、observed flow 端口投影、现场覆盖率与索引增长测试仍未完成。

> **实际访问端口本地实现，待迁移与验收。** 新增按传感器、源 IP、协议、目标端口及 10 分钟窗口聚合的 ClickHouse 读模型，仅从新流量写入，保留 7 天；发现页只对当前地址读取最近两小时桶，标为“实际访问线索”，展示样本事件号与观测时间，明确不代表设备端口开放。读模型每个分组增加一份聚合写入，需在 184 验证实际增长和查询延迟；未回填的时间段不宣称覆盖。

> **服务公告归属复核。** 服务线索改按传感器与 MAC 成对读取和匹配，详情展示样本事件号与最近观测时间；仍从两小时 `normalized_events` 原表读取，需在现场测量请求成本，再决定是否建设独立公告投影。访问端口桶采用最大时间和对应样本事件，避免重试写入把次数虚增。

> **逐消息 DHCP 本地链路，待现场切源。** 受审计的 Zeek 文件流新增 `--zeek-dhcp-message` 入口，固定解析版本 `zeek-dhcp-message-v1`，沿用按文件代次、偏移及原文哈希确认的持久段。`device_dhcp_message.log` 的 REQUEST 形成 MAC 线索事实，保留 option 55/60/61 与 option 93 出现状态，但删除其请求地址作为当前绑定；ACK 只用明确分配地址形成绑定，OFFER 等消息只留标准事件、不进入设备事实；缺失或无效 MAC/IP 的消息也只保留原文与不可投影事件。现场切源须先停用旧 reader，使用 `stream-cancel` 预览与应用审计退役旧源，再用 `stream-prepare --zeek-dhcp-message` 确认固定起点与旧输入审计，最后以 `stream-run --zeek-dhcp-message` 启动；运行时拒绝两个 DHCP 文件源并行。2026-11-01 只读核对显示 184 的 `proxy-sentinel-ingest-stream-dhcp-layered-r8.service` 仍活动，使用 `zeek-dhcp-binding` 读取 `/opt/proxy-sentinel/data/zeek/logs/current/device_dhcp_binding.log`；尚未执行切源，也不能把本地测试称为现场覆盖。

### P0：修正发现页布局和空列

- 当前表格列较多，1440 视口下“最近观测/操作”容易互相挤压；
- 需要把操作列固定在右侧，或压缩列宽/合并列；
- 增加三视口检查：390×844、1280×800、1440×900；
- 不允许使用“未识别/未获取/未知/—”占位。

### P0：完善被动 OS 指纹

现有：

- 主机名前缀；
- MAC OUI；
- TTL；
- DHCP vendor class/requested options（API 直接读日志尾部）。

下一步：

1. 把 `device_dhcp_message.log` 正式纳入数据链路，按 MAC/IP 聚合并缓存，不要每页请求重复读大文件；
2. 解析 DHCP option 55、60、61、93；
3. 增加 HTTP User-Agent、TLS JA3/JA4、SMB native OS 信号；
4. 输出 `os_family`、`confidence`、`evidence`，不要输出确定版本；
5. 多个信号冲突时显示冲突，不要取第一条。

### P1：服务端口/服务名称

- 已从 DNS-SD/SSDP payload 提取；
- 增加 observed flow 的 `dst_port` 聚合，区分“服务公告”和“实际访问”；
- 输出证据来源和时间，避免把访问端口当成开放端口；
- 页面按服务类型/端口去重，避免一个服务实例刷多行。

### P1：接入位置

- 当前只有 VLAN/网络域/传感器；
- 若后续能把镜像点放到接入交换机，可补 LLDP/FDB；
- 当前不要用 VLAN 推测物理端口。

### P2：采集可靠性

- 发现 segment 曾因 fact scope mismatch 阻塞，坏段已移到 `/var/lib/proxy-sentinel/discovery-quarantine-20261031`；
- 为同类坏段增加自动隔离和告警，不要无限重试；
- 监控 `discovery_device_current_shadow` 最新时间和 eventbus lag；
- 采集范围有效期到期前自动提醒；
- 不在采集路径里做无界文件读取。

### P2：页面验收

- 发现页总数与 current 表口径对齐；
- 服务线索、OS 线索、类型线索在详情可追溯；
- 页面无 console/page error；
- 390 宽度使用卡片布局，不出现表格爆框。

## 明确不做

- 不主动扫描全网；
- 不猜 SNMP community；
- 不伪造 OS/端口/接入位置；
- 不把线索写成确定结论；
- 不删除唯一原文或未核验归档。

## 验证命令

后端：

```bash
go test ./internal/controlplane ./internal/discovery ./internal/store
go build ./cmd/proxy-sentinel
go build ./cmd/event-bus-current-shadow
```

前端：

```bash
cd frontend
pnpm test --run
pnpm typecheck
pnpm build
```

现场只读核对：

```bash
/opt/proxy-sentinel/scripts/eventbus-184-health.sh
```

页面：

```text
http://222.204.3.184:8088/devices?tab=discovery
```

## 最近提交

```text
85eb38c8 接入被动TTL与DHCP信号
b4cd6e66 增加被动服务端口列并修复采集范围过期
25f8268f 增加镜像流量被动服务线索
00bc6954 优化SNMP网关候选排序
3a26cae6 增加从发现网段选择SNMP候选
```
