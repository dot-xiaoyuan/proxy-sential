# 当前工作（2026-11-18，北京时间）

本页记录当前现场版本、数据边界、未完成缺口和下一步。现场瞬时状态以再次只读检查为准；已结束的试验和发布细节保留在 Git 历史。

## 184 发布与验收

- **2026-11-18 16:23 投影减写已切到发现进程，整包重启没有做。** `current` 为 `2026.11.18-dbb58e4c`（源码 `dbb58e4c1228ce9a39c11dbc05f36838855cf127`，包 SHA256 `35f6d96e80da4b3b1f05ce8640ca8d0c3c5c5b01b62fbebe870112bb8bc3fa75`），`previous` 为 `2026.11.16-5b23c764`。PostgreSQL 252 条、ClickHouse 75 条候选迁移与账本校验一致。全量 `upgrade-application.sh` 因风险物化进程没有稳定主进程号而在切换前退出，16:05 的一次全量重启又被就绪检查退回。16:23 只重启了 `proxy-sentinel-discovery`，进程 `3913506` 的可执行文件位于新目录，启动后继续完成 `write_facts` 投影；`/readyz=200`，NCU `18082/readyz=200`。控制面、入库、身份和被动发现仍是已加载的 `5b23c764` 程序。风险物化启动项使用 `current`，它下次自行退出再拉起时会带上新程序。现场配置未改，旧发布目录未清理。这是观察投影减写的短时混版，不是单版本验收。
- **2026-11-18 18:50 只读复核：减写已见效，投影仍追不上采集。** 进程仍是混版：`discovery`（16:23 起）、`flow-syn-signal`（18:45 崩溃重启后）、`risk-materializer`（18:48 崩溃重启后）运行 `2026.11.18-dbb58e4c`，控制面、入库、身份、被动发现仍是 `5b23c764`；`/readyz=200`（0.8 秒），NCU `18082/readyz=200`。发现投影每 30 秒窗口的设备当前态写入 38–62 行、事实写入 423–660 行，10 分钟窗口为 1,333/12,839，约为改动前同口径的 1/10（11-17 10:09–10:13 为 3,860/3,866）。风险脏队列 37,509（10:11）→16,071（16:49）→10,699（18:51），风险物化每轮 `claims=8 committed=8`。但投影队列从 29 段（16:24）持续涨到 656 段（18:49），约 +4.3 段/分钟；采集约 10–14 段/分钟、投影约 10 段/分钟，单段平均 4.6 秒（`commit` 1.71 秒、`begin_tx` 1.93 秒、`publish_state` 1.02 秒），17:44 出现一次 30 秒 `projection.write` 超时失败。PG 采样仍有 11–25 个后端阻塞在 `LWLock:WALWrite`。这是混版短时观察，不构成单版本验收，也不能据此认定投影瓶颈已经解决。
- 最近一次全量应用更新的源码与发布目录为 `2026.11.16-5b23c764`，源码提交 `5b23c764dcd9b22fa9ff7a714784c707713304a4`，发布包 SHA256 为 `171569a709f7cc6cf362ffc609077c04c8b1d48571fc0dcfedd1bd15c79dd135`。2026-11-17 约 10:06 通过应用更新流程切换；PG 252 条、ClickHouse 75 条已应用迁移及校验值一致。受影响服务进程与 systemd 生效路径已核对，切换时 `/readyz` 通过。路由读源生效环境为 `DISCOVERY_CURRENT_SOURCE=stream` 与 `ROUTER_ASSET_CURRENT_SOURCE=stream`。
- 当前 `previous=2026.11.16-fa046d27` 仅供问题未验收期间回退；尚未按单版本约定清理。登录态页面验收按用户要求暂缓，本地前端测试、类型检查、构建与三视口检查不能替代现场页面验收。一次健康检查也不构成状态接口 P95/P99 验收。
- 处置动作与上报记录继续是“仅记录、未执行”；不实际发送通知或执行处置。

## 当前数据问题与原因

- **2026-11-19 10:10 只读复核：发现投影完全停摆，共享判定零命中。** 发现投影队列自 06:08 起冻结在 7,934 段、durable backlog 7,935 段，采集已因 `recovery_backlog`（low_water 3,967）暂停；卡点是设备 `642047043d5b372f85a22887b2a96b9b` 的事实计数漂移（存储 `evidence_count=89`，最新 scope 实际 90 行），`buildStreamDiscoveryStateSummary` 的 fail-closed 校验使该段永远无法投影，单线程有序车道随之停摆，且没有可用修复入口。`risk-materializer` 重启 282 次，仍是 `renew incremental risk window lease: timeout`。load 降到 24.6 是采集停下的结果，不是优化效果。
- 同一时点共享识别没有产出：`proxy-sentinel-control-plane-eventbus` 09:00–10:03 共 19,129 条 `shared_observation_decision`，其中 18,724 `expired`、405 `insufficient`、0 `matched`；时延 914 条 <180 秒、12,704 条 180–300 秒、4,325 条 600–1,800 秒，而 `shared-access-observe.json` 的 `freshness_seconds=180`。11-18 21:00–21:30 同为全 `expired`，不是今晚才出现。
- 共享强锚点缺失：ClickHouse 中 `ieee1905_client_association` 最后一条为 11-17 02:32（UTC），运行中的 `discovery-collection-stream-dnssd-b3.json` 把 `ieee1905_client_association`、`dhcp`、`ndp` 都设为 `false`，只开 `dns_sd/ssdp/arp/lldp`。`NewObservationDecision` 要求 `StrongAnchor` 非空才可能 `matched`，因此当前配置下共享命中不可能出现。`packet-sidecar` 自 11-17 02:33 起只产出 `ttl`，`ssdp/arp/ndp` 改由发现进程以 `source=passive` 写入，并在今日 05:20 后中断。`router_assessments` 11,206 行全部过期（live=0，最后 `last_seen` 为 11-16 19:06 UTC）。磁盘使用 93%、剩余 120 GB。
- 路由资产已改读稀疏 `stream_discovery_network_state`，以协议网关线索展示，不把路由角色候选当成确认资产。10:00 左右同源有 35 条有效网关线索；10:16 只读检查仅剩 48 条已过期网关线索、当前有效 0 条。默认列表 SQL 在当前无命中时约 0.3 毫秒，因此此刻空白不是慢查询或旧影子读源。`ttl.jsonl` 在 10:17 仍持续收到 SSDP，PG 网关最新观测却停在 09:40，10 分钟租约已自然过期。报文源读取及发现投影滞后约 38 分钟；不能延长租约或把过期线索伪装成当前路由器。
- 10:19 报文源 `ttl.jsonl` 文件约 1.036 GB、游标约 675 MB，未读约 361 MB；多段 journal 已完成 archive 但 projection 待完成。10:21 的短窗输入约 401 KB/s、游标仅约 65 KB/s，未读增至约 370 MB。最近尾部约 4 MB 样本以不同 IP/MAC 的 NDP 为主，另有 SSDP，不能把整条源当成单个重复热点。被动发现 10:09–10:13 的连续窗口接纳 64 段、7,630 标准事件，投影 43 段、3,873 事件，PG 事实与设备状态分别写 3,866、3,860 行，持久待办 889→908 段。最近 20 个未完成段的 2,206 条事件中，ARP 2,116、DNS-SD 67、SSDP 23；此协议分布只代表该样本。普通发现当前态写入是可量化的负担，但不能据此把所有 PG `WALWrite` 归于发现链路。
- DHCP 历史源的一个已确认原文段已按唯一正文、哈希和落点修复，读指针随后从旧代 34 推进至代 50；10:11 仍约 1.64 GB 未读。握手源保护轮转链同刻仍约 4.48 GB 未读，报文源另约 326 MB。风险脏队列同刻约 37,509 项，部分 `commit affected risk facts` 与租约续期仍因 PG 等待超时。身份接收曾在 5 秒预算内多次 503，阶段日志明确为 `identity_inbox_failed stage=accept`；Redis 仍重试，不把失败记作已接收。各来源积压独立，不能称为单一 Redpanda 积压。
- PG 抽样仍有多条 `WALWrite`，并有数据读取及长时自动清理；这些等待会随瞬时负载变化。ClickHouse 正在执行必要保留规则的 `stream_event_search` 大块 TTL 重写，磁盘 IO 也在竞争。一次受控诊断日志清理仅移除已过期且无活动引用的约 30.8 GB `system.text_log` 块；没有清空 `query_log` 或必要原文。`/readyz` 可短时返回 200，过去亦曾间歇超时，尚无持续延迟验收。

- **2026-11-18 18:50 只读复核的未解决项。** 风险物化累计重启 163 次，失败原因是 `renew incremental risk window lease: timeout: context deadline exceeded`；`flow-syn-signal` 重启 18 次，报 `invalid flow SYN ring block header`，并伴随每批 1,105–24,810 的 `kernel_drops`，TCP SYN 采集有丢包。DHCP 流车道自 10:00 起卡在同一段 `90d3bfe2…` 的 `archive stage=reconcile`，累计 479 次重试，同期 Zeek DHCP 日志仍增长到 31 MB。`stream_discovery_network_state` 50 行全部过期、最后更新停在 11-17 03:47（UTC），路由资产仍为空窗。发现设备当前态存活 2,402 行、10 分钟内有更新的只有 1,333 行，当前态依靠每秒 100 条的过期车道重建，需持续观察是否掉设备。自动清理落后：`stream_discovery_receipts_202611` 死元组 5.04M、上次自动清理为 11-11，`stream_discovery_facts` 的 VACUUM 已运行 41 分钟未结束。根盘使用 92%、剩余 138 GB（16:31 为 115 GB），相对 100 GiB 最小保留线只剩约 38 GB 余量。

## 阶段 0 执行记录（2026-11-19）

- **10:22 已按用户授权停掉发现类服务**：`proxy-sentinel-discovery`、`proxy-sentinel-inventory`、`proxy-sentinel-inventory-backfill`、`proxy-sentinel-recognition-minute-shadow` 全部 `disable --now`，原始启停状态记录在 `/opt/proxy-sentinel/data/ops/20261119-stage0-stop.json`。保留 `recognition-materializer`（同一进程负责共享设备画像）、`passive-discovery`、`router-prober`、读模型与控制面。停服后 `shared_behavior_observations`、`stream_discovery_facts`、`stream_discovery_device_state`、`stream_discovery_changes`、`stream_discovery_receipts_202611` 的 60 秒写入增量均为 0，`/readyz` 在无 IO 风暴时返回 200。
- **积压按审计口径取消，不计作完成**：7,935 段、430,552,709 字节全部导出到 `/opt/proxy-sentinel/data/audit-cancelled-source/20261119T021840Z-passive-projection-backlog.jsonl`，含 `segment_id`、`content_sha256`、字节数、来源文件与偏移、`accepted_at`、取消原因 `passive_projection_lane_deadlocked_device_fact_count_drift`，清单哈希 `8c73b40cbf5e73d8045b8732740ee0087543724c328b250ce74e5e451b9857ad`；原始 `.segment` 仍保留在 journal 目录，未删除唯一原文。停服前后 journal 段数均为 7,935，增量审计为空。
- **已修两处健壮性缺陷（代码，未发布）**：设备事实计数漂移不再阻塞整条有序投影车道，完整读取时以实际事实数为准并把漂移写入日志（`internal/discovery/stream_state.go`），新增回归测试 `internal/discovery/stream_state_count_drift_test.go`；风险物化租约续期遇到瞬时超时改为有界重试（最多 8 次、单次 8 秒）后才退出（`cmd/proxy-sentinel/main.go`）。`go test ./internal/discovery`、`go build ./...`、`go vet` 均通过。
- **待解决且无法用配置绕过**：`ttl.jsonl` 中确有新的 `ieee1905_topology`/`ssdp` 事件（样本 `control-1a3c2b36…` 时间 2026-11-19T02:28:00Z），但 ClickHouse `stream_event_search` 的 `packet-sidecar` 源在 11-17 02:33 之后只有 `ttl`，同期 2 小时 263,820 条全部是 `ttl`，说明设备信号入库路径丢弃了非 `ttl` 记录；这是共享强锚点缺失的直接原因，属于代码层选择逻辑，需定位后修复并补回放测试。停止发现期间 `shared_observation_decision` 仍以 `expired` 为主，判定时延中位约 200–500 秒，超过 180 秒新鲜度窗口。

## 阶段 1 执行记录（2026-11-19）

- **共享强锚点丢在一条被单段卡死的流车道上，不是协议过滤**。报文流车道 `proxy-sentinel-ingest-stream-packet-layered-r7` 自 11-17 08:19 起卡在同一段 `939607a9…`（内含 760 ttl、238 `ieee1905_topology`、2 `ieee1905_client_association`），archive 每 3 秒超时后无限重试，累计 9,906 次。`stream-run` 单次存储预算默认 3 秒且上限也是 3 秒，ClickHouse 在保留规则合并期间单次写入常超 3 秒，于是一个段就把整条有序车道永久钉住，控制面自此只能看到 `packet-sidecar` 的 `ttl`。
- **已发布应用更新 `2026.11.19-89853113`**（仅后端二进制，前端资产未变，目录用硬链接复制，`bin/proxy-sentinel` sha256 `64533882f1a75b1606c6e3e4ecae0a15c6a98074736fc9fcee2b79e55329a150`）：`current=2026.11.19-89853113`，`previous=2026.11.18-dbb58e4c`，无新增迁移。含三项修复：设备计数漂移自愈、风险物化租约有界重试、`ingest stream-run` 单次存储预算默认 15 秒且上限放宽到 120 秒。
- **现场参数与修复**：报文流车道与 DHCP 流车道各加 drop-in `--store-timeout 45s`；用 `stream-repair --settled-scoped --lane archive` 按作用域行证明确认了卡死段（1,000 事件）及其后续 1 段，车道已越过卡点。`risk-materializer` 已换新二进制并重启，重启计数归零，持续提交 features/evidence/snapshots。
- **当前进展**：报文车道正在回放 43 个轮转文件（共 4.3 GB）的历史积压，ClickHouse 中 `packet-sidecar` 的非 `ttl` 协议已从 11-17 02:33 恢复到 11-17 02:34 并继续推进；`/readyz=200`（12 毫秒）。回放追平前共享判定仍只能看到 11-17 之前的新鲜度，`matched` 还不会出现；判定时延仍超过 180 秒新鲜度窗口，属于阶段 2 的范围。

- **2026-11-19 12:20 走"提高入库吞吐"路线（A）**。发布 `2026.11.19-8e8c87e6`（`previous=2026.11.19-89853113`）：归档/搜索车道工作数上限 2→8，新增 `--archive-workers/--search-workers`；ClickHouse 写入启用 `async_insert_busy_timeout_ms=2000` 与 32 MiB 合并窗口，减少每次段提交新建 part。handshake 与 flow-syn 车道改为 24 段待办、45 秒单次预算、4+4 工作线程。实测 handshake 滞后自 12:13 的 99 分钟收敛到 12:27 的 73.9 分钟（约 1.4 倍追赶速度），flow-syn 与身份均为亚分钟级；`stream_event_search` 上 46.59 GiB 合并已到 100%，活跃 part 22 个（此前持续翻倍）。入库速率已高于采集速率，但共享判定仍全为 `expired`：报文车道按用户要求停用，`ieee1905` 无新鲜数据，且 handshake 证据追平前窗口必然过期。

## 2026-11-20 执行计划与落地（路由器 + 共享）

### 目标与必要链路

184 只验收两项目标：**识别路由器（网络线索）**、**识别共享行为（强锚点确认）**。

| 目标 | 必需信号 | 采集 | 入库 | 消费者 | 验收口径 |
| --- | --- | --- | --- | --- | --- |
| 共享命中 | `ieee1905_client_association`/`snapshot`；handshake 佐证；ttl 弱线索；身份 | device-signal packet/handshake | **packet stream-run** + handshake stream-run | shared_observation worker | 出现 `matched`；`latency_ms` 多数 <180s |
| 路由线索 | ssdp / ieee1905_topology / ndp / lldp / dhcp 网关事实 | device-signal + Zeek DHCP | packet + dhcp stream-run → **窄网络投影** | `stream_discovery_network_state` | live gateway/router clue >0 |
| 已追平佐证 | handshake、flow-syn | 对应 sidecar | 对应 stream-run | 共享弱信号 | 未读近 0，保持即可 |

硬条件：`NewObservationDecision` 要求 `StrongAnchor` 非空；现场 `freshness_seconds=180`。不移动 epoch、不把取消积压计作完成、不造数。

### 问题待办

| ID | 问题 | 优先级 | 阶段 |
| --- | --- | --- | --- |
| P1 | packet stream-run 自 11-19 12:05 停用 | P0 | A |
| P2 | CH 无新鲜 ieee1905 → 共享 matched=0 | P0 | A |
| P3 | packet 当前未读约 0.7 GiB（另有轮转 `.1`） | P0 | A |
| P4 | 约 19% 判定 ≥180s → expired；PG `WALWrite` | P1 | A 观察 / 必要时调优 |
| P5 | discovery/inventory 停服 → 路由空窗 | P1 | B |
| P6 | 无安全的 shared/network-only 窄投影配置 | P1 | B（需代码） |
| P7 | 旧 `ingest run` 与 stream-run 双读 `ttl.jsonl` | P2 | C |
| P8 | 根盘 95%、剩约 92–94G | P2 | C |
| P9 | DHCP 游标跨轮转 | P2 | C 观察 |
| P10 | inventory stale / 身份 delayed | P2 | C |

### 阶段划分

**阶段 A（今天落地）— 恢复强锚点入库**

1. 记录启停前水位：packet/handshake 未读、CH 各 protocol 最新 `observed_at`、共享 decision 分布、磁盘/load、`/readyz`。
2. 为 packet unit 对齐握手车道追赶参数：`--store-timeout 45s --archive-workers 4 --search-workers 4 --max-pending-segments 24`（原仅 45s/8 pending；`Restart=no` 保持，便于异常即停）。
3. `systemctl start proxy-sentinel-ingest-stream-packet-layered-r7`，连续观察：进程存活、未读净斜率、CH 是否出现当日 `ieee1905_*`/`ssdp`/`ndp`、段提交是否再被单段钉死。
4. 追平到近实时后，统计 30–60 分钟 `shared_observation_decision`：`matched`/`insufficient`/`expired` 与 `latency_ms` 分位；handshake 未读保持近 0。
5. 失败回退：`systemctl stop` 该 unit，保留 journal/原文，记录卡点段与错误；不改 freshness、不跳游标。

**阶段 B — 窄路由线索（A 验收后再动）**

1. 不恢复全量 discovery/inventory 热写。
2. 优先启用/补齐仅写 `stream_discovery_network_state` 的窄路径（已有 network backfill/state 代码则现场验证；缺配置则补 `shared_only`/network clue 职责标记与回归测试后发布）。
3. 验收：network_state live>0、路由页非空窗、PG WAL 不明显回到停服前风暴。

**阶段 C — 稳态**

1. 明确 stream-run 为报文权威路径；收敛旧 `ingest run` 对同文件的搜索写入，避免“只有 ttl”错觉。
2. 容量：清无引用过期日志块、控制 CH part；根盘留出 >100GiB 余量，不删唯一原文/案件证据。
3. 保持单段超时有界、计数漂移自愈、风险租约有界重试。

### 阶段 A 执行记录（2026-11-20）

- **13:43 启停前只读水位**：版本 `2026.11.19-8e8c87e6`；packet inactive（Restart=no）；packet 未读约 **707 MiB**、handshake 未读 0；近 2 小时 CH `packet-sidecar` 仅 `ttl`；根盘 95%/剩 92G；load ~19。
- **13:44 已启动 packet stream-run**：drop-in 先为 `--store-timeout 45s --archive-workers 4 --search-workers 4 --max-pending-segments 24`；随后提到 workers **8+8**、pending **32**。采集端 `ttl.jsonl` 游标附近事件时间约为当日 `04:02Z`（落后实时约 1.5–2h），尾部持续有 `ieee1905_*`/`ssdp`/`ndp`。
- **卡点**：有序投影车道钉在旧段 `891ea2fc…`（`accepted_at=11-19T04:05Z`，`needs_projection=true`）。`write_facts` 常耗时 ~119s，恢复投影预算仅 120s，于是 `projection reconcile` 每 2 分钟超时重试；pending 顶满后源游标净推进为 0，未读继续涨。search/archive 可前进，但不能释放段。`event_key_scheme_mismatch` 收据仍 `projected=1000`，不是“未投影”，是超时未 ACK。
- **14:03 已发布 `2026.11.20-03eb8c70`**（`previous=2026.11.19-8e8c87e6`）：恢复投影超时 5m；发布前先把 18 个混版进程对齐到旧 `current`，并把 `service-expectations.json` 中 discovery 改为 `stopped`（与阶段0一致）。`/readyz=200`。卡段 `891ea2fc` 随后释放，投影可在 ~1–2 分钟/段推进。
- **14:10 只读发现更严重卡点（出生代恢复读错）**：journal 段 `ab78fc9a…`（offset 247093081–247865270，`accepted_at` 今日）内嵌 1000 条事件全是 **`2026-11-17T03:06:30Z` 的 ndp**；同偏移在 `ttl.jsonl.1` 上实际是今日 `04:04Z` 的 ttl/ieee1905。段 `raw_sha256` 与文件切片哈希不一致。CH 中 **没有任何** `observed_at>=2026-11-20` 的 packet-sidecar 非 ttl 行。轮转发生在约 06:07Z，随后 catch-up 经 birth/recovery 写入了错误代际正文。
- **14:12 已停止 packet unit**，避免继续写入错代数据。`stream-cancel` 因 birth `file_id` 与轮转后尾校验无法锚定、解码预算耗尽而失败；改为保留旧 journal，另做审计清单。
- **14:22 `stream-prepare` 新鲜切入**：epoch `packet-fresh-20261120T062000Z`，`replace-closed-epoch=packet-birth-20261111T022159Z`，`cancel-id=packet-birth-wrong-generation-rehydrate-20261120`，`start_offset=121802597`（当时文件尾），丢弃记录 157,526/121,802,597 字节（审计取消、不计完成）；pending 段清单 `.../20261120T062000Z-packet-birth-pending-segments.jsonl` 哈希 `a8ad5ccf…`。unit 改指向新 journal，recovery 目录换新空目录。
- **14:24 验收（只读）**：CH 已出现当日 `observed_at` 的 `ieee1905_topology`/`ssdp`/`ndp`；14:25 起有当日 `ieee1905_client_association`（至少 3 条）。共享判定仍以 `expired`/`insufficient` 为主、`matched=0`，时延中位仍常 >180s；packet 未读约数 MiB、pending 段仍高，需继续追平后观察 matched。
- **14:28 投影仍慢于采集**：新鲜 epoch 上单段 `write_facts` 约 84 秒，pending 顶满，未读从数 MiB 涨到约 18 MiB。活跃写入落在 `stream_discovery_device_state`。`stream_discovery_network_state` 仍是旧 epoch `packet-birth-20261111T022159Z` 的 50 行过期网关，没有新鲜路由线索。
- **窄投影**：packet-sidecar 的新 `ndp`/`arp`/`ttl`/`hop_limit` 不再进入发现热路径，仍进 ClickHouse 正文。已经编成 `stream4-` 的段保持原收据子集，邻居事实不再写设备当前态；段内尚未编号的 `ieee1905_topology` 留到下一段再投影，避免改变已提交段哈希。新捕获的拓扑和客户端快照适配为接入点线索。`shared_only` 仍拒绝确认。
- **14:39 发布回退**：`2026.11.20-25755dc6` 曾切到 current，packet 在投影段 `b7a3301f…` 上报内容冲突后退出；升级脚本已把 current 恢复为 `2026.11.20-03eb8c70` 并核对进程。该候选目录仍留在磁盘，不是 current。
- **14:44 已发布 `2026.11.20-be34e6d2`**（previous=`2026.11.20-03eb8c70`）。packet 保持 active，发布后没有新的源内容冲突。已编号旧段仍整段出收据，新段里 1000 条事件只投影几十到几百条路由线索；`write_facts` 从约 84 秒降到数秒。`stream_discovery_network_state` 新鲜 epoch 现有 24 行（1 条 gateway clue，23 条已过期，`type_last_seen` 仍停在 06:25Z），要等游标追到近实时后才会保持有效。阶段 C 未开始。

## 数据边界与待办

- 固定来源 epoch：被动发现 `discovery-fresh-20261031T092000Z`，报文 `packet-birth-20261111T022159Z`，握手 `handshake-birth-20261111T022159Z`，TCP SYN `flow-syn-birth-20261113T104500Z`；身份派生新起点 `2026-10-29T05:11:29Z`。不移动起点，不把旧段或取消任务计作完成。11 月 12 日约七小时无 PCAP 窗口及既有套接字丢包仍是未恢复证据缺口。Redpanda 仍是影子链路。
- 用户已确认目标职责：184 保留共享识别与路由线索，204 负责自己镜像范围内的普通设备发现；两边采集范围独立，184 普通设备不转发到 204。204 现场使用另一镜像口和采集身份，当前发现物化仍有超时、硬件证据超过单次 128 条的未完成评估，不能把它视为 184 原文副本或宣称其数据全量正常。
- 当前没有安全的“184 停普通发现设备、仅保留共享/路由投影”配置。停止 discovery worker 会停止采集或必要投影；路由资产读取网络稀疏态和设备当前态，部分共享线索读取 DHCP 事实和当前态。共享档案的弱网络角色提示仍读取旧普通发现表，切换前必须改读窄网络事实或明确显示为历史。可实施的减载边界是保留 journal、ClickHouse 权威正文、收据与共享需要的地址/网关事实，将普通设备当前态的重复更新从 184 热路径分离；需新代码、固定水位对账和回放，不能通过停服务或跳 ACK 实现。
- 先修复报文源投影滞后与路由空窗，核对源游标、各 journal lane、PG 等待及持续输入净斜率。身份接收重复进度初始化减写、普通 NDP 无效风险特征/唤醒减写和职责标记兼容读者均已完成代码验证，尚未发布；两个真实 PG 身份集成测试因本机没有隔离数据库而未执行。职责标记空值保持旧段完整投影，`shared_only` 在新 writer 和固定 cutover 完成前明确拒绝，不能把未投影段计作完成。报文源现已启用 stream4/manifest 减写，单纯调高待处理段上限只会增加缓冲，不会增加唯一的有序投影工作线程。按同一固定时间窗记录 ClickHouse 确认、PG 行写、真实状态变化、WAL、ClickHouse 合并、积压和未解释缺口，再分阶段启用窄投影。现场仅用真实输入，不造数压测。
- 用户选择只用现有资源。必要正文早期粗估约 2.45 GB/日、一年约 893 GB，尚未计索引、journal、WAL、合并和单机故障保护；11 月 17 日 10:40 左右根盘剩余约 144 GiB，不足以承诺一年保留。不得缩短约定保留期、删除唯一原文或案件证据以掩盖容量缺口。旧程序目录只在验收及活动引用核对后按单版本约定清理。
