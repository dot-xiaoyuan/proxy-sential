# 184 现场存储与查询问题汇总分析（2026-10-15，只读定位）

> 范围：`root@222.204.3.184`，现场版本 `2026.10.15-ingestgate1`。全程只读；12:08 按用户要求停止全部应用服务，停前状态见 `/opt/proxy-sentinel/ops/service-state-before-stop-20261015-120747.txt`。
> PG 统计从 2026-10-14 14:18 UTC（PG 重启）开始累计，约 13.5 小时。
> 完成度：身份收件箱、PG 全局与主机、读模型与 ClickHouse、控制面查询路径、设备库存投影、身份历史物化、摄入与识别，七个方向全部深挖完成。标「推测」的条目是证据不完整的部分。
> 注意：pg_stat 的 n_live_tup 在重启后失真，本文的行数以实际计数为准，例如 device_signal_events 304 万行、device_address_leases 76 万行、identity_full_snapshots 450 行。

## 一、总体结论

数据量并不大：认证增量峰值约 3.4 万条/小时，原始事件约 8 GB/天。系统失速的原因是**几处设计缺陷把少量输入放大成单块机械盘承受不了的随机 IO 和刷盘次数**，再通过超时、重试和全量重建形成正反馈：

```
小批 / 高频提交 ─┐
全量重建 / 代际 ─┼─> PG 写放大（13.5h：WAL 56GB，检查点写回 65GB，整库只有 47GB）─┐
派生表扇出    ─┘                                                         ├─> HDD 饱和（util 98%，r_await ≈100ms）
CH 回扫 / 合并 ──> 每天读数 TB、合并读 1.4 TB ──────────────────────────────┘          │
                                                                                       v
        固定短超时（2s / 1s）──> 回滚重做 ──> 更多写入 <── 批次缩小、固定开销占主导 <── 单次往返变慢
        同步等待发布超时 ──> 整份快照重传 ──> 又一次全量重建
```

硬件前提：PostgreSQL、ClickHouse、dpi 的 ES/Mongo/Redis 共用一块 7200 转 HDD（Seagate ST2000NM000B），PG 只有 12GB 共享缓存。dpi 的 Redis 历史上累计写盘约 123TB，10-09 起已停止写盘，不是本次成因。

## 二、问题清单（按缺陷类型聚合）

### A. 全量重建代替增量更新（违反「增量更新」）

| # | 问题 | 证据 | 代码位置 |
|---|---|---|---|
| A1 | 每份 NCU 全量快照都整代重建 `identity_current_addresses`（约 3.7 万行），再 GROUP BY 生成两张引用表 | 现场同时存有 47 代、约 131 万行，有效的只有 1 代；同一快照 `12ffbb…` 被构建 11 次 | `internal/store/identity_calibration.go:18-109` |
| A2 | 旧代际清理每轮每表 1000 行、事务 1 秒，基本无法完成 | PG 日志 6 小时内被取消 2,196 次 | `internal/store/identity_calibration.go:260` |
| A3 | 把原始全量快照文档当作在线查询的数据源：策略类读取每次把 7 天内**全部 450 份**快照（压缩后每份约 5.6MB，合计约 2.5GB）逐份反序列化，再和 118 万行观测在内存里对账 | 实际 450 行（统计里的 51 行已过期）；TOAST 读取约 24GB（命中 251 万次、从磁盘读 48 万次）。调用方有十余个：策略、动作、白名单、风险校验、proxy 事件详情等 | `identity_reconciliation.go:199`（`ListPolicySessions`）；另有 `identity_calibration.go:208`、`account_projection.go:33`、`inventory_snapshot_projection.go:89-97`（每次重试都解开整份文档，14 小时内重试 201 次） |
| A4 | 库存「关系聚合」每次都对该关系的全部历史重新求 min/max；每次重新登录会生成一个新的 origin_key，于是新增一行 contribution | contributions 有 2,300 万行、13GB，只对应 8.1 万个终端；账号 090077 的一个关系就有 7,712 行；deltas 插入 512 万、删除 634 万（worker 主体代码**待深挖**） | `inventory_projection_incremental.go:334` |
| A6 | 账号标签按账号整体重算 7 天会话，NOT EXISTS 按每条会话行求值，复杂度 O(n²) | 公共账号 090077 在 7 天内有 23,725 条会话、只对应 5 个 MAC，约 1.1 亿次索引检查，每次都超过 15 秒超时；已失败 1,549 次；该车道积压 7,276 个账号；PG 日志中被取消 1,039 次的就是这条 | `account_assessments.go:119-133` |
| A5 | CH 物化里存在全窗口重算 | shared behavior 每 30 秒重算 15 分钟窗口，同一窗口约算 10 次 | `internal/store/shared_behavior_materializer.go:70`、`recognition_materializer.go:206-224` |

### A'. 设备库存投影（已深挖）

| # | 问题 | 证据 | 代码位置 |
|---|---|---|---|
| P1 | **快照全量重放**：每份快照的事件都是新 event_id，`record_id=sha256(source,event_id)` 无法去重。一份快照大约扇出 4.6~5.4 万条 snapshot_facts，每条最多再扇出 3 条 contribution 和 1 条 delta | 450 份快照中 355 份未处理；每次只应用 100 个事件、间隔至少 1 秒，而快照每约 3 分钟到一份 | `inventory_snapshot_projection.go`、`account_projection.go:62+` |
| P2 | **逐行、逐 origin 往返处理**：每个 origin 依次查 5 段 UNION 视图、整组删除、逐行插入、重建 timer；每个关系做一次全历史聚合，ip 关系再删除重插 ip_points；每设备至少写 jobs 4 次。一批 500 个 origin 有数千条语句，超过 30 秒就整批回滚 | 吞吐约 300 设备/分钟 | `inventory_projection_incremental.go:36-136,314,329-351,360-386`；`inventory_projection.go:118-120,298,322` |
| P3 | **认领排序导致饥饿**：`(processed_generation>0) DESC` 把处理不完的热点设备排到队尾 | 45 个设备中位等待 38.7 小时；网关 MAC `c4:07:78:08:20:02` 积压 55.8 万条 delta（有 86.7 万条 ARP、7.9 万个 IP），一个设备占全部 delta 的 10% 以上 | `inventory_projection.go:298` |
| P4 | **jobs 热行锁被长事务持有**：触发器在身份摄入事务里 upsert jobs，锁到提交才释放（注释里记录过单批 49 秒）；快照投影一个事务 upsert 约 3.7 万个会话；快照路径 `lock_timeout=100ms` 失败后返回 `false,nil`，**静默跳过、不报错** | 锁失败每小时 181~1,702 次 | `identity_batch_write.go:820`、`inventory_snapshot_projection.go:200-215` |
| P5 | **触发器回归，撤销与更正丢失**：迁移 122 删掉了 111 中「端点变更时为旧端点补写 D 型 delta」的分支，旧端点的 contributions 永远不会被撤销 | 现场函数体已证实；`old_payload` 列恒为空 | `migrations/postgres/122` 对照 `111` |
| P6 | **错误不可追溯**：last_error 只存 `projection_failed`，没有详情；日志里有 72 次 `expected 4 arguments, got 8`（代码缺陷）和 200 次 42P18 | 90 个失败设备平均有 16,539 条 contribution，约为平均值的 59 倍 | — |
| P7 | **jobs 每变一行源数据就被非 HOT 更新一次** | 约 8.3 万行累计更新 589 万次，其中 HOT 只有 49 万次；delta 来源约 60% 是 ip_mac_history、15% 是 snapshot_facts | 触发器 `enqueue_inventory_projection*` |
| P8 | **宽 jsonb 主键加整组替换导致索引膨胀**：contributions 主键含 79 字节的 origin_key，再加上 latest 索引；deltas 每行约 690 字节，其中 payload 不到 100 字节 | 7 个以上零使用索引（lookup_text/name/mac/ip、sessions_dimensions 等）；`fair_claim` 每次认领约扫 6,400 个索引元组 | — |

### A''. 身份写入、识别物化与设备名称（已深挖）

| # | 问题 | 证据 | 代码位置 |
|---|---|---|---|
| R1 | **全局身份写锁**：domain worker（每块 1,000 条，注释里记录过持锁 49 秒）、两个身份物化进程、旧接入路径都共用一把 advisory 锁。物化进程等 8 秒拿不到锁就返回 `(0,nil)`，看起来是成功，实际是无声停滞 | — | `identity_batch_write.go:806`、`identity_materializer.go:193`、`domain_worker.go:202` |
| R2 | **每行身份数据扇出 3–5 行队列写入**：每改一行历史表、实体或会话，都会触发写 deltas（整行转 jsonb）、upsert projection_jobs、upsert recognition_jobs；会话表另加 account_tag 和 shared_profile 两路 | 基表变更约 536 万行，对应 jobs 更新 589 万次、deltas 插入 515 万行，接近 1:1 | `postgresstore.go:1526` |
| R3 | **30 分钟窗口合并大面积失效**：arp 后续行中 68% 与上一窗口间隔不到 60 分钟，却新开了一行（推测原因：窗口头截止时间按整批最新观测计算，且只在延长时才更新）；packet-sidecar 在 10-14 00:00–15:00 的事件时间比接收时间晚 6–13 小时，加重误判 | `identity_ip_mac_history` 表 3.0GB、索引 5.4GB（覆盖索引 3.25GB；主键 383MB，0 次使用） | `bindingAnchor` |
| R4 | **识别物化每次整终端重算，由 8 张表的行级触发器驱动**：不限定列，任何更新都会标脏；每次重算都要重读会话、IP 历史、接入历史、名称、线索、域名证据 | jobs 被更新 48 万次；dirty_generation 最大 339,957；积压 12,860 个；超时 648 次 | `recognition_materializer.go:92`、`postgresstore.go:425` |
| R5 | **summary 表每分钟全表 jsonb 展开** | 约 810 次 Seq Scan；8 个筛选索引 0 次使用 | `fingerprint_coverage.go:70` |
| R6 | **设备名重试永远在轮转一批无法解析的记录**：约 1.46 万条 mDNS 记录永远解析不了，却被反复取出；每条 mdns_service 触发一次 mdnsServiceOwners 全表扫描（约 130ms），100 条就超过 10 秒预算。这才是每 15 秒一次超时的真实来源 | 超时 3,661 次；`device_name_evidence` 被顺序扫描 11.4 万次、读 147 亿行 | `domain_worker.go:98,112`、`device_names_postgres.go:163,254` |
| R7 | 设备名称每条单独提交一次（每次 WAL fsync 约 230ms），ON CONFLICT 每次改写整行，又触发识别作业 | — | `device_names_postgres.go:37` |
| R8 | router recognition 对每个事件单独查一次 ResolveDeviceAt（N+1），并吞掉错误 | 空 IP 报错 51,834 次（推测来自该车道） | `router_recognition_materializer.go:195`、`device_lease.go:97` |
| R9 | **没有保留或清理机制**：`device_signal_events` 304 万行，主键几乎覆盖全部列，每批还要按 signal 对全部历史做一次 count 和 row_number；`device_address_leases` 76 万行，其中当前有效的只有 2 条，5 个索引大量重复（458MB）；`discovery_batch_work` 在 V2 关闭后留下 1 万行无人消费（每行约 59KB，TOAST 661MB） | — | `identity_batch_write.go:696-724` |
| R10 | `identity_ingest_batches` 上的 `scope_key AND sequence` 查询没带 `protocol_version=2`，用不上部分索引，只能并行全扫，而且每次 apply 提交都会执行 | EXPLAIN 已确认 | `identity_inbox.go:307`、`identity_calibration.go:106,171` |

### B. 同步耦合与非幂等重传（快照风暴）

| # | 问题 | 证据 | 代码位置 |
|---|---|---|---|
| B1 | 桥接上传快照后同步等待「校准发布」，上限 3 分钟；超时当失败处理，10 秒后重读 Redis、生成新快照 ID 再整份上传 | 名义 30 分钟一份，实际每 3 分 20 秒一份；日志里的 `deadline_exceeded` 与快照入库时间逐一对应 | `internal/legacy4k/publication.go:13`、`cmd/legacy-4k-identity-bridge/main.go:349` |
| B2 | 进程每次重启都立即补一次全量快照 | 11:00 到 11:51 重启 4 次 | `main.go:362` |
| B3 | 校准发布时作废收件箱租约（`lease_epoch+1`）；apply 又要求代际不变，换代就整批失败 | `identity inbox apply: identity worker lease expired` | `identity_calibration.go:184`、`identity_inbox.go:212` |

### C. 热点单行与心跳写入（全局串行点）

| # | 问题 | 证据 |
|---|---|---|
| C1 | `identity_pipeline_scopes` 单行有 13 处写入点：接收、apply、导出心跳、校准续租、失败上报 | apply 收尾的 UPDATE 被取消 102 次；该行 autovacuum 924 次 |
| C2 | 多个单行状态表每轮循环都写 | `endpoint_inventory_projection_state` 1 行被更新 19.6 万次、autovacuum 1,233 次；`application_*_cursor` 空闲时也每秒 UPDATE（`application_observation_read_model.go:52`、`application_connection_read_model.go:63`） |
| C3 | 刷盘过于频繁 | 业务进程 13.5 小时 WAL 刷盘 52 万次（约 11 次/秒），`synchronous_commit=on` |

### D. 固定短超时与批量控制（自我放大）

| # | 问题 | 证据 | 代码位置 |
|---|---|---|---|
| D1 | 收件箱 claim/apply 硬编码 2 秒，短于 10 秒的租约 | 自 10-13 起 apply 超时 6,447 次、claim 超时 1,089 次 | `identity_inbox_worker.go:32,39` |
| D2 | 批量控制失败就减半，最低 25，连续成功 10 次才 +25；每批固定开销 0.4 到 0.9 秒，与条数无关 | 每批 2 到 3 条时 apply 仍需约 0.8 秒；积压时始终卡在 25 条 | `identity_inbox_worker.go:15-26` |
| D3 | 失败后整批回滚，已写的 WAL 白费 | — | — |
| D4 | 库存投影实时车道按截止时间失败，jobs 行锁超时（**待深挖**） | 2,441 次 `lock timeout` 加 6,530 次 `NOWAIT` 冲突，语句为 `...projection_jobs ... FOR UPDATE`；38,628 个设备积压约 13 小时 | — |
| D5 | 失败任务没有退避，并且永远排在队首：失败后只设 `not_before=now()+1s`，不更新 `updated_at`；领取 SQL 的排序与索引列顺序不一致，每次领取都要 Seq Scan 加 Sort | 090077 大约每 16 秒里有 15 秒占着账号标签车道；领取 SQL 累计读 15.4 亿行 | `account_assessments.go:342` |
| D6 | 触发器在每次会话写入时把 dirty_generation 加一，不合并 | 090077 的 dirty_generation 已累加到 39,887，processed_generation 只有 9 | `migrations/postgres/117:96` |

### E. 可靠消费与游标语义（违反「可靠消费」「不得跳过积压」）

| # | 问题 | 证据 / 代码 |
|---|---|---|
| E1 | 域名对账在结果为空时每轮把游标**倒退 10 分钟**，退到 7 天下限为止 | `domain_worker.go:342-358`；现场游标停在 10-11；每次读 1.38 亿行、5.6GB 却返回 0 行，约 1.15 TiB/天 |
| E2 | passive/router 物化在结果为空时游标不前进，尾部扫描越来越长 | passive `:156,:651-653`；router `:149,:174` |
| E3 | **同一时间戳行数超过批大小时游标永久卡住**：CH 的 MV 把 `received_at` 写成 `now64(6)`，同一次插入的所有行时间戳相同（09:44:00.683936 一个时间戳有 708 行，router-pilot 单个时间戳最多 6,823 行）。10-13 现场版本的 SQL 只按时间过滤，续读点在 Go 侧 `chRowAfterCursor` 里判断，所以 LIMIT N 每次读回的都是同一批行；卡住的批又被当成满批让批大小翻倍，超时后再减半，始终没超过 708。`processed_events` 同时被虚增。 | `cursor_boundary.go:18`、`identity_materializer.go:46-67,144-158,215`。HEAD 已在 `:120` 补回 `event_id>` 条件，但「批大小必须大于同一时间戳行数」这个前提仍然存在 |
| E4 | **主动跳过积压，数据已真实丢失**：`PROXY_SENTINEL_MAX_BACKLOG=5m` 会把游标直接改成 `now()-5m`，并把超时的识别和画像作业标为已完成。router-pilot 跳过约 2,247 万行，其中 10-10 到 10-13 一次就跳过约 8,837 万行；ncu 跳过约 12.6 万行 | bc152658 引入的 `materializer_backlog.go` 仍在现场版本中运行（集成分支上已无此文件），现场 `runtime.env` 仍配置着这一项 |
| E7 | **全局暂停把不相关的车道一起停掉**：`deferIdentityDerivedWork` 只要收件箱积压超过 100 条，就暂停两个物化进程和导出，而且查询不按传感器过滤。NCU 收件箱一积压，router-pilot 也跟着停，没有任何报错 | `identity_materializer.go:416`；导出积压 72,185 条，从 01:27 起停止；router-pilot 落后约 36 小时（游标后还有 6,461 万行） |
| E8 | **设备批次丢弃后无法补回**：domain worker 队列容量只有 32，队满直接丢批，日志 13,745 次；对账只从 CH 回读 dns/tls/quic/http，设备和 DHCP 批次不在其中，所以「durable replay will retry」的说法不成立 | `domain_worker.go:36,89`、`domain_evidence_clickhouse.go:26`；租约日入库量 10-13 为 17,494、10-14 为 2,259、10-15 为 159，同期 CH 每小时仍有约 2.7 万条 DHCP（推测是丢批所致） |
| E5 | 按接收时间建的游标没有 `< now()-Δ` 安全边界，迟到可见的块会被永久跳过；`APPLICATION_HISTORY_DISABLED` 关闭后迟到事件也补不回来 | `activity_v3_read_model.go:181`、`application_jobs.go:218`、`appdomain/scheduler.go:13` |
| E6 | **重复处理**：NCU 认证事件先写 PG 收件箱，再导出到 CH，再从 CH 读回 PG。router-pilot 的设备事件由 domain worker 写一遍，又由默认身份物化进程从 CH 读回写一遍，两路抢同一把锁。CH 中约 1,100 个重复 event_id 来自导出重投 | `identity_materializer.go:282-284`、`domain_worker.go:74,191` |

### F. 查询与键设计不匹配，读放大（ClickHouse 与 PG）

| # | 问题 | 证据 |
|---|---|---|
| F1 | `normalized_events` 排序键中 timestamp 在第 3 位，按时间范围查询只能靠分区裁剪 | 域名对账 1.15 TiB/天 |
| F2 | activity dispatch 的下界固定在 cutover，元组比较用不上主键；版本表每轮全表 argMax | 约 276GB/天，`activity_v3_read_model.go:108-121` |
| F3 | identity 物化 `SELECT *` 读宽 JSON 列，LIMIT 150 一直停在初始值 | 766GB/天，`identity_materializer.go:122` |
| F4 | passive 表的类型字段不在排序键里，近 1 天 2300 万行中 ARP 占 76% | passive_v2 一天读 3.46 TiB（10-14 已修正元组比较的写法） |
| F5 | `device_name_evidence` 缺 `lower(value)` 和 `processed_at` 方向的索引，并在每个摄入批次被调用 | 约 40 万行，被顺序扫描 11.4 万次、共读 147 亿行（`device_names_postgres.go:163,255`） |
| F6 | `identity_ingest_batches` 旧协议数据从不清理，并被频繁顺序扫描 | 顺序扫描 7,943 次、读 26.7 亿行 |
| F7 | 存在无用索引，写入时仍要维护 | `endpoint_recognition_summary` 8 个索引 idx_scan=0；`identity_ip_mac_history_pkey` 383MB 从未使用 |

### F'. 控制面列表、详情与缓存（违反「列表读取边界」「游标分页」「缓存约束」）

| # | 问题 | 证据 / 代码 |
|---|---|---|
| F8 | `/device-inventory` 每次请求都在请求内做全网 facets（DISTINCT 加三表 Hash Join）和 `count(*)`；不带 cursor 时退回 OFFSET 分页；SSID 等维度筛选用 `dimensions->>'ssid'`，用不上 GIN 索引，对 97 万行做 Seq Scan | `device_inventory_list.go:66,163,175,186-194` |
| F9 | 每次列表、详情、溯源请求都要算全局投影状态：对 projection_jobs 做 3 次 Seq Scan | 13.5 小时内 13.7 万次、读 50 亿行；`inventory_read_state.go:31` |
| F10 | 旧接口 `/devices` 把全量终端 catalog 加载进内存，再用 9 个 OR 的 `EXISTS … LIKE '%q%'` 查询 | EXPLAIN cost 4,330 万，其中对 8.4GB 的 ip_mac_history 做并行全扫；后台 `RebuildDeviceProfiles` 也通过它用 OFFSET 翻遍全网；`postgresstore.go:487-640,1646` |
| F11 | `/router-observations` 和 `/account-assessments` 都在请求内先做窗口去重或分组、再算 count、最后 OFFSET；前者还按 JSON 字段筛选 | `router_observations.go:249-268`、`account_assessments.go:382` |
| F12 | 跨查询键持锁：`deviceInventoryUpdating` 拿着全局 mutex 执行 SQL，所有列表请求串行等待 | `device_inventory_list.go:279-301` |
| F13 | 缓存不按版本失效：metadata 用 30 秒 TTL；catalog 刷新失败后最长 5 分钟仍返回旧值且不带错误标记；统计缓存 60 秒内都标为 fresh | `server.go:425`、`recognition_catalog_cache.go:27-31`、`statistics_cache.go:236-288` |
| F14 | `/integrations/identity/status` 和 `/metrics` 每次请求都对 36.6 万行的 batches 做全表 count | `identity_ingest.go:248`（即 F6 的主要来源） |
| F15 | 名称解析在空地址时也执行 `''::inet`，报错 51,834 次 | `device_lease.go:97` |
| F16 | SRun 轮询按 `campus_id=''` 去找上一份快照，现场快照的 campus 是 `ncu`，所以「成员没变就跳过」的判断可能一直不生效（推测） | `srun_identity_poll.go:114` |

### G. 写入扇出与派生表冗余（违反「索引与结果表成本」）

| # | 问题 | 证据 |
|---|---|---|
| G1 | 每个采集源每 5 秒单独插入一次，不跨源合批 | normalized_events 一天插入 2.4 万次，中位每次 50 行（`internal/realtime/worker.go:111-226`） |
| G2 | 每次插入同步触发约 12 个 MV | 原始写入 8.1GB/天，派生写入约 70GB/天，约 8 倍；合并读约 1.4TB/天 |
| G3 | 死表和重复写入 | `ip_event_features_10m` 没有读方、没有 TTL，一天合并读 722GB；`shared_behavior_signal_events_v1_mv_new` 与旧 MV 完全相同，导致**双写**（仓库里没有它，推测是现场手工创建） |
| G4 | 退役不完整 | ids v1/v2、passive v1 已停写但仍占约 28GB；connection v1/v2 仍在双写；identity_signal_events 几乎是 normalized_events 的全量副本 |
| G5 | PG 侧每次身份写入经 14 个触发器扇出到投影、识别、标签等队列 | 库存 deltas 和 jobs 的变动量是全库最大（**待深挖**） |

### H. 状态与健康判定失真（违反「未处理不得伪装完成」「明确区分状态」）

| # | 问题 |
|---|---|
| H1 | 收件箱停滞 2.5 小时、积压 6.2 万条，`/readyz` 的 `identity_ingest` 仍报 `ready`：该组件只做 `db.PingContext`（`health.go:168`）；`stale` 不影响 ready；非必需组件的任何错误一律显示为 `delayed`（`health.go:129`） |
| H4 | 运行状态里的 `last_error` 是单个字段，下一次成功就把它清空，于是状态在 failed 和 ready 之间来回跳（`account_assessments.go:325`）；同时一个坏任务会让全局投影状态报 failed（`inventory_read_state.go:42-49`） |
| H5 | 读模型游标在没有新数据时也把 `updated_at` 刷成 now，健康检查据此判定为新鲜，实际数据停在 10-08 |
| H2 | `application_read_model` 永远是 delayed：依赖的一次性回填只在 `PROXY_SENTINEL_RUN_LEGACY_BACKFILL=true` 时才执行，现场 `application_read_model_backfills` 为 0 行（`application_read_model_health.go:66-75`） |
| H3 | 应用识别链路在空转：10-09 起 L7 事件为 0，但每 2 秒仍写一个空批次，现场已积累 20.4 万行 |

### I. 生命周期与运维配置

| # | 问题 |
|---|---|
| I1 | 标准事件 TTL 只有 7 到 8 天，且按事件时间计算，违反「热查 30 天、按入库时间、归档一年」；归档表只在 10-14 写过 3 小时 |
| I2 | CH `text_log` 日志级别为 trace，大部分系统日志表没有 TTL（共约 30GB） |
| I3 | PG 参数不适合当前负载：`max_wal_size=8GB` 导致 7 次被迫检查点、单次检查点写 15 到 76 分钟；`effective_cache_size=32GB`；没有慢日志、`pg_stat_statements` 和 `track_io_timing` |
| I4 | 业务进程 13.5 小时从磁盘读约 61GB、缓存驱逐 716 万次，工作集远大于 12GB 共享缓存（膨胀的代际表、宽索引加剧这一点） |

## 三、根因排序

0. **数据已丢失，正确性优先于性能（E4、E7、E8、P4、P5）**：跳过积压已丢弃超过 1.1 亿行身份和设备事实；设备和 DHCP 批次在队满时直接丢弃，而且补不回来；快照投影拿不到锁就静默跳过；迁移 122 删掉了撤销分支，更正永远不会生效。这些问题即使性能恢复也会继续产生错误结果，需要先修复，再规划补数。
1. **全量重建与非幂等重传（A1–A3、B1–B3）**：认证快照每 3 分钟整代重建 3.7 万行，清理又跟不上，是 PG 写放大和缓存污染的最大单一来源，并直接打断收件箱。策略类读取还在请求内整读 7 天快照（约 2.5GB），把同一份原始文档反复解压。
2. **按实体整体重算、逐行往返、复杂度随历史量增长（A4、A6、P1–P3、R4）**：库存投影逐 origin 往返，超过 30 秒整批回滚；识别每次重算整个终端；网关 MAC 一个设备就积压 55.8 万条 delta。公共账号和反复重新登录让账号标签和库存关系聚合变成 O(n²) 或全历史扫描；再加上失败不退避、一直排在队首（D5），一个热点账号就能堵死整个车道。
3. **固定短超时加整批回滚（D1–D3）**：在慢盘上把「慢」变成「失败重做」，形成正反馈。
4. **热点单行、心跳和小提交（C1–C3、G1）**：刷盘次数和行锁串行决定了吞吐上限，与数据量无关。
5. **游标语义 bug 与键不匹配（E1–E2、F1–F4）**：CH 每天回扫数 TB，与 PG 抢同一块盘。
6. **派生扇出与冗余（G2–G5）**：每条输入在 CH 和 PG 都扇出 8 到 14 份写入。
7. **查询路径越界（F8–F14）**：列表请求内聚合、OFFSET、JSON 筛选和全局锁，让「5 秒可查询」和「P95 ≤500ms」在当前结构下无法保证。
8. **状态失真（H）**：问题发生时不可见，排障只能靠人工巡检。
9. **生命周期与参数（I）**：放大以上问题，但不是根因。

### 共性的设计问题

把以上问题归并，核心是五条反复出现的模式：

1. **用「整体重算」代替「增量维护」**：快照代际、账号标签、关系聚合、全窗口统计都是这样。代价随历史量增长，而不是随变化量增长。
2. **把原始大文档或原始事件当作查询源**：快照 jsonb、宽 JSON 列、JSON 字段筛选，导致每次读取都要解压、反序列化。
3. **把可靠性建立在「短超时加重试」上**：没有退避，没有幂等的重传 ID，也不区分慢和失败。在慢盘上会自我放大。
4. **以单行状态和全局锁做协调**：租约、进度、心跳、错误都集中在同一行；所有身份写入共用一把 advisory 锁；一个车道积压就暂停全部车道。所有车道在这里串行，并互相拖累。
6. **用「跳过」和「静默返回成功」应对压力**：跳过积压、队满丢批、拿不到锁返回 `(0,nil)`。系统看起来正常，数据却在悄悄丢失。
5. **健康状态只看「进程活着」和「最近写过」**：不看积压量和最老待处理时间，所以失速发生时看不到。

## 四、待确认与后续

- 现场版本里 `materializer_backlog.go` 仍在运行，而集成分支上已经没有这个文件：需要核对现场版本与分支的差异，以及 `PROXY_SENTINEL_MAX_BACKLOG` 的配置来源。
- packet-sidecar 在 10-14 有 6–13 小时的时间戳偏移，需要查明原因。
- 补数方案：被跳过的约 1.1 亿行（CH 中的数据仍在 TTL 内的部分）和丢失的 DHCP 租约批次。
- 临时文件 3.97GB 的归因：现场 `log_temp_files=-1`，目前只能推测主要来自快照分块暂存。
- L7 事件自 10-09 起为 0 的上游原因。
- `shared_behavior_signal_events_v1_mv_new` 的来历（仓库里没有）。
