# 被动发现段定位事件键方案（兼容基础已实现）

## 现状与目标

184 的自然流量已经多次填满发现采集队列并造成停采。2026-11-03 的只读样本中，投影单段约 5.57 秒，`reserve_keys` 约 3.34 秒；紧凑键表约 3,072 万行、12 GiB，主键索引约 2.26 GiB。采集输入约每秒 355–478 条，而投影持续低于该速率。这些是不同时间窗的现场样本，不能直接当作新方案的吞吐承诺。把段扩大到 2,000 条只能摊薄固定提交成本，仍会保留逐事件 PostgreSQL 键写入。

目标是让**新接收的被动发现段**通过段主键和段内序号定位回执，退出 `stream_discovery_event_keys_compact` 的逐事件写入。旧 `stream2` 键、旧回执、原文、案件引用和归档状态保持原样。新方案只去掉重复的 PostgreSQL 键账本；事实、真实状态变化、需要异步诊断的回执与权威原文仍按各自职责保留。

## 身份和持久证明

1. 新 `EventID` 使用 `stream3-<64 字符十六进制段 ID>-<十进制序号>`，外部 `event_key` 仍为 `<epoch>:<EventID>`。序号从 0 开始，严格小于该段投影事件数和 2,000。解析时先精确匹配调用方给定的 epoch 前缀，再限制段 ID 为 64 个小写十六进制字符、序号为无前导零的规范十进制；不能从任意字符串截取后静默接受。
2. `streamlog.segmentID` 当前只由 epoch、来源、来源路径、文件/采集实例 ID、起止偏移与可选来源代次计算，不依赖事件键或正文哈希。因此采集端已算出来源正文长度和结束偏移后，可调用同一函数生成段 ID，再给各事件填入 `stream3` 键；不会形成哈希循环。投影必须重新计算并核对段 ID、来源位置、事件序号和所有键，禁止信任单独传来的 ID。
3. `stream_projection_segments.segment_id` 主键、内容哈希和来源位置承担段级幂等：同一段重试且内容一致只确认原事务；同一位置内容不同必须失败并隔离。单段内部事件序号唯一，跨段的 ID 由完整来源位置区分。切换前先恢复旧 journal 中未完成的 `stream2` 段，固定首个 `stream3` 段 ID、首次入库时间和来源游标；不修改旧段和旧截止点。
4. 现有清单继续保存每个序号的处理结果和识别摘要。建议在 `stream_discovery_segment_receipt_manifests` 增加 `key_scheme`（旧行为 `stream2`）、单段 `scope_id`、按序号连续拼接的 32 字节 `content_hashes`。新段写入前验证全部事件属于同一 capture scope；清单约束要求 `octet_length(content_hashes)=32*jsonb_array_length(results)`，且长度等于段事件数。哈希取自每个标准事件正文的 SHA256；按序号读取 `substring(content_hashes from 32*ordinal+1 for 32)`。每 2,000 条最多新增 64 KiB 哈希元数据和一份 scope，不新增逐事件 B-tree 索引或完整原文副本。旧清单保持原列值；可短期给 `stream2` 清单填影子哈希做核对，但 `key_scheme` 仍为 `stream2`，不能把影子元数据当作新回执。

段行、清单、事实和状态变化仍在同一个投影事务提交。新键只可在 `key_scheme='stream3'`、段来源为 `passive-discovery`、epoch 和来源位置完整、序号合法、scope 与正文哈希匹配、该结果为非空字符串时由清单提供回执。归档状态仍以 `lanes_finalized_at` 区分处理中和已确认；不能因为投影已提交就称原文已经归档。案件读取另外从 ClickHouse 取权威原文、重新计算哈希，并由案件触发器复核已保存原文及引用。

兼容基础迁移命名为 `224_passive_segment_key_locator.sql`，应用后账本从 224 项变为 225 项。它只扩展现有段表和清单表；段行的独立 `passive_key_scheme` 防止清单标记损坏时把已存在的新段误判成“无记录”。旧段默认 `legacy`、旧清单默认 `stream2`，旧键继续可读：

```sql
ALTER TABLE stream_projection_segments
 ADD COLUMN passive_key_scheme text NOT NULL DEFAULT 'legacy',
 ADD COLUMN source_generation bigint NOT NULL DEFAULT 0;
ALTER TABLE stream_discovery_segment_receipt_manifests
 ADD COLUMN key_scheme text NOT NULL DEFAULT 'stream2',
 ADD COLUMN scope_id text,
 ADD COLUMN content_hashes bytea;
ALTER TABLE stream_discovery_segment_receipt_manifests
 ADD CONSTRAINT stream_discovery_manifest_key_scheme
 CHECK (key_scheme IN ('stream2','stream3') AND
  (key_scheme <> 'stream3' OR
   (scope_id IS NOT NULL AND scope_id <> '' AND content_hashes IS NOT NULL AND
    octet_length(content_hashes)=32*jsonb_array_length(results)))) NOT VALID;
```

`stream3` 写入还要把每个 `results` 项校验为非空字符串，并核对 `event_count`、月份及所有哈希；单行 CHECK 无法跨表验证这些条件。应用读取从来源位置和 `source_generation` 重新计算段 ID；案件触发器使用严格的 SQL 键解析函数并校验同一位置。该迁移不建逐事件索引；单段主键查询仍用现有 `segment_id` 索引。迁移、触发器和查询必须在真实 PostgreSQL 隔离库中执行计划与故障回放，不能把 SQL mock 视为迁移验收。

## 需要同时覆盖的读取和恢复入口

| 入口 | 新键必须做的核对 |
| --- | --- |
| `StreamDiscoveryReceipt`、最多 50 键的批量接口 | 从键解析段 ID/序号，按段主键读取清单；核对 epoch、scope、正文哈希、结果和月份，按最终确认时间分别标记处理中或已确认。批量按段分组，不能逐键重复解压同一清单。旧键仍走原账本。 |
| 设备变化历史和证据引用 | 有界分页读 `stream_discovery_changes`，仅对本页的新键按段定位；核对 `body_ref` 的 epoch、scope、key、SHA256、月份和正文布局。缺失或冲突应明确失败，不把历史行误报为有效证据。 |
| 案件证据读取与 `sentinel_protect_stream_discovery_case_evidence` | 应用与 PostgreSQL 触发器分别核对新清单、段最终确认、引用字段和 ClickHouse 原文哈希。无清单、错误序号、错误 scope、错误哈希、未最终确认都拒绝，旧案件引用继续走既有路径。 |
| `MarkStreamArchiveConfirmed` 与中断恢复 | 对照 journal 的段哈希、来源位置、所有事件键及清单的结果/哈希向量；先有三条 lane 的持久 ACK，再标记最终确认。重复执行不新增事实或回执。兼容版本必须能处理后续版本遗留的 `stream3` 段。 |
| 分钟识别、异步诊断和新鲜度 | 继续按清单摘要统计静态输入、按必要的逐事件诊断回执观察异步结果；`manifest` 段的待归档和迟到投影水位逻辑继续适用。抽样诊断回执可保留，但不能作为所有新事件都已持久化的替代证明。 |

兼容版分别识别旧 `stream2` 和新 `stream3`，新键的归档恢复从 journal 校验段来源和所有事件键。段 ID 根本不存在时可返回“无记录”；段已存在但清单缺失、序号越界或哈希冲突时必须明确报错，不能回退到旧键表掩盖损坏。`stream2` 既有每事件键是不可逆的来源位置哈希，无法直接从键找段；不能把旧数据无审计地改造成新格式。

## 发布顺序和回退

1. **兼容读取版**：新增向前迁移（当前文件序列 223 之后的独立迁移）和全部 `stream3` 读取、案件、归档恢复路径，但写入开关默认关闭，现场仍只产生 `stream2`。迁移只增加列、约束和触发器分支，不改写已应用迁移或旧数据。先在隔离 PostgreSQL/ClickHouse 回放重复、乱序、跨月、中断、冲突、篡改、归档失败和案件引用；现场只读核对旧键结果与影子清单元数据，保留该版作为下一阶段的 `previous`。
2. **新写入版**：确认上一版确能恢复 `stream3` 后，才启用新键。让正在运行的发现进程排空内存队列并自然接管，记录固定切换游标、首段和停采缺口；不强杀、不重置历史。先按自然流量受限运行并检查段/清单/原文/案件样本、查询延迟、错误、队列、净积压和 PostgreSQL I/O。若新写入版故障，关闭开关或回退到兼容读取版；不可回退到尚不识别 `stream3` 的版本。旧 `stream2` 段仍可恢复。
3. **旧数据退役**：仅在新读路径、归档覆盖范围和引用逐项核验、30 天热查与首次入库后一年归档、案件保护均满足后另行设计。此方案不授权删除旧键、唯一原文、未完成任务或案件证据。

验收记录必须分别给出实际输入、持久接收、投影完成和未完成缺口，不能以服务 `active`、清单行数或短时健康检查宣称镜像覆盖恢复。首次阶段应比较相同自然负载下的每事件 PostgreSQL 写入量、WAL 与磁盘等待、投影事件/秒、采集队列和 `full_count`；数据分布和其他服务负载需同时记录。当前 184 为旋转盘且本机空闲空间不足 100 GiB，不在本机启动完整快照，也不在现场造数压测。

## 2026-11-03 兼容基础实现进度

隔离分支已加入 224 迁移、严格的 `stream3` 键解析，以及按段主键读取单条和最多 50 键批量回执；同一段的多个序号只读取一行清单。段行另存独立的键格式和来源代次，回执读取重算来源段 ID 并核对整段结果；另以一次有界查询检查已有抽样诊断回执的失败状态、哈希、引用、结果和定位，缺席的诊断行不构成缺口。段级投影与中断重放、归档确认、设备变化历史、案件应用读取和 PostgreSQL 案件触发器均加入新路径；历史列表对新键强制使用段清单证明并拒绝同键旧账本歧义。归档确认将 journal 的纳秒入库时间按 PostgreSQL 微秒精度核对；JSON 入库的历史和诊断时间允许向上舍入一个微秒，超过该范围仍报冲突。新段元数据一旦写入即不可改写，最终确认时间只准首次填写。分钟识别与新鲜度查询本来就按 `manifest` 模式读取段清单，无需另增逐事件查询。旧 `stream2` 查询和写入路径保持原样；当前采集不会生成 `stream3`。

**这仍是未部署的兼容候选，不是已验收的回退入口。** 全仓 Go 测试、构建和 vet 已通过；测试用 SQL mock 及 ClickHouse HTTP 夹具验证读取与重放。新迁移、SQL 函数、案件和不可变触发器的真实 PostgreSQL 集成测试已编写，但因没有专用测试数据库未执行；也尚未用真实 PostgreSQL/ClickHouse 回放全部故障条件。当前本机可用磁盘不足 100 GiB，未启动数据库容器。先完成这些验证、发布兼容版并确认 `previous` 后，才能另出版本开启新键写入；不能把当前代码或 mock 结果称为现场容量改善。
