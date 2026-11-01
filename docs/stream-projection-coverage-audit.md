# 流式投影段完成见证与归档覆盖审计

`stream_projection_segments` 在迁移 215 后记录来源文件号、起止偏移和 `lanes_finalized_at`。这行能为**指定投影段的处理完成**提供一个 PostgreSQL 见证；不能单独证明指定来源区间已经完整接收，更不能证明一年归档或允许清理键、收据、变更与原文。

## 当前只读核验入口

`cmd/stream-witness-audit` 接受一份独立保存的、最多 128 段的来源区间清单。每段包含段 ID、投影哈希、投影事件数和偏移。清单必须在 journal 释放段体前由同一代次的不可变来源材料生成并保存；不能从待核对的 `stream_projection_segments` 行反向复制字段充当独立证据。当前系统**没有自动保存这份清单**，已释放的 r37 段不能仅凭 PG 行补造。因此此命令是后续安全退役的前置核验工具，不能用于宣称现有 r37 历史区间可清理。

示例结构（哈希与 ID 仅作格式示意，不是现场证据）：

```json
{
  "epoch": "example-epoch",
  "source_kind": "zeek-dhcp-binding",
  "source_path": "/path/to/dhcp.log",
  "file_id": "example-file-id",
  "start_offset": 0,
  "end_offset": 100,
  "segments": [
    {
      "segment_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "projection_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "event_count": 2,
      "start_offset": 0,
      "end_offset": 100
    }
  ]
}
```

`projection_sha256` 是 `streamProjectionSegmentHash` 写入 PG 的投影内容哈希，**不是** journal `State.ContentSHA256`，也不是 ClickHouse 原文哈希。每段 `event_count` 是需要发现投影的事件数，不是原始段内所有标准事件数。二者必须由同一不可变段和相同版本的投影逻辑计算。当前缺少持久的清单生成与封存链路；独立性不足的清单只能做字段一致性排查。

```sh
PROXY_SENTINEL_POSTGRES_DSN="$READ_ONLY_DSN" \
  go run ./cmd/stream-witness-audit --manifest /path/to/immutable-interval.json
```

命令仅在 PostgreSQL 的只读、可重复读事务中按 `segment_id` 主键逐段读取，最多 128 行，事务有 15 秒上限，单语句有 5 秒上限；不扫描整代次、不修改账本。输出 JSON 记录清单 SHA256、检查时间、问题代码与每个未核验维度。`witness_confirmed=true` 只表示**清单中列出的段**在该快照内与 PG 的来源位置、投影哈希、计数及完成时间一致。输出的 `cleanup_allowed` 恒为 `false`。旧行的 NULL 位置、缺少 finalizer、缺段、偏移断口或重叠、哈希与计数冲突均拒绝。返回码 0 仅表示这一步见证匹配；返回码 1 表示见证未通过或查询失败。

## 为什么不能从现有字段推导清理资格

- journal 的 `Release` 会删除 `.segment`、`.state` 和 ack log；PG 段行没有逐事件的 `scope_id/event_key/content_sha256` 列表。PG 投影哈希不能反推出原文或逐事件收据。旧段的来源位置和完成时间保持 NULL，不能事后补签。
- `stream_discovery_receipts.archive_state='confirmed'` 表示 lane 确认；`lanes_finalized_at` 还依赖搜索和下游唤醒完成。两者都不是 `stream_event_body_evidence`、`stream_source_raw` 及 PG 变更历史在一年期限内的归档覆盖证明。ClickHouse evidence body 与 evidence raw 的 TTL 取决于 `first_archived_at`，查询时存在也不保证目标保留区间的每一刻都可恢复。
- 来源同一文件可能有晚到、重放、撤销或代次切换；无发现投影事件的段也不会有这张 PG 见证。清单内位置连续不证明清单覆盖了固定截止点之前的全部段，非投影段形成的断口还要由别的 lane 证明；还需来源封存水位、文件代次、未完成 journal/lane 缺口和跨代次重放记录。不能移动截止点来跳过未完成输入。
- 案件引用可进入 `stream_discovery_case_evidence`，并将相关 `stream_discovery_changes.protected` 置为真。当前没有按事件键高效枚举所有案件引用的独立索引或区间级保护清单，不能用“本次未查到案件”替代保护核验。案件原文与唯一原文不随普通热历史退役。

## 完整覆盖审计所需的下一步

1. **封存来源清单**：在段释放之前，以有界方式从 journal 固定段 ID、文件代次、来源区间、原文哈希、投影哈希、逐事件键、事件哈希、ClickHouse 归档月份与保留类别，并记录来源不可变截止点和内容哈希。清单只存必要哈希、引用和计数，不再复制完整原文；需要说明其持久落点、失效与一年保留责任。文件轮转或代次变化另起区间。旧行无法补签时明确标记为不可审计。
2. **逐批完成证明**：按清单顺序逐段核对 PG 完成见证与 journal 未完成缺口；再用两套事件键台账的精确主键及固定月份核对逐事件收据、`body_ref`、`archive_confirmed_at` 和数量。任何丢失、冲突、pending/failed、旧 NULL 或未完成 lane 都拒绝。
3. **原文与归档证明**：按 `body_ref` 的类别、月份、scope、key、哈希精确查 ClickHouse authoritative body；核对正文 SHA256、原始 `stream_source_raw` 的段 ID/来源位置/原文字节哈希、首次入库与首次归档时间、必要的变更历史与覆盖计数。控制单次事件数和返回字节数；ClickHouse 重复物理行不能掩盖不同哈希。核验覆盖范围、保留终点和恢复副本后，才能讨论热副本退役。
4. **案件与迟到保护**：按事件键建立可有界查询的案件引用/保护见证，检查受保护变更和原文；固定区间以后到达的重放、更正、撤销按事件键重新打开相应审计。所有相关任务取消时保留逐批不可变审计、原始证据与原因，不将取消计为完成。

### 后续逐事件核验的有界查询形状

清单增加每个投影事件的 `(epoch, scope_id, event_key, content_sha256, body_ref)` 后，审计器每次最多传 50 个键，在只读快照中分别走两套台账的唯一索引和固定月份的收据主键。下面是查询形状，`$1` 为最多 50 条的 JSON 数组；调用端必须校验返回行数与输入一致，逐行比较预期哈希、月份、完整 `body_ref`，并拒绝两本台账互相矛盾、缺收据、`pending/failed` 或缺确认时间：

```sql
WITH input AS MATERIALIZED (
  SELECT * FROM jsonb_to_recordset(CASE
    WHEN jsonb_array_length($1::jsonb) BETWEEN 1 AND 50 THEN $1::jsonb
    ELSE '[]'::jsonb END)
    AS v(ordinal int, epoch text, scope_id text, event_key text,
         content_sha256 text, body_ref jsonb)
)
SELECT i.ordinal, l.accepted_month AS legacy_month, l.content_sha256 AS legacy_hash,
       c.accepted_month AS compact_month, c.content_sha256 AS compact_hash,
       r.content_sha256 AS receipt_hash, r.archive_state,
       r.archive_confirmed_at, r.body_ref
FROM input i
LEFT JOIN LATERAL (
  SELECT accepted_month, content_sha256 FROM stream_discovery_event_keys
  WHERE epoch=i.epoch AND scope_id=i.scope_id AND event_key=i.event_key
) l ON true
LEFT JOIN LATERAL (
  SELECT accepted_month, content_sha256 FROM stream_discovery_event_keys_compact
  WHERE key_hash=sentinel_stream_discovery_key_hash(i.epoch,i.scope_id,i.event_key)
    AND epoch=i.epoch AND scope_id=i.scope_id AND event_key=i.event_key
) c ON true
LEFT JOIN LATERAL (
  SELECT content_sha256, archive_state, archive_confirmed_at, body_ref
  FROM stream_discovery_receipts
  WHERE accepted_month=coalesce(c.accepted_month,l.accepted_month)
    AND epoch=i.epoch AND scope_id=i.scope_id AND event_key=i.event_key
) r ON true
ORDER BY i.ordinal;
```

ClickHouse 侧先按 `body_ref` 的 `archive_month`、`scope_id`、`event_key` 查窄列并限制物理重复行数，确认没有冲突哈希；随后仅对准确三元组取一份 body 并计算 SHA256。`internal/store/stream_read.go` 的 `GetStreamEventsByRefs` 已实现每批最多 100 个引用的两阶段读取，可作为正文校验基础，但它没有产出区间级归档清单。源原文还须按 `(archive_month, segment_id, raw_sha256)` 查 `stream_source_raw`，核对原文字节哈希、位置及保留类别；不能因为只抽到一个正文或仅有 `archive_state=confirmed` 就判定覆盖。

`stream_discovery_case_evidence` 的主键以 `case_id` 开头，`stream_discovery_changes` 也没有按 `(epoch,event_key)` 的索引。未来按事件键审计案件与变更前需要有界索引或独立的受保护引用清单，并单独说明其稀疏写入成本、案件保留期和撤销后的失效规则。当前不作全表扫描来制造“未引用”结论。

现阶段没有上述完整证明，也没有清理入口。容量增长测试仍应包含 PG 台账、收据、变更、ClickHouse body/raw 和未来审计元数据的总成本；一次短窗的段见证不能替代一年保留验收。
