-- 重放去重不再依赖逐 event_id 的存在性扫描。
--
-- ingest 在插入前会把每个 event_id 读回来做幂等判断；现场基线上一批 500 个 id 就要碰
-- 31–57 个 granule（normalized_event_ids_v2 按 64 行/granule 细分），时间范围扫描同样
-- 会撞超时，每批 4 MiB 的写入因此要 7–11 秒，采集长期落后于生产速率。
--
-- 打开非复制表的插入级去重窗口后，重放的整块插入由 ClickHouse 按内容哈希丢弃，
-- 因此可以配合 PROXY_SENTINEL_EVENT_ID_IDEMPOTENCY=clickhouse 跳过该扫描。
-- 两者必须同时存在：只设置开关而不开窗口，重放批次会真的重复入库。
ALTER TABLE normalized_events MODIFY SETTING non_replicated_deduplication_window=100;
