-- normalized_event_ids_v1/v2 只服务 PROXY_SENTINEL_EVENT_ID_IDEMPOTENCY=scan 的逐 id 存在性
-- 扫描（internal/store/clickhousestore.go: existingEventIDs）。现场 184 已设为 clickhouse
-- 模式：eventIDScanDisabled 直接跳过该扫描，改由 normalized_events 的
-- non_replicated_deduplication_window 按内容哈希丢弃重放块；该模式下两张索引表没有任何读取方。
--
-- 现场实测（system.query_log 662 万行，覆盖 2026-10-08 10:47 起全部留存期）：
--   normalized_event_ids_v1 被读 8 次、normalized_event_ids_v2 被读 49 次，
--   对照组 identity_signal_events_v1 被读 337,479 次 —— 同样的统计口径下，前两者已无读取方。
--
-- 但两个物化视图仍挂在 normalized_events 上：每个事件多写两张表（195.94M 行事件各写两次），
-- 现场 729 个活跃部件里有 141 个来自这两张表，是纯粹的写放大与合并压力。
-- 停止写入后两张表各 6.25 GiB / 8.57 GiB 会在 8 天 TTL 内自行收缩到 0。
--
-- 只删除物化视图，保留目标表：历史数据仍可查询，配置回到 scan 模式时仍有一段窗口可用，
-- 且可依 017/018/025/037 中同一段定义重建（重建后仅缺少停写期间的窗口）。
DROP TABLE IF EXISTS normalized_event_ids_v1_mv;
DROP TABLE IF EXISTS normalized_event_ids_v2_mv;
