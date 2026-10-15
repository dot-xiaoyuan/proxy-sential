-- 退役无读取方的派生表与重复物化视图（ClickHouse 迁移 041）。
--
-- shared_behavior_signal_events_v1_mv_new：现场手工创建、仓库中没有定义，SELECT 与
--   shared_behavior_signal_events_v1_mv 完全相同，两者同时写入同一张目标表，自 10-15 02:00
--   起该表每小时行数恰为去重行数的 2 倍。删除后由迁移 040 维护的唯一视图继续写入。
-- ip_event_features_10m：001 建立的聚合物化视图，代码中没有读取方、没有 TTL；每天约 2.4 万
--   个小 part 落入旧分区，合并读出约 722 GB/天，是全库合并读取最大的一项。删除视图即删除其
--   内表，不影响 normalized_events。
-- passive_discovery_events_v1：迁移 038 已删除其物化视图，此后无写入亦无读取方（被动发现
--   读取 v2），约 6.6 GiB 只等待 30 天 TTL。
--
-- normalized_event_ids_v1/v2 不在此处删除：它们仍是 PROXY_SENTINEL_EVENT_ID_IDEMPOTENCY=scan
-- 模式的读取方（internal/store/clickhousestore.go），按 039 的说明随 8 天 TTL 自然清空。
DROP TABLE IF EXISTS shared_behavior_signal_events_v1_mv_new;
DROP TABLE IF EXISTS ip_event_features_10m;
DROP TABLE IF EXISTS passive_discovery_events_v1;
