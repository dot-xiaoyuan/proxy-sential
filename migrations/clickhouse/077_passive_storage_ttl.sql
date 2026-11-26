-- 为被动发现原文归档表配置 1 年自动保留期（与 30 天热查 + 1 年归档生命周期契约对齐）。
ALTER TABLE passive_discovery_raw_archive
  MODIFY TTL toDateTime(accepted_at) + INTERVAL 1 YEAR DELETE;
