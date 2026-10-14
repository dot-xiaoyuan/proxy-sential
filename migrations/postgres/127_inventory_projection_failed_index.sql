-- 投影车道每完成一个 endpoint，都会执行一次
--   UPDATE endpoint_inventory_projection_state SET last_error = CASE WHEN EXISTS(
--     SELECT 1 FROM endpoint_inventory_projection_jobs
--      WHERE last_error <> '' AND processed_generation < dirty_generation)
--     THEN 'projection_failed' ELSE '' END, updated_at = now() WHERE singleton
-- （internal/store/inventory_projection.go）。
--
-- 现场 184（2026-10-14）开启 log_min_duration_statement=2000 后实测：该语句在 100 秒窗口内执行
-- **28 次、平均 2,517 ms**，合计约 70 秒——占该窗口数据库时间的约 70%。它不是无害的心跳：
-- 状态行的 updated_at 被 inventory_read_state.go 当作读模型的 AsOf / ResultVersion（缓存失效键），
-- 所以**不能用"值没变就跳过"来消除它**；但它的代价来自那条 EXISTS：现有索引
-- inventory_projection_pending_since 是 (pending_since) WHERE processed_generation<dirty_generation、
-- inventory_projection_unprepared 是 (endpoint_id) WHERE processed_generation=0，没有一条匹配
-- `last_error <> ''`，于是每次都要扫任务表（约 8 万行 / 21 MB），且被多个投影 worker 串行放大。
--
-- 本迁移补一条与谓词匹配的部分索引，使 EXISTS 变成一次极小的索引探测，语义完全不变。
-- 现场先以 CREATE INDEX CONCURRENTLY 手工创建（避免长锁），此处为事务内执行的幂等版本。
CREATE INDEX IF NOT EXISTS inventory_projection_failed
  ON endpoint_inventory_projection_jobs(endpoint_id)
  WHERE last_error <> '';
