-- 删除投影/识别任务队列上从未被选中的索引。
--
-- 这两张表是身份写入路径每次变更都要 upsert 的热点（行级触发器入队），而索引远大于堆：
--   endpoint_inventory_projection_jobs  堆 20 MB / 索引 112 MB
--   endpoint_recognition_jobs           堆 ~5 MB / 索引 ~20 MB
--
-- pg_stat_user_indexes（stats_reset=never）显示下列索引几乎从未被任何计划选中；表本身很小，
-- 顺序扫描远便宜于索引扫描，因此它们只带来写入放大与索引页闩锁争用：
--   inventory_projection_work_claim            0 次扫描   13 MB
--   inventory_projection_unprepared            0 次扫描  5.3 MB
--   inventory_projection_pending               1 次扫描   53 MB
--   inventory_projection_oldest_pending        1 次扫描   13 MB
--   inventory_projection_pending_since         1 次扫描    8 MB
--   endpoint_recognition_jobs_ready            0 次扫描  3.2 MB
--   endpoint_recognition_jobs_pending          0 次扫描  5.2 MB
--
-- 在用的索引保留：inventory_projection_fair_claim（27,894 次）、
-- inventory_projection_generation_watermark（6 次）、endpoint_recognition_jobs_lane_ready（24,056 次）
-- 以及两张表的主键。
--
-- 现场用 DROP INDEX CONCURRENTLY 手工删除以避免长锁；本迁移在事务内执行同样的幂等删除并记入账本。
DROP INDEX IF EXISTS inventory_projection_work_claim;
DROP INDEX IF EXISTS inventory_projection_unprepared;
DROP INDEX IF EXISTS inventory_projection_pending;
DROP INDEX IF EXISTS inventory_projection_oldest_pending;
DROP INDEX IF EXISTS inventory_projection_pending_since;
DROP INDEX IF EXISTS endpoint_recognition_jobs_ready;
DROP INDEX IF EXISTS endpoint_recognition_jobs_pending;
