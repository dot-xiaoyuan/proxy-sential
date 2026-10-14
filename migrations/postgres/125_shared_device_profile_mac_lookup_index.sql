-- 089 的 enqueue_existing_shared_device_profile_identity_jobs 逐行按「endpoint_id 或规范化
-- MAC」唤醒已存在的共享设备画像。MAC 分支把 regexp_replace(lower(mac),...) 作用在**列**上，
-- 因此无法使用既有的 shared_device_profiles_mac 索引（该索引扫描计数长期为 0）。
--
-- 现场 184（2026-10-14）实测该查询退化为顺序扫描：
--   Seq Scan on shared_device_profiles (actual time=0.028..7.028 rows=1 loops=1)
--     Filter: ... regexp_replace(lower(mac),'[^0-9a-f]','','g') = '9844ced758e0'
--     Rows Removed by Filter: 938   Buffers: shared hit=433   Execution Time: 7.113 ms
-- 表仅 939 行 / 3.4 MB，但每次调用都要扫全表并对每行做正则，约 7.26 ms/行。
-- 该函数由 shared_device_profile_endpoint_dirty / _session_dirty / _account_projection_dirty
-- 三个行级触发器调用，每批约 2,500 台设备，合计约 50 秒——这正是
-- `domain batch timing ... identity=49.045s total=49.058s` 的来源。
--
-- 本迁移补一条与查询表达式完全匹配的表达式索引，使该分支可走索引：
--   Seq Scan 7.113 ms / 433 buffers → Bitmap Index Scan 0.159 ms / 2 buffers
-- 现场以 CONCURRENTLY 创建后，函数耗时由 7.26 ms/行降到 4.39 ms/行，索引被实际使用。
-- 逐行调用的计划与 SPI 开销仍在，后续需要把这三个触发器改为语句级、集合式唤醒。
CREATE INDEX IF NOT EXISTS shared_device_profiles_mac_normalized
  ON shared_device_profiles (regexp_replace(lower(mac), '[^0-9a-f]', '', 'g'))
  WHERE merged_into_profile_id IS NULL;
