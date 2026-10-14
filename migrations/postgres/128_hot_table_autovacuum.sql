-- 热点表按行数比例触发 autovacuum 的默认阈值（scale 0.2）在这些表上等于"几乎不触发"：
--   identity_ip_mac_history        1,380 万行，第 10 轮修复后每分钟约 636 次行内更新 -> 每天约 92 万死元组
--   endpoint_inventory_contributions 1,820 万行，插入与整 origin 替换并存
-- 按 20% 计算，前者要积到 276 万死元组（约 800 MB 膨胀）才会清理，而表本身只有 10 GB。
-- 这里按表收紧比例阈值，并给纯插入表打开 insert 阈值（PG 13+），让可见性映射跟得上索引扫描。
-- 这些参数保存在系统目录中，重启后仍然有效。
ALTER TABLE identity_ip_mac_history SET (
  autovacuum_vacuum_scale_factor = 0.02,
  autovacuum_vacuum_threshold = 1000,
  autovacuum_analyze_scale_factor = 0.01,
  autovacuum_vacuum_insert_scale_factor = 0.02
);
ALTER TABLE endpoint_inventory_contributions SET (
  autovacuum_vacuum_scale_factor = 0.02,
  autovacuum_vacuum_threshold = 1000,
  autovacuum_vacuum_insert_scale_factor = 0.02
);
ALTER TABLE endpoint_inventory_projection_deltas SET (
  autovacuum_vacuum_scale_factor = 0.02,
  autovacuum_vacuum_threshold = 1000,
  autovacuum_vacuum_insert_scale_factor = 0.02
);
ALTER TABLE identity_binding_window_heads SET (
  autovacuum_vacuum_scale_factor = 0.02,
  autovacuum_vacuum_threshold = 500
);
ALTER TABLE identity_current_addresses SET (
  autovacuum_vacuum_scale_factor = 0.05,
  autovacuum_vacuum_threshold = 1000
);
