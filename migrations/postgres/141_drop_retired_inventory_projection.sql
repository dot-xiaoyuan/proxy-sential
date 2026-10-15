-- 删除已退役的逐行触发器库存投影（PG 迁移 141）。
--
-- 迁移 139 起终端列表由终端状态更新器维护，读取只用 endpoint_inventory_lookup 与
-- endpoint_inventory_accounts；以下表、视图与函数自此无写入方也无读取方。184 现场约 16.6 GB
-- （贡献表 13 GB、快照事实 1.5 GB、会话 0.85 GB、delta 0.47 GB、关联 0.42 GB 等）。
-- 保留：endpoint_inventory_lookup、endpoint_inventory_accounts、endpoint_state_watermark。
DROP VIEW IF EXISTS endpoint_inventory_observation_facts;
DROP TABLE IF EXISTS endpoint_inventory_contributions;
DROP TABLE IF EXISTS endpoint_inventory_projection_deltas;
DROP TABLE IF EXISTS endpoint_inventory_projection_jobs;
DROP TABLE IF EXISTS endpoint_inventory_projection_timers;
DROP TABLE IF EXISTS endpoint_inventory_projection_state;
DROP TABLE IF EXISTS endpoint_inventory_associations;
DROP TABLE IF EXISTS endpoint_inventory_ip_points;
DROP TABLE IF EXISTS endpoint_inventory_sessions;
DROP TABLE IF EXISTS endpoint_inventory_snapshot_facts;
DROP TABLE IF EXISTS endpoint_inventory_snapshot_chunks;
DROP TABLE IF EXISTS endpoint_inventory_snapshot_jobs;
DROP FUNCTION IF EXISTS enqueue_inventory_projection();
DROP FUNCTION IF EXISTS enqueue_inventory_projection_id(text);
DROP FUNCTION IF EXISTS record_inventory_projection_delta();
DROP FUNCTION IF EXISTS enqueue_inventory_snapshot();
