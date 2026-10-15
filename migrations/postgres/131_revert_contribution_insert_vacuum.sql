-- 128 给这张 1,832 万行的表加了 autovacuum_vacuum_insert_scale_factor=0.02，等于每小时左右
-- 触发一次整表 VACUUM。现场 2026-10-15 抓到 93 秒的 VACUUM public.endpoint_inventory_contributions
-- （IO/AioIoCompletion），与已经饱和的磁盘上运行的投影互相争抢，加剧了端点物化超时。
-- 该表按写入量触发清理的收益不足以抵消这次 IO 冲击，改回只按死元组比例（0.05）触发。
ALTER TABLE endpoint_inventory_contributions RESET (autovacuum_vacuum_insert_scale_factor);
ALTER TABLE endpoint_inventory_contributions SET (autovacuum_vacuum_scale_factor = 0.05);
ALTER TABLE endpoint_inventory_projection_deltas RESET (autovacuum_vacuum_insert_scale_factor);
ALTER TABLE endpoint_inventory_projection_deltas SET (autovacuum_vacuum_scale_factor = 0.05);
