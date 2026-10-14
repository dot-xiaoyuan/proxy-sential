-- endpoint_inventory_contributions 的三个聚合索引只服务 refreshInventoryRelation 里三段等价的
-- 标量子查询（同一 (endpoint_id,kind,value,source) 分组上的 min(first_seen) / max(confidence) /
-- 最新 last_seen,event_id）。该语句已改写为一次 "最新行 CROSS JOIN 聚合" 查询，与
-- inventory_contribution_latest 的 (endpoint_id,kind,value,source,last_seen DESC,event_id DESC)
-- 前缀完全匹配：最新行走索引有序取一行，min/max 在同前缀的索引范围内扫该分组（现场平均约 59 行、
-- 同端点分组物理相邻），代价可忽略。
--
-- 现场实测这三条语句的调用量只有约 0.4 次/秒（444,798 + 441,534 + 440,000 次覆盖数据库全生命周期），
-- 而索引维护发生在每次贡献行插入/替换上（现场 360 次/秒）：删掉三个索引即每秒少约 1,080 次索引写，
-- 并释放 first 1.15 GB + confidence 2.26 GB + ip 0.71 GB = 4.12 GB。
-- 保留：pkey（按 origin 整组替换，470 万次扫描）与 inventory_contribution_latest。
DROP INDEX IF EXISTS inventory_contribution_first;
DROP INDEX IF EXISTS inventory_contribution_confidence;
DROP INDEX IF EXISTS inventory_contribution_ip;
