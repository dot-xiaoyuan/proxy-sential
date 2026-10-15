-- 库存投影认领（PG 迁移 136）改为纯按等待时长公平排序。
--
-- 原排序 (last_error<>''),(processed_generation>0) DESC,… 让从未完成过一轮的设备排在所有
-- 已投影设备之后；热点设备的 delta 持续到达，processed_generation 一直为 0，于是永远排在
-- 队尾（现场 45 个设备中位等待 38.7 小时，网关 MAC 积压 55.8 万条 delta）。
--
-- 新索引与认领 SQL 的 ORDER BY 完全一致，读取收益是认领保持索引有序扫描；写入成本与被替换
-- 的旧索引相同（同一部分谓词、少一列）；旧索引不再被任何查询使用，一并删除。
CREATE INDEX IF NOT EXISTS inventory_projection_claim_by_age ON endpoint_inventory_projection_jobs
 ((last_error<>''), COALESCE(pending_since,updated_at), endpoint_id) WHERE processed_generation<dirty_generation;
DROP INDEX IF EXISTS inventory_projection_fair_claim;
