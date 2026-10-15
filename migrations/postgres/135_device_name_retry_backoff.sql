-- 设备名称重试（PG 迁移 135）退避与索引。
--
-- RetryDeviceNames 每 15 秒按 processed_at 取 100 条未归属的 mDNS 名称重新解析。现场约
-- 1.46 万条名称永远无法归属，却被无限轮转；每条 mdns_service 又触发一次 mdnsServiceOwners，
-- 而 lower(value) 无索引，单条约 130ms 的并行全表扫描，10 秒预算每轮超时（3,661 次），
-- device_name_evidence 13.5 小时被顺序扫描 11.4 万次、读 147 亿元组。
--
-- retry_after/retry_attempts 让无法归属的名称按指数退避离开热轮转（上限 6 小时），新到的
-- DHCP 证据仍按地址立即重试。两个部分索引：
--   * device_name_retry_due：仅覆盖未归属的 mDNS 行（现场约 1.5 万行），读取收益是重试
--     选取从全表扫描变为索引范围读；写入成本只在未归属 mDNS 行上产生；随行删除失效。
--   * device_name_mdns_owner：仅覆盖 mdns_hostname 行，供 mdnsServiceOwners 按
--     (sensor_id, lower(value)) 精确查找；写入成本限于 mDNS 主机名插入与更新。
ALTER TABLE device_name_evidence ADD COLUMN IF NOT EXISTS retry_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE device_name_evidence ADD COLUMN IF NOT EXISTS retry_after timestamptz NOT NULL DEFAULT '-infinity';
CREATE INDEX IF NOT EXISTS device_name_retry_due ON device_name_evidence(retry_after,processed_at,event_id)
 WHERE source IN ('mdns_hostname','mdns_service') AND endpoint_id='';
CREATE INDEX IF NOT EXISTS device_name_mdns_owner ON device_name_evidence(sensor_id,lower(value),observed_at DESC)
 WHERE source='mdns_hostname';
