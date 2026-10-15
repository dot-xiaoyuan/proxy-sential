-- 路由观测列表（/router-observations → ListRouterObservations）的排序/分区键是逐行计算的表达式：
--   device_key = CASE WHEN mac<>'' THEN 'mac:'||lower(mac)
--                     WHEN endpoint_id<>'' THEN 'endpoint:'||endpoint_id
--                     WHEN ip IS NOT NULL THEN 'ip:'||host(ip)||':vlans:'||array_to_string(vlans,',')
--                     ELSE 'assessment:'||assessment_id END
--   rank 顺序  = CASE status WHEN 'confirmed' THEN 3 WHEN 'likely' THEN 2 ELSE 1 END DESC, confidence DESC, …
--
-- 现场实测（router_assessments 33,020 行 / 147 MB，无筛选最坏情况）：
--   改写前约 1.29 秒，并产生约 140 MB 落盘临时文件（temp read=17,945 written=12,897），磁盘饱和时
--   表现为"网络设备页签点了转圈到超时"；第 77 轮把窗口函数改成只排窄列后（发布
--   2026.10.15-routerlist1）落盘归零、总耗时约 0.54 秒，但计划显示剩余成本仍在"内存内窗口+排序"
--   （Nested Loop 外层 actual 528 ms；33k 行 500 ms ≈ 15 µs/行），逐行重建 device_key 文本与多次
--   排序是余下成本。把两个键固化为生成列并加索引后，查询侧可用 DISTINCT ON 直接走索引有序扫描。
--
-- 为什么需要辅助函数：生成列只接受 immutable 表达式，而 array_to_string(anyarray,text) 在
-- PostgreSQL 里按签名是 STABLE（泛型元素的输出函数无法保证 immutable），现场实测：
--   lower(mac COLLATE "C")、host(ip)、ip::text、CASE status … → 均可作生成列 ✓
--   array_to_string(vlans,',')、vlans::text                          → 报 "generation expression is not immutable" ✗
-- 这三个表达式在给定输入下完全确定，因此用声明为 IMMUTABLE 的 SQL 函数包住整段 key 计算：
-- 键的文本形态与原先逐字一致（现场已用真实数据验证生成结果形如 mac:46:b7:45:aa:de:4c），
-- 分组/去重语义不变。
CREATE OR REPLACE FUNCTION sentinel_router_device_key(
  mac text, endpoint_id text, ip inet, vlans text[], assessment_id text)
RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $fn$
 SELECT CASE WHEN mac<>'' THEN 'mac:'||lower(mac COLLATE "C")
             WHEN endpoint_id<>'' THEN 'endpoint:'||endpoint_id
             WHEN ip IS NOT NULL THEN 'ip:'||host(ip)||':vlans:'||array_to_string(vlans,',')
             ELSE 'assessment:'||assessment_id END
$fn$;

ALTER TABLE router_assessments
  ADD COLUMN IF NOT EXISTS device_key text GENERATED ALWAYS AS (
    sentinel_router_device_key(mac, endpoint_id, ip, vlans, assessment_id)) STORED,
  ADD COLUMN IF NOT EXISTS status_rank smallint GENERATED ALWAYS AS (
    CASE status WHEN 'confirmed' THEN 3 WHEN 'likely' THEN 2 ELSE 1 END) STORED;

CREATE INDEX IF NOT EXISTS router_assessment_device_rank ON router_assessments
  (device_key, status_rank DESC, confidence DESC, last_seen DESC, assessment_id);
