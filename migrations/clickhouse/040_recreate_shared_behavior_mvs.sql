-- 现场 2026-10-14 20:59:30 起，shared_behavior 这条链路的三个物化视图不再写入，
-- 导致 shared_behavior_signal_events_v1 停在那一刻（3,518,945 行）、
-- shared_behavior_device_model_events_v1 始终为 0 行，"信号 → 防代理结论"整段为空。
-- 源数据与归一化一直正常（router_signal_events_v1 每小时约 8.5 万条、packet-sidecar
-- 每小时约 108 万条），视图定义本身也是干净的。
--
-- 本迁移把现场最终生效的三段定义固化为可重放对象（先删后建，可在空库重跑）：
--   signal        取 028 的版本：ttl_path 门槛含 direction='unknown' AND neighbor_mac!=''，
--                 与现场实际流量一致（029 的 outbound-only 版本会永远匹配不到）。
--   device_model  取 030 的版本（名字虽为 device_model，目标表就是 signal_events，设计如此）。
--   index         取 031 的版本，从 signal_events 派生 device_model 相关行。
-- 注意：重建视图不会回填历史，2026-10-14 20:59:30 至重建时刻之间的 signal 行缺失，
-- 如需补齐，按 028 中同一段 INSERT ... SELECT 从 normalized_events 补写。
DROP VIEW IF EXISTS shared_behavior_device_model_index_v1_mv;
DROP VIEW IF EXISTS shared_behavior_device_model_events_v1_mv;
DROP VIEW IF EXISTS shared_behavior_signal_events_v1_mv;

CREATE MATERIALIZED VIEW shared_behavior_signal_events_v1_mv
TO shared_behavior_signal_events_v1 AS
SELECT timestamp,event_id,sensor_id,campus_id,
 JSONExtractString(payload_json,'access_domain') AS access_domain,
 subject_ip,source,
 JSONExtractString(observer_json,'collector_instance_id') AS collector_instance_id,
 feature.1 AS feature_family,feature.2 AS feature_value
FROM normalized_events
ARRAY JOIN arrayFilter(item -> item.2!='', [
 tuple('ua_os',multiIf(
  positionCaseInsensitiveUTF8(JSONExtractString(payload_json,'user_agent'),'android')>0,'Android',
  positionCaseInsensitiveUTF8(JSONExtractString(payload_json,'user_agent'),'iphone')>0 OR positionCaseInsensitiveUTF8(JSONExtractString(payload_json,'user_agent'),'ipad')>0,'iOS',
  positionCaseInsensitiveUTF8(JSONExtractString(payload_json,'user_agent'),'windows')>0,'Windows',
  positionCaseInsensitiveUTF8(JSONExtractString(payload_json,'user_agent'),'mac os')>0 OR positionCaseInsensitiveUTF8(JSONExtractString(payload_json,'user_agent'),'macintosh')>0,'macOS',
  positionCaseInsensitiveUTF8(JSONExtractString(payload_json,'user_agent'),'linux')>0,'Linux','')),
 tuple('ttl_path',if(source_event_type='ttl'
  AND JSONExtractInt(payload_json,'ttl') BETWEEN 1 AND 255
  AND (JSONExtractString(flow_json,'direction')='outbound'
   OR (JSONExtractString(flow_json,'direction')='unknown' AND JSONExtractString(payload_json,'neighbor_mac')!='')),
  concat('initial=',toString(multiIf(JSONExtractInt(payload_json,'ttl')<=32,32,JSONExtractInt(payload_json,'ttl')<=64,64,JSONExtractInt(payload_json,'ttl')<=128,128,255)),
   ',hops=',toString(multiIf(JSONExtractInt(payload_json,'ttl')<=32,32,JSONExtractInt(payload_json,'ttl')<=64,64,JSONExtractInt(payload_json,'ttl')<=128,128,255)-JSONExtractInt(payload_json,'ttl')),
   ',observed=',toString(JSONExtractInt(payload_json,'ttl'))),'')),
 tuple('tcp_stack',if(source_event_type='ttl',JSONExtractString(payload_json,'tcp_stack'),'')),
 tuple('tls_stack',if(JSONExtractString(payload_json,'ja4')!='',concat('ja4:',JSONExtractString(payload_json,'ja4')),if(JSONExtractString(payload_json,'ja3')!='',concat('ja3:',JSONExtractString(payload_json,'ja3')),''))),
 tuple('dhcp_stack',if(source_event_type='dhcp' AND JSONExtractString(payload_json,'requested_options')!='',
  hex(MD5(concat(JSONExtractString(payload_json,'vendor_class'),'|',JSONExtractString(payload_json,'requested_options')))),''))
]) AS feature
WHERE subject_ip!='';

CREATE MATERIALIZED VIEW IF NOT EXISTS shared_behavior_device_model_events_v1_mv
TO shared_behavior_signal_events_v1 AS
WITH
 JSONExtractString(payload_json,'user_agent') AS ua,
 multiIf(
  positionCaseInsensitiveUTF8(ua,'android')>0,
   extract(ua,'(?i)([A-Z0-9][A-Z0-9._-]{3,})[ ]+Build/'),
  match(ua,'iPhone[0-9]+,[0-9]+'),extract(ua,'(iPhone[0-9]+,[0-9]+)'),
  match(ua,'iPad[0-9]+,[0-9]+'),extract(ua,'(iPad[0-9]+,[0-9]+)'),
  '') AS hardware_model,
 multiIf(
  startsWith(hardware_model,'iPhone') OR startsWith(hardware_model,'iPad'),'Apple',
  positionCaseInsensitiveUTF8(ua,'honor')>0,'Honor',
  positionCaseInsensitiveUTF8(ua,'xiaomi')>0 OR positionCaseInsensitiveUTF8(ua,'redmi')>0,'Xiaomi',
  positionCaseInsensitiveUTF8(ua,'samsung')>0 OR startsWith(hardware_model,'GT-'),'Samsung',
  positionCaseInsensitiveUTF8(ua,'huawei')>0,'Huawei','') AS hardware_brand,
 if(startsWith(hardware_model,'iPhone') OR startsWith(hardware_model,'iPad'),'iOS','Android') AS os_family,
 if(startsWith(hardware_model,'iPad'),'tablet','mobile') AS device_type
SELECT timestamp,event_id,sensor_id,campus_id,
 JSONExtractString(payload_json,'access_domain') AS access_domain,
 subject_ip,source,
 JSONExtractString(observer_json,'collector_instance_id') AS collector_instance_id,
 'device_model' AS feature_family,
 concat(hardware_brand,'|',os_family,'|',device_type,'|',hardware_model) AS feature_value
FROM normalized_events
WHERE subject_ip!='' AND hardware_model!='';

CREATE MATERIALIZED VIEW IF NOT EXISTS shared_behavior_device_model_index_v1_mv
TO shared_behavior_device_model_events_v1 AS
SELECT timestamp,event_id,sensor_id,campus_id,access_domain,subject_ip,source,collector_instance_id,feature_value
FROM shared_behavior_signal_events_v1
WHERE feature_family='device_model' AND subject_ip!='' AND feature_value!='';
