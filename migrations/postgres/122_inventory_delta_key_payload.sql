-- 投影增量队列（PG 迁移 122）只保留续读键，不再存整行 JSONB。
--
-- record_inventory_projection_delta 此前把变更行整体 to_jsonb 后写进
-- endpoint_inventory_projection_deltas：account_identity_session_projection 的行里
-- 带着完整会话 document，单条 payload 可达 1.5 KiB，670 MB 的队列表因此大部分是
-- 重复的文档内容；而唯一消费方 materializeInventoryDeltaTx 只反序列化
-- {source,event_id,session_id} 三个字段来重建 origin key，随后回源表重读事实。
--
-- 于是这些字节在写侧放大每一次身份写入，在读侧让每个 endpoint 的物化最多读 500 份
-- 完整 payload。这里把 payload 收窄到消费方真正读取的字段，语义不变：
--   * 观测类表（identity_ip_mac_history/identity_access_history/snapshot_facts）用 event_id；
--   * 会话类表（account_sessions/account_identity_session_projection）用 session_id；
--   * 标量类表（endpoint_entities/endpoint_recognition_summary/device_name_notes）的 payload
--     本就不被读取，收窄为空对象。
CREATE OR REPLACE FUNCTION record_inventory_projection_delta() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  body jsonb;
  endpoint text;
  event text;
BEGIN
  body := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
  endpoint := CASE
    WHEN TG_TABLE_NAME = 'account_identity_session_projection'
      THEN COALESCE(body->'document'->>'endpoint_id','')
    ELSE COALESCE(body->>'endpoint_id','')
  END;
  event := COALESCE(body->>'event_id', body->>'session_id', body->>'snapshot_id', '');
  IF endpoint <> '' THEN
    INSERT INTO endpoint_inventory_projection_deltas(endpoint_id,source_table,operation,event_id,payload)
    VALUES(endpoint,TG_TABLE_NAME,substr(TG_OP,1,1),event,
           jsonb_strip_nulls(jsonb_build_object(
             'source', body->>'source',
             'event_id', body->>'event_id',
             'session_id', body->>'session_id')));
  END IF;
  RETURN NULL;
END $$;
