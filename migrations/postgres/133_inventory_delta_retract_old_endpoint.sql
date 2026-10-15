-- 投影增量队列（PG 迁移 133）恢复旧端点的撤销通知。
--
-- 迁移 111 在源行 endpoint_id 改变时，会为旧端点补写一条 D 型 delta；迁移 122
-- 收窄 payload 时连这个分支一起删掉了。结果是源行改归属后，旧端点只被标脏而拿不到
-- delta，materializeInventoryDeltaTx 不会为它重读这个 origin，旧 contributions 永远
-- 不会被撤销，更正和撤销在投影里丢失。
--
-- 这里保留 122 的窄 payload，只把旧端点分支加回来：旧端点收到同一 origin 的续读键，
-- 消费方回源表重读后发现事实已不归它，于是删除对应 contributions。
CREATE OR REPLACE FUNCTION record_inventory_projection_delta() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  body jsonb;
  previous jsonb;
  endpoint text;
  old_endpoint text;
  event text;
BEGIN
  IF TG_OP <> 'INSERT' THEN previous := to_jsonb(OLD); END IF;
  body := CASE WHEN TG_OP = 'DELETE' THEN previous ELSE to_jsonb(NEW) END;
  endpoint := CASE
    WHEN TG_TABLE_NAME = 'account_identity_session_projection'
      THEN COALESCE(body->'document'->>'endpoint_id','')
    ELSE COALESCE(body->>'endpoint_id','')
  END;
  old_endpoint := CASE
    WHEN TG_TABLE_NAME = 'account_identity_session_projection'
      THEN COALESCE(previous->'document'->>'endpoint_id','')
    ELSE COALESCE(previous->>'endpoint_id','')
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
  IF old_endpoint <> '' AND old_endpoint IS DISTINCT FROM endpoint THEN
    INSERT INTO endpoint_inventory_projection_deltas(endpoint_id,source_table,operation,event_id,payload)
    VALUES(old_endpoint,TG_TABLE_NAME,'D',
           COALESCE(previous->>'event_id', previous->>'session_id', previous->>'snapshot_id', ''),
           jsonb_strip_nulls(jsonb_build_object(
             'source', previous->>'source',
             'event_id', previous->>'event_id',
             'session_id', previous->>'session_id')));
  END IF;
  RETURN NULL;
END $$;
