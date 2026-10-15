-- 终端识别脏标记（PG 迁移 137）等待终端实体存在后再入队。
--
-- endpoint_recognition_jobs.endpoint_id 外键引用 endpoint_entities。设备名称、域名证据等来源
-- 可能先于终端实体到达（stability1 起设备事件只由身份物化写入实体，router-pilot 物化落后时更
-- 常见），此时触发器插入作业违反外键，整个来源批次随之失败：现场 12 分钟 65 次。
--
-- 实体不存在时跳过入队不会丢失识别：endpoint_entities 上的 endpoint_recognition_entity_dirty
-- 触发器在实体首次写入时会为该终端入队，识别物化届时读取全部已到达的名称与证据。
CREATE OR REPLACE FUNCTION mark_endpoint_recognition_dirty(target_id text) RETURNS void AS $$
BEGIN
 IF target_id IS NULL OR target_id='' THEN RETURN; END IF;
 IF NOT EXISTS (SELECT 1 FROM endpoint_entities WHERE endpoint_id=target_id) THEN RETURN; END IF;
 INSERT INTO endpoint_recognition_jobs(endpoint_id) VALUES(target_id)
 ON CONFLICT(endpoint_id) DO UPDATE SET
  dirty_generation=endpoint_recognition_jobs.dirty_generation+1,
  lane=0,
  not_before=LEAST(endpoint_recognition_jobs.not_before,now()),
  updated_at=CASE WHEN endpoint_recognition_jobs.processed_generation<endpoint_recognition_jobs.dirty_generation THEN endpoint_recognition_jobs.updated_at ELSE now() END
 WHERE endpoint_recognition_jobs.processed_generation>=endpoint_recognition_jobs.dirty_generation
    OR endpoint_recognition_jobs.lease_until>clock_timestamp() OR endpoint_recognition_jobs.lane=1;
END;
$$ LANGUAGE plpgsql;
