-- Coalesce changes already covered by an unclaimed job. Do not move pending
-- endpoints to the back of the queue on each heartbeat. An active claim MUST
-- advance the generation so its completion cannot swallow a concurrent input.
CREATE OR REPLACE FUNCTION mark_endpoint_recognition_dirty(target_id text) RETURNS void AS $$
BEGIN
 IF target_id IS NULL OR target_id='' THEN RETURN; END IF;
 INSERT INTO endpoint_recognition_jobs(endpoint_id) VALUES(target_id)
 ON CONFLICT(endpoint_id) DO UPDATE SET
  dirty_generation=endpoint_recognition_jobs.dirty_generation+1,
  not_before=LEAST(endpoint_recognition_jobs.not_before,now()),
  updated_at=CASE WHEN endpoint_recognition_jobs.processed_generation<endpoint_recognition_jobs.dirty_generation
    THEN endpoint_recognition_jobs.updated_at ELSE now() END
 WHERE endpoint_recognition_jobs.processed_generation>=endpoint_recognition_jobs.dirty_generation
    OR endpoint_recognition_jobs.lease_until>clock_timestamp();
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION enqueue_endpoint_recognition_job() RETURNS trigger AS $$
BEGIN
 PERFORM mark_endpoint_recognition_dirty(CASE WHEN TG_OP='DELETE' THEN OLD.endpoint_id ELSE NEW.endpoint_id END);
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION enqueue_discovery_link_recognition_job() RETURNS trigger AS $$
DECLARE target_id text;
BEGIN
 FOR target_id IN
  SELECT DISTINCT changed.target_endpoint_id FROM (VALUES
   (CASE WHEN TG_OP='INSERT' THEN NULL ELSE OLD.endpoint_id END),
   (CASE WHEN TG_OP='DELETE' THEN NULL ELSE NEW.endpoint_id END)
  ) AS changed(target_endpoint_id)
  WHERE changed.target_endpoint_id IS NOT NULL AND changed.target_endpoint_id<>''
 LOOP
  PERFORM mark_endpoint_recognition_dirty(target_id);
 END LOOP;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;
