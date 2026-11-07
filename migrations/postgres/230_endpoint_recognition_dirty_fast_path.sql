-- Repeated discovery links and name evidence mark the same endpoint dirty many
-- times per minute. The conflict branch below already skips the update when the
-- job is dirty and unleased, but PostgreSQL still locks the conflicting job row
-- to evaluate it, which lets the link batch, name evidence and the recognition
-- summary take endpoint job locks in different orders. Skip the upsert entirely
-- when the job is already dirty and waiting for a worker: the worker reads the
-- latest evidence when it runs, so no dirty generation is lost.
CREATE OR REPLACE FUNCTION mark_endpoint_recognition_dirty(target_id text)
RETURNS void
LANGUAGE plpgsql
AS $function$
BEGIN
 IF target_id IS NULL OR target_id='' THEN RETURN; END IF;
 IF NOT EXISTS (SELECT 1 FROM endpoint_entities WHERE endpoint_id=target_id) THEN RETURN; END IF;
 IF EXISTS (
  SELECT 1 FROM endpoint_recognition_jobs
  WHERE endpoint_id=target_id AND processed_generation<dirty_generation
    AND lease_until<clock_timestamp() AND lane=0
 ) THEN
  RETURN;
 END IF;
 INSERT INTO endpoint_recognition_jobs(endpoint_id) VALUES(target_id)
 ON CONFLICT(endpoint_id) DO UPDATE SET
  dirty_generation=endpoint_recognition_jobs.dirty_generation+1,
  lane=0,
  not_before=LEAST(endpoint_recognition_jobs.not_before,now()),
  updated_at=CASE WHEN endpoint_recognition_jobs.processed_generation<endpoint_recognition_jobs.dirty_generation THEN endpoint_recognition_jobs.updated_at ELSE now() END
 WHERE endpoint_recognition_jobs.processed_generation>=endpoint_recognition_jobs.dirty_generation
    OR endpoint_recognition_jobs.lease_until>clock_timestamp() OR endpoint_recognition_jobs.lane=1;
END;
$function$;
