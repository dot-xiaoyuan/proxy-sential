-- Reserve one bounded worker for library rebuilds; live evidence uses lane 0.
ALTER TABLE endpoint_recognition_jobs ADD COLUMN IF NOT EXISTS lane smallint NOT NULL DEFAULT 0 CHECK(lane IN (0,1));
CREATE INDEX IF NOT EXISTS endpoint_recognition_jobs_lane_ready ON endpoint_recognition_jobs(lane,updated_at,endpoint_id) WHERE processed_generation<dirty_generation;
CREATE OR REPLACE FUNCTION mark_endpoint_recognition_dirty(target_id text) RETURNS void AS $$
BEGIN
 IF target_id IS NULL OR target_id='' THEN RETURN; END IF;
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
