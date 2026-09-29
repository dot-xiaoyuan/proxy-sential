CREATE SEQUENCE IF NOT EXISTS read_model_revision_v3_seq;

CREATE TABLE IF NOT EXISTS read_model_runtime_state (
 name TEXT PRIMARY KEY,
 state JSONB NOT NULL DEFAULT '{}'::jsonb,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS read_model_jobs (
 model TEXT NOT NULL,
 bucket_start TIMESTAMPTZ NOT NULL,
 sensor_id TEXT NOT NULL DEFAULT '',
 campus_id TEXT NOT NULL DEFAULT '',
 dirty_generation BIGINT NOT NULL DEFAULT 1,
 processed_generation BIGINT NOT NULL DEFAULT 0,
 not_before TIMESTAMPTZ NOT NULL DEFAULT now(),
 status TEXT NOT NULL DEFAULT 'pending',
 attempts INTEGER NOT NULL DEFAULT 0,
 lease_owner TEXT NOT NULL DEFAULT '',
 lease_until TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
 last_error TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(model,bucket_start,sensor_id,campus_id)
);

CREATE INDEX IF NOT EXISTS read_model_jobs_ready
ON read_model_jobs(model,status,not_before,bucket_start)
WHERE status IN ('pending','running');

CREATE TABLE IF NOT EXISTS endpoint_recognition_summary (
 endpoint_id TEXT PRIMARY KEY REFERENCES endpoint_entities(endpoint_id) ON DELETE CASCADE,
 brand TEXT NOT NULL DEFAULT '',
 model TEXT NOT NULL DEFAULT '',
 os_family TEXT NOT NULL DEFAULT '',
 role TEXT NOT NULL DEFAULT '',
 confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
 conflict BOOLEAN NOT NULL DEFAULT false,
 evidence_count INTEGER NOT NULL DEFAULT 0,
 rule_version TEXT NOT NULL DEFAULT '',
 summary JSONB NOT NULL DEFAULT '{}'::jsonb,
 first_seen TIMESTAMPTZ,
 last_seen TIMESTAMPTZ,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS endpoint_recognition_summary_brand
ON endpoint_recognition_summary(lower(brand),last_seen DESC);
CREATE INDEX IF NOT EXISTS endpoint_recognition_summary_os
ON endpoint_recognition_summary(lower(os_family),last_seen DESC);
CREATE INDEX IF NOT EXISTS endpoint_recognition_summary_role
ON endpoint_recognition_summary(role,last_seen DESC);

CREATE TABLE IF NOT EXISTS endpoint_recognition_jobs (
 endpoint_id TEXT PRIMARY KEY REFERENCES endpoint_entities(endpoint_id) ON DELETE CASCADE,
 dirty_generation BIGINT NOT NULL DEFAULT 1,
 processed_generation BIGINT NOT NULL DEFAULT 0,
 not_before TIMESTAMPTZ NOT NULL DEFAULT now(),
 attempts INTEGER NOT NULL DEFAULT 0,
 lease_owner TEXT NOT NULL DEFAULT '',
 lease_until TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
 last_error TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS endpoint_recognition_jobs_ready
ON endpoint_recognition_jobs(not_before,updated_at)
WHERE processed_generation < dirty_generation;

CREATE OR REPLACE FUNCTION enqueue_endpoint_recognition_job() RETURNS trigger AS $$
DECLARE target_id TEXT;
BEGIN
 target_id := CASE WHEN TG_OP='DELETE' THEN OLD.endpoint_id ELSE NEW.endpoint_id END;
 IF target_id IS NOT NULL AND target_id<>'' THEN
  INSERT INTO endpoint_recognition_jobs(endpoint_id)
  VALUES(target_id)
  ON CONFLICT(endpoint_id) DO UPDATE SET
   dirty_generation=endpoint_recognition_jobs.dirty_generation+1,
   not_before=LEAST(endpoint_recognition_jobs.not_before,now()),updated_at=now();
 END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS endpoint_recognition_entity_dirty ON endpoint_entities;
CREATE TRIGGER endpoint_recognition_entity_dirty
AFTER INSERT OR UPDATE ON endpoint_entities
FOR EACH ROW EXECUTE FUNCTION enqueue_endpoint_recognition_job();

DROP TRIGGER IF EXISTS endpoint_recognition_domain_dirty ON endpoint_domain_evidence_events;
CREATE TRIGGER endpoint_recognition_domain_dirty
AFTER INSERT OR UPDATE OR DELETE ON endpoint_domain_evidence_events
FOR EACH ROW EXECUTE FUNCTION enqueue_endpoint_recognition_job();

DROP TRIGGER IF EXISTS endpoint_recognition_name_dirty ON device_name_evidence;
CREATE TRIGGER endpoint_recognition_name_dirty
AFTER INSERT OR UPDATE OR DELETE ON device_name_evidence
FOR EACH ROW EXECUTE FUNCTION enqueue_endpoint_recognition_job();

INSERT INTO endpoint_recognition_jobs(endpoint_id)
SELECT endpoint_id FROM endpoint_entities WHERE entity_role='endpoint'
ON CONFLICT(endpoint_id) DO NOTHING;
