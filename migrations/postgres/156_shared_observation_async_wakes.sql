-- The installed application keeps its original trigger behavior until the operator switches mode.
SET LOCAL lock_timeout = '5s';

CREATE TABLE shared_observation_wake_mode (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 mode text NOT NULL DEFAULT 'legacy' CHECK (mode IN ('legacy','shadow','async')),
 changed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO shared_observation_wake_mode(singleton,mode) VALUES(true,'legacy');

CREATE TABLE shared_observation_wakes (
 wake_id bigserial PRIMARY KEY,
 kind text NOT NULL CHECK (kind IN ('identity_ip','snapshot_scope','snapshot_ip','health_scope','capture_scope')),
 producer_mode text NOT NULL DEFAULT 'legacy' CHECK (producer_mode IN ('legacy','shadow','async')),
 source text NOT NULL DEFAULT '', sensor_id text NOT NULL DEFAULT '', campus_id text NOT NULL DEFAULT '',
 access_domain text NOT NULL DEFAULT '', bridge_id text NOT NULL DEFAULT '', ip inet,
 force_all boolean NOT NULL DEFAULT false,
 origin_xid bigint NOT NULL DEFAULT txid_current(),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 cursor_job_id text NOT NULL DEFAULT '', processed_at timestamptz,
 matched_jobs bigint NOT NULL DEFAULT 0, applied_jobs bigint NOT NULL DEFAULT 0
);
CREATE INDEX shared_observation_wakes_pending ON shared_observation_wakes(wake_id) WHERE processed_at IS NULL;
CREATE INDEX shared_observation_wakes_retention ON shared_observation_wakes(processed_at,wake_id) WHERE processed_at IS NOT NULL;
CREATE INDEX shared_observation_wakes_origin ON shared_observation_wakes(origin_xid,kind);

ALTER TABLE shared_observation_jobs ADD COLUMN lease_token text NOT NULL DEFAULT '';
ALTER TABLE shared_observation_jobs ADD COLUMN lease_until timestamptz;
ALTER TABLE shared_observation_jobs ADD COLUMN last_dependency_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE shared_observation_jobs ADD COLUMN last_decision_latency_ms bigint;
CREATE INDEX shared_jobs_identity_ip ON shared_observation_jobs(ip,last_event_at) WHERE NOT expired;

CREATE OR REPLACE FUNCTION shared_wake_identity_ip() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE address inet; wake_mode text;
BEGIN
 BEGIN address:=NULLIF(NEW.session_data->>'ip','')::inet; EXCEPTION WHEN invalid_text_representation THEN RETURN NEW; END;
 IF address IS NULL THEN RETURN NEW; END IF;
 SELECT mode INTO wake_mode FROM shared_observation_wake_mode WHERE singleton;
 IF wake_mode IN ('shadow','async') AND EXISTS (
  SELECT 1 FROM shared_observation_jobs j WHERE j.ip=address AND NOT j.expired
   AND j.last_event_at>=now()-interval '1 hour' AND NEW.observed_at>=j.last_event_at-interval '10 minutes'
 ) THEN
  INSERT INTO shared_observation_wakes(kind,producer_mode,source,sensor_id,campus_id,access_domain,ip)
  VALUES('identity_ip',wake_mode,COALESCE(NEW.session_data->>'source',''),COALESCE(NEW.session_data->>'sensor_id',''),COALESCE(NEW.session_data->>'campus_id',''),COALESCE(NEW.session_data->>'access_domain',''),address);
 END IF;
 IF wake_mode <> 'async' THEN
  UPDATE shared_observation_jobs j SET revision=j.revision+1,next_attempt_at=now(),last_dependency_at=clock_timestamp(),
   dirty_since=CASE WHEN j.revision=j.completed_revision THEN now() ELSE j.dirty_since END
  WHERE j.ip=address AND NOT j.expired AND NEW.observed_at>=j.last_event_at-interval '10 minutes'
  AND EXISTS(SELECT 1 FROM shared_observation_mappings m WHERE m.active AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain
   AND m.identity_source=NEW.session_data->>'source' AND m.identity_sensor_id=NEW.session_data->>'sensor_id'
   AND m.identity_campus_id=NEW.session_data->>'campus_id' AND m.identity_access_domain=NEW.session_data->>'access_domain'
   AND m.valid_from<=j.last_event_at AND m.valid_until>j.last_event_at);
 END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION shared_wake_capture_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE changed boolean := false; wake_mode text;
BEGIN
 IF TG_OP='UPDATE' THEN changed:=NEW.complete IS DISTINCT FROM OLD.complete; END IF;
 SELECT mode INTO wake_mode FROM shared_observation_wake_mode WHERE singleton;
 IF wake_mode IN ('shadow','async') AND EXISTS (
  SELECT 1 FROM shared_observation_jobs j WHERE j.sensor_id=NEW.sensor_id AND j.campus_id=NEW.campus_id
   AND j.access_domain=NEW.access_domain AND NOT j.expired AND j.last_event_at>=now()-interval '1 hour'
   AND (changed OR j.coverage_state<>'verified')
 ) THEN
  INSERT INTO shared_observation_wakes(kind,producer_mode,sensor_id,campus_id,access_domain,force_all)
  VALUES('capture_scope',wake_mode,NEW.sensor_id,NEW.campus_id,NEW.access_domain,changed);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER shared_capture_scope_changed AFTER INSERT OR UPDATE ON shared_capture_progress
 FOR EACH ROW EXECUTE FUNCTION shared_wake_capture_scope();

CREATE OR REPLACE FUNCTION shared_wake_snapshot_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE wake_mode text;
BEGIN
 SELECT mode INTO wake_mode FROM shared_observation_wake_mode WHERE singleton;
 -- The index is written before projection. Only the projected log is authoritative
 -- in async mode; legacy keeps the installed trigger behavior until cutover.
 IF TG_TABLE_NAME='shared_identity_snapshot_indexes' AND wake_mode='async' THEN RETURN NEW; END IF;
 IF wake_mode IN ('shadow','async') THEN
  INSERT INTO shared_observation_wakes(kind,producer_mode,source,sensor_id,campus_id,access_domain)
  VALUES('snapshot_scope',wake_mode,NEW.source,NEW.sensor_id,NEW.campus_id,NEW.access_domain);
 END IF;
 IF wake_mode <> 'async' THEN
  UPDATE shared_observation_jobs j SET revision=j.revision+1,next_attempt_at=now(),last_dependency_at=clock_timestamp(),
   dirty_since=CASE WHEN j.revision=j.completed_revision THEN now() ELSE j.dirty_since END
  WHERE NOT j.expired AND EXISTS(SELECT 1 FROM shared_observation_mappings m WHERE m.active
   AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain
   AND m.identity_source=NEW.source AND m.identity_sensor_id=NEW.sensor_id AND m.identity_campus_id=NEW.campus_id AND m.identity_access_domain=NEW.access_domain
   AND m.valid_from<=j.last_event_at AND m.valid_until>j.last_event_at);
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION shared_wake_health_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE wake_mode text;
BEGIN
 SELECT mode INTO wake_mode FROM shared_observation_wake_mode WHERE singleton;
 IF wake_mode IN ('shadow','async') THEN
  INSERT INTO shared_observation_wakes(kind,producer_mode,bridge_id) VALUES('health_scope',wake_mode,NEW.bridge_id);
 END IF;
 IF wake_mode <> 'async' THEN
  UPDATE shared_observation_jobs j SET revision=j.revision+1,next_attempt_at=now(),last_dependency_at=clock_timestamp(),
   dirty_since=CASE WHEN j.revision=j.completed_revision THEN now() ELSE j.dirty_since END
  WHERE NOT j.expired AND EXISTS(SELECT 1 FROM shared_observation_mappings m WHERE m.active AND m.health_bridge_id=NEW.bridge_id
   AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain
   AND m.valid_from<=j.last_event_at AND m.valid_until>j.last_event_at);
 END IF;
 RETURN NEW;
END $$;
