-- A shared-access reader changes generations only after its file source has
-- an audited fresh cursor. Old pending jobs remain identifiable as canceled;
-- no historical event or cursor is marked processed by this switch.
CREATE TABLE stream_shared_source_cutovers (
 sensor_id text NOT NULL,
 source_owner text NOT NULL CHECK(source_owner IN ('handshake-sidecar','packet-sidecar')),
 epoch text NOT NULL,
 source_kind text NOT NULL DEFAULT 'device-signals' CHECK(source_kind='device-signals'),
 source_path text NOT NULL,
 scope_id text NOT NULL CHECK(scope_id<>''),
 source_cutoff_at timestamptz NOT NULL,
 cancel_id text NOT NULL,
 canceled_jobs bigint NOT NULL CHECK(canceled_jobs>=0),
 canceled_manifest_sha256 text NOT NULL CHECK(length(canceled_manifest_sha256)=64),
 state text NOT NULL CHECK(state IN ('prepared','active','closed')),
 activated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(sensor_id,source_owner,epoch),
 FOREIGN KEY(epoch,source_kind,source_path) REFERENCES stream_source_cutovers(epoch,source_kind,source_path)
);
CREATE UNIQUE INDEX stream_shared_one_active_source
 ON stream_shared_source_cutovers(sensor_id,source_owner) WHERE state='active';

CREATE TABLE stream_shared_canceled_jobs (
 sensor_id text NOT NULL,
 source_owner text NOT NULL,
 epoch text NOT NULL,
 job_kind text NOT NULL CHECK(job_kind IN ('ip','gateway')),
 job_id text NOT NULL,
 canceled_revision bigint NOT NULL,
 last_event_at timestamptz NOT NULL,
 dirty_since timestamptz NOT NULL,
 PRIMARY KEY(sensor_id,source_owner,epoch,job_kind,job_id),
 FOREIGN KEY(sensor_id,source_owner,epoch)
  REFERENCES stream_shared_source_cutovers(sensor_id,source_owner,epoch)
);

ALTER TABLE shared_observation_jobs ADD COLUMN canceled_epoch text NOT NULL DEFAULT '';
ALTER TABLE shared_gateway_observation_jobs ADD COLUMN canceled_epoch text NOT NULL DEFAULT '';
ALTER TABLE shared_observation_jobs ADD COLUMN generation_id text NOT NULL DEFAULT '';
ALTER TABLE shared_gateway_observation_jobs ADD COLUMN generation_id text NOT NULL DEFAULT '';
ALTER TABLE shared_capture_progress ADD COLUMN generation_id text NOT NULL DEFAULT '';
ALTER TABLE shared_behavior_observations ADD COLUMN generation_id text NOT NULL DEFAULT '';
CREATE INDEX shared_jobs_current_generation_pending ON shared_observation_jobs(sensor_id,generation_id,next_attempt_at,dirty_since,job_id)
 WHERE NOT expired AND canceled_epoch='';
CREATE INDEX shared_gateway_current_generation_pending ON shared_gateway_observation_jobs(sensor_id,generation_id,next_attempt_at,job_id)
 WHERE NOT expired AND canceled_epoch='';

-- The segment receipt and the affected work keys commit together. Replaying a
-- finalized segment may verify its immutable hash but cannot wake work twice.
CREATE TABLE stream_shared_segment_receipts (
 segment_id text PRIMARY KEY,
 epoch text NOT NULL,
 source_kind text NOT NULL DEFAULT 'device-signals' CHECK(source_kind='device-signals'),
 source_path text NOT NULL,
 source_owner text NOT NULL CHECK(source_owner IN ('handshake-sidecar','packet-sidecar')),
 segment_sha256 text NOT NULL CHECK(length(segment_sha256)=64),
 event_count integer NOT NULL CHECK(event_count>=0 AND event_count<=500),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(epoch,source_kind,source_path) REFERENCES stream_source_cutovers(epoch,source_kind,source_path)
);

CREATE TABLE stream_shared_case_evidence (
 case_id text NOT NULL REFERENCES risk_cases(case_id),
 epoch text NOT NULL,
 scope_id text NOT NULL,
 event_key text NOT NULL,
 content_sha256 text NOT NULL,
 body_ref jsonb NOT NULL,
 document text NOT NULL,
 captured_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(case_id,epoch,scope_id,event_key),
 CHECK(octet_length(document)<=4194304),
 CHECK(encode(sha256(convert_to(document,'UTF8')),'hex')=content_sha256),
 CHECK(jsonb_typeof(document::jsonb)='object')
);

CREATE FUNCTION sentinel_protect_stream_shared_case_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ref jsonb; saved stream_shared_case_evidence%ROWTYPE;
BEGIN
 IF NEW.evidence ? 'stream_shared_evidence_refs' THEN
  IF jsonb_typeof(NEW.evidence->'stream_shared_evidence_refs')<>'array'
   OR jsonb_array_length(NEW.evidence->'stream_shared_evidence_refs')>100
  THEN RAISE EXCEPTION 'invalid stream shared evidence references'; END IF;
  FOR ref IN SELECT value FROM jsonb_array_elements(NEW.evidence->'stream_shared_evidence_refs') LOOP
   IF jsonb_typeof(ref)<>'object' OR ref->>'class'<>'evidence'
    OR coalesce(ref->>'epoch','')='' OR coalesce(ref->>'scope','')=''
    OR coalesce(ref->>'key','')='' OR coalesce(ref->>'month','')=''
    OR coalesce(ref->>'sha256','')=''
   THEN RAISE EXCEPTION 'invalid stream shared evidence reference'; END IF;
   SELECT * INTO saved FROM stream_shared_case_evidence
    WHERE case_id=NEW.case_id AND epoch=ref->>'epoch'
     AND scope_id=ref->>'scope' AND event_key=ref->>'key';
   IF saved.document IS NULL OR saved.content_sha256<>ref->>'sha256'
    OR saved.body_ref<>ref OR encode(sha256(convert_to(saved.document,'UTF8')),'hex')<>saved.content_sha256
   THEN RAISE EXCEPTION 'stream shared original evidence unavailable'; END IF;
  END LOOP;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER protect_stream_shared_case_evidence
 AFTER INSERT OR UPDATE OF evidence ON risk_case_evidence_snapshots
 FOR EACH ROW EXECUTE FUNCTION sentinel_protect_stream_shared_case_evidence();

-- Identity changes may wake only the current source generation. These replace
-- old trigger bodies without rewriting already applied migration files.
CREATE OR REPLACE FUNCTION shared_wake_identity_ip() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE address inet; wake_mode text;
BEGIN
 BEGIN address:=NULLIF(NEW.session_data->>'ip','')::inet; EXCEPTION WHEN invalid_text_representation THEN RETURN NEW; END;
 IF address IS NULL THEN RETURN NEW; END IF;
 SELECT mode INTO wake_mode FROM shared_observation_wake_mode WHERE singleton;
 IF wake_mode IN ('shadow','async') AND EXISTS (
  SELECT 1 FROM shared_observation_jobs j WHERE j.ip=address AND NOT j.expired AND j.canceled_epoch=''
   AND j.generation_id=COALESCE((SELECT min(cancel_id) FROM stream_shared_source_cutovers c WHERE c.sensor_id=j.sensor_id AND c.state='active'),'')
   AND j.last_event_at>=now()-interval '1 hour' AND NEW.observed_at>=j.last_event_at-interval '10 minutes'
 ) THEN
  INSERT INTO shared_observation_wakes(kind,producer_mode,source,sensor_id,campus_id,access_domain,ip)
  VALUES('identity_ip',wake_mode,COALESCE(NEW.session_data->>'source',''),COALESCE(NEW.session_data->>'sensor_id',''),COALESCE(NEW.session_data->>'campus_id',''),COALESCE(NEW.session_data->>'access_domain',''),address);
 END IF;
 IF wake_mode <> 'async' THEN
  UPDATE shared_observation_jobs j SET revision=j.revision+1,next_attempt_at=now(),last_dependency_at=clock_timestamp(),
   dirty_since=CASE WHEN j.revision=j.completed_revision THEN now() ELSE j.dirty_since END
  WHERE j.ip=address AND NOT j.expired AND j.canceled_epoch=''
   AND j.generation_id=COALESCE((SELECT min(cancel_id) FROM stream_shared_source_cutovers c WHERE c.sensor_id=j.sensor_id AND c.state='active'),'')
   AND NEW.observed_at>=j.last_event_at-interval '10 minutes'
   AND EXISTS(SELECT 1 FROM shared_observation_mappings m WHERE m.active AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain
    AND m.identity_source=NEW.session_data->>'source' AND m.identity_sensor_id=NEW.session_data->>'sensor_id'
    AND m.identity_campus_id=NEW.session_data->>'campus_id' AND m.identity_access_domain=NEW.session_data->>'access_domain'
    AND m.valid_from<=j.last_event_at AND m.valid_until>j.last_event_at);
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION shared_wake_snapshot_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE wake_mode text;
BEGIN
 SELECT mode INTO wake_mode FROM shared_observation_wake_mode WHERE singleton;
 IF TG_TABLE_NAME='shared_identity_snapshot_indexes' AND wake_mode='async' THEN RETURN NEW; END IF;
 IF wake_mode IN ('shadow','async') THEN
  INSERT INTO shared_observation_wakes(kind,producer_mode,source,sensor_id,campus_id,access_domain,covered_to)
  VALUES('snapshot_scope',wake_mode,NEW.source,NEW.sensor_id,NEW.campus_id,NEW.access_domain,NEW.observed_at);
 END IF;
 IF wake_mode <> 'async' THEN
  UPDATE shared_observation_jobs j SET revision=j.revision+1,next_attempt_at=now(),last_dependency_at=clock_timestamp(),
   dirty_since=CASE WHEN j.revision=j.completed_revision THEN now() ELSE j.dirty_since END
  WHERE NOT j.expired AND j.canceled_epoch=''
   AND j.generation_id=COALESCE((SELECT min(cancel_id) FROM stream_shared_source_cutovers c WHERE c.sensor_id=j.sensor_id AND c.state='active'),'')
   AND EXISTS(SELECT 1 FROM shared_observation_mappings m WHERE m.active
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
  WHERE NOT j.expired AND j.canceled_epoch=''
   AND j.generation_id=COALESCE((SELECT min(cancel_id) FROM stream_shared_source_cutovers c WHERE c.sensor_id=j.sensor_id AND c.state='active'),'')
   AND EXISTS(SELECT 1 FROM shared_observation_mappings m WHERE m.active AND m.health_bridge_id=NEW.bridge_id
    AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain
    AND m.valid_from<=j.last_event_at AND m.valid_until>j.last_event_at);
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION shared_wake_capture_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE changed boolean := false; wake_mode text; previous_to timestamptz;
BEGIN
 IF TG_OP='UPDATE' THEN
  changed:=NEW.complete IS DISTINCT FROM OLD.complete OR NEW.covered_from<OLD.covered_from;
  previous_to:=OLD.covered_to;
 END IF;
 SELECT mode INTO wake_mode FROM shared_observation_wake_mode WHERE singleton;
 IF wake_mode IN ('shadow','async') AND EXISTS (
  SELECT 1 FROM shared_observation_jobs j WHERE j.sensor_id=NEW.sensor_id AND j.campus_id=NEW.campus_id
   AND j.access_domain=NEW.access_domain AND NOT j.expired AND j.canceled_epoch=''
   AND j.generation_id=COALESCE((SELECT min(cancel_id) FROM stream_shared_source_cutovers c WHERE c.sensor_id=j.sensor_id AND c.state='active'),'')
   AND j.last_event_at>=now()-interval '1 hour'
   AND (changed OR (j.coverage_state<>'verified' AND j.last_event_at>COALESCE(previous_to,NEW.covered_from)
    AND j.last_event_at<=NEW.covered_to))
 ) THEN
  INSERT INTO shared_observation_wakes(kind,producer_mode,sensor_id,campus_id,access_domain,force_all,covered_to,previous_covered_to)
  VALUES('capture_scope',wake_mode,NEW.sensor_id,NEW.campus_id,NEW.access_domain,changed,NEW.covered_to,COALESCE(previous_to,NEW.covered_from));
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION shared_wake_identity_stream_batch(batch jsonb) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE wake_mode text;
BEGIN
 SELECT mode INTO wake_mode FROM shared_observation_wake_mode WHERE singleton;
 IF wake_mode IN ('shadow','async') THEN
  INSERT INTO shared_observation_wakes(kind,producer_mode,source,sensor_id,campus_id,access_domain,ip)
  SELECT DISTINCT 'identity_ip',wake_mode,
   COALESCE(r.session_data->>'source',''),COALESCE(r.session_data->>'sensor_id',''),
   COALESCE(r.session_data->>'campus_id',''),COALESCE(r.session_data->>'access_domain',''),
   shared_identity_stream_inet(r.session_data->>'ip')
  FROM jsonb_to_recordset(batch) r(session_data jsonb,observed_at timestamptz)
  JOIN shared_observation_jobs j ON j.ip=shared_identity_stream_inet(r.session_data->>'ip')
   AND NOT j.expired AND j.canceled_epoch=''
   AND j.generation_id=COALESCE((SELECT min(cancel_id) FROM stream_shared_source_cutovers c WHERE c.sensor_id=j.sensor_id AND c.state='active'),'')
   AND j.last_event_at>=now()-interval '1 hour'
   AND r.observed_at>=j.last_event_at-interval '10 minutes';
 END IF;
 IF wake_mode<>'async' THEN
  UPDATE shared_observation_jobs j SET revision=j.revision+1,next_attempt_at=now(),
   last_dependency_at=clock_timestamp(),
   dirty_since=CASE WHEN j.revision=j.completed_revision THEN now() ELSE j.dirty_since END
  FROM (
   SELECT DISTINCT shared_identity_stream_inet(r.session_data->>'ip') AS ip,
    r.session_data->>'source' AS source,r.session_data->>'sensor_id' AS sensor_id,
    r.session_data->>'campus_id' AS campus_id,r.session_data->>'access_domain' AS access_domain,
    max(r.observed_at) AS observed_at
   FROM jsonb_to_recordset(batch) r(session_data jsonb,observed_at timestamptz)
   GROUP BY 1,2,3,4,5
  ) changed
  WHERE j.ip=changed.ip AND NOT j.expired AND j.canceled_epoch=''
   AND j.generation_id=COALESCE((SELECT min(cancel_id) FROM stream_shared_source_cutovers c WHERE c.sensor_id=j.sensor_id AND c.state='active'),'')
   AND changed.observed_at>=j.last_event_at-interval '10 minutes'
   AND EXISTS(SELECT 1 FROM shared_observation_mappings m WHERE m.active
    AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain
    AND m.identity_source=changed.source AND m.identity_sensor_id=changed.sensor_id
    AND m.identity_campus_id=changed.campus_id AND m.identity_access_domain=changed.access_domain
    AND m.valid_from<=j.last_event_at AND m.valid_until>j.last_event_at);
 END IF;
END $$;
