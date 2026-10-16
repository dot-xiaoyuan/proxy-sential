-- Transient per-IP work, updated only by arriving observations. A failed attempt
-- never advances completion. First receipt is preserved across ingestion retries.
CREATE TABLE shared_observation_jobs (
 job_id text PRIMARY KEY, sensor_id text NOT NULL,campus_id text NOT NULL,access_domain text NOT NULL,ip inet NOT NULL,
 revision bigint NOT NULL DEFAULT 1,completed_revision bigint NOT NULL DEFAULT 0,
 first_received_at timestamptz NOT NULL DEFAULT now(),dirty_since timestamptz NOT NULL DEFAULT now(),
 last_event_at timestamptz NOT NULL,last_received_at timestamptz NOT NULL DEFAULT now(),
 next_attempt_at timestamptz NOT NULL DEFAULT now(),attempts integer NOT NULL DEFAULT 0,
 last_error text NOT NULL DEFAULT '',completed_at timestamptz,expired boolean NOT NULL DEFAULT false,
 UNIQUE(sensor_id,campus_id,access_domain,ip)
);
CREATE INDEX shared_observation_jobs_pending ON shared_observation_jobs(next_attempt_at,dirty_since,job_id) WHERE NOT expired;
ALTER TABLE policy_decision_records ADD COLUMN trigger_type text NOT NULL DEFAULT '';
ALTER TABLE policy_decision_records ADD COLUMN subject_ip inet;
ALTER TABLE policy_decision_records ADD COLUMN result text NOT NULL DEFAULT '';
ALTER TABLE policy_decision_records ADD COLUMN observation_id text NOT NULL DEFAULT '';
ALTER TABLE policy_decision_records ADD COLUMN evidence_version text NOT NULL DEFAULT '';
ALTER TABLE policy_decision_records ADD COLUMN first_received_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX policy_decisions_shared_time ON policy_decision_records(trigger_type,result,evaluated_at DESC,decision_id DESC);
CREATE INDEX policy_decisions_ip_time ON policy_decision_records(subject_ip,evaluated_at DESC,decision_id DESC);
CREATE INDEX policy_decisions_observation ON policy_decision_records(observation_id,evaluated_at DESC,decision_id DESC);
CREATE INDEX policy_identity_ip_scope_time ON policy_identity_observations
 ((session_data->>'source'),(session_data->>'sensor_id'),(session_data->>'campus_id'),(session_data->>'access_domain'),(session_data->>'ip'),observed_at,event_id);
-- Current generation lookup is a health check, never a replacement for history.
CREATE INDEX identity_current_ip ON identity_current_addresses(scope_key,generation,ip);
-- IP-addressable snapshot members avoid loading entire authentication inventories
-- for a sharing window. Older snapshots are not treated as indexed implicitly.
CREATE TABLE shared_identity_snapshot_indexes (
 source text NOT NULL,sensor_id text NOT NULL,campus_id text NOT NULL,access_domain text NOT NULL,snapshot_id text NOT NULL,
 observed_at timestamptz NOT NULL,received_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(source,sensor_id,campus_id,access_domain,snapshot_id)
);
CREATE TABLE shared_identity_snapshot_members (
 source text NOT NULL,sensor_id text NOT NULL,campus_id text NOT NULL,access_domain text NOT NULL,snapshot_id text NOT NULL,
 ip inet NOT NULL,session_id text NOT NULL,document jsonb NOT NULL,received_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(source,sensor_id,campus_id,access_domain,ip,snapshot_id,session_id)
);
ALTER TABLE shared_observation_jobs ADD COLUMN last_document jsonb;
CREATE TABLE shared_observation_executions (
 execution_id text PRIMARY KEY,account_id text NOT NULL,evidence_version text NOT NULL,
 state text NOT NULL CHECK(state IN ('recorded','expired')),document jsonb NOT NULL,
 expires_at timestamptz NOT NULL,
 first_received_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX shared_observation_execution_expiry ON shared_observation_executions(expires_at,execution_id) WHERE state='recorded';
-- Event-time bridge health, including heartbeat gaps. Never backdate new proof.
CREATE TABLE shared_identity_health_intervals (
 bridge_id text NOT NULL,valid_from timestamptz NOT NULL,valid_to timestamptz,
 healthy boolean NOT NULL,PRIMARY KEY(bridge_id,valid_from)
);
CREATE UNIQUE INDEX shared_identity_health_open ON shared_identity_health_intervals(bridge_id) WHERE valid_to IS NULL;
CREATE FUNCTION shared_record_identity_health() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE healthy_now boolean; old_healthy boolean; begin_at timestamptz; gap_at timestamptz;
BEGIN
 healthy_now := NEW.state='healthy' AND NEW.event_consecutive_failures=0 AND NEW.snapshot_consecutive_failures=0;
 SELECT healthy,valid_from INTO old_healthy,begin_at FROM shared_identity_health_intervals WHERE bridge_id=NEW.bridge_id AND valid_to IS NULL;
 IF TG_OP='UPDATE' AND NEW.heartbeat_at>OLD.heartbeat_at+interval '60 seconds' THEN
  gap_at:=GREATEST(OLD.heartbeat_at+interval '60 seconds',COALESCE(begin_at,OLD.heartbeat_at));
  UPDATE shared_identity_health_intervals SET valid_to=gap_at WHERE bridge_id=NEW.bridge_id AND valid_to IS NULL;
  INSERT INTO shared_identity_health_intervals VALUES(NEW.bridge_id,gap_at,NEW.heartbeat_at,false) ON CONFLICT DO NOTHING;
  begin_at:=NULL;
 ELSIF begin_at IS NOT NULL AND old_healthy IS DISTINCT FROM healthy_now THEN
  UPDATE shared_identity_health_intervals SET valid_to=now() WHERE bridge_id=NEW.bridge_id AND valid_to IS NULL;
  begin_at:=NULL;
 END IF;
 IF begin_at IS NULL THEN INSERT INTO shared_identity_health_intervals VALUES(NEW.bridge_id,now(),NULL,healthy_now) ON CONFLICT DO NOTHING; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER shared_identity_health AFTER INSERT OR UPDATE ON identity_bridge_runtime FOR EACH ROW EXECUTE FUNCTION shared_record_identity_health();
CREATE INDEX shared_decision_archive_candidates ON policy_decision_records(first_received_at,decision_id) WHERE trigger_type='shared_access';
CREATE TABLE shared_observation_archive_receipts (
 decision_id text PRIMARY KEY,observation_id text NOT NULL,content_hash text NOT NULL,
 first_received_at timestamptz NOT NULL,verified_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX shared_archive_observation ON shared_observation_archive_receipts(observation_id,verified_at DESC);
ALTER TABLE shared_observation_jobs ADD COLUMN last_result text NOT NULL DEFAULT '';
ALTER TABLE shared_observation_jobs ADD COLUMN coverage_state text NOT NULL DEFAULT '';
ALTER TABLE shared_observation_jobs ADD COLUMN attribution_state text NOT NULL DEFAULT '';
CREATE INDEX shared_jobs_pending_visibility ON shared_observation_jobs(dirty_since,job_id) WHERE revision>completed_revision AND NOT expired;
CREATE INDEX shared_jobs_ip_visibility ON shared_observation_jobs(ip,dirty_since,job_id) WHERE revision>completed_revision AND NOT expired;
-- L2 associations have no trustworthy source IP. Resolve only their own MAC's
-- lease in a separate durable task, never from forwarded IP packets.
CREATE TABLE shared_gateway_observation_jobs (
 job_id text PRIMARY KEY,sensor_id text NOT NULL,campus_id text NOT NULL,access_domain text NOT NULL,gateway_mac text NOT NULL,
 revision bigint NOT NULL DEFAULT 1,completed_revision bigint NOT NULL DEFAULT 0,
 last_event_at timestamptz NOT NULL,first_received_at timestamptz NOT NULL DEFAULT now(),dirty_since timestamptz NOT NULL DEFAULT now(),
 next_attempt_at timestamptz NOT NULL DEFAULT now(),last_error text NOT NULL DEFAULT '',
 resolved_ip inet,expired boolean NOT NULL DEFAULT false,
 UNIQUE(sensor_id,campus_id,access_domain,gateway_mac)
);
CREATE INDEX shared_gateway_jobs_pending ON shared_gateway_observation_jobs(next_attempt_at,job_id) WHERE NOT expired;
CREATE INDEX shared_gateway_jobs_ip ON shared_gateway_observation_jobs(sensor_id,campus_id,access_domain,resolved_ip,last_event_at);
CREATE TABLE shared_capture_progress (
 sensor_id text NOT NULL,campus_id text NOT NULL,access_domain text NOT NULL,source text NOT NULL,collector_instance_id text NOT NULL,
 covered_from timestamptz NOT NULL,covered_to timestamptz NOT NULL,complete boolean NOT NULL,document jsonb NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(sensor_id,campus_id,access_domain,source,collector_instance_id)
);
CREATE INDEX shared_capture_progress_current ON shared_capture_progress(sensor_id,campus_id,access_domain,source,covered_to DESC);
-- Only configured capture/auth mappings may wake a current IP after identity
-- changes. These are query indexes and scheduling metadata, not identity facts.
CREATE TABLE shared_observation_mappings (
 config_version text NOT NULL,sensor_id text NOT NULL,campus_id text NOT NULL,access_domain text NOT NULL,
 identity_source text NOT NULL,identity_sensor_id text NOT NULL,identity_campus_id text NOT NULL,identity_access_domain text NOT NULL,
 valid_from timestamptz NOT NULL,valid_until timestamptz NOT NULL,health_bridge_id text NOT NULL DEFAULT '',active boolean NOT NULL DEFAULT true,
 PRIMARY KEY(config_version,sensor_id,campus_id,access_domain,valid_from)
);
CREATE INDEX shared_observation_mapping_authority ON shared_observation_mappings(identity_source,identity_sensor_id,identity_campus_id,identity_access_domain) WHERE active;
CREATE FUNCTION shared_wake_identity_ip() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE address inet;
BEGIN
 BEGIN address:=NULLIF(NEW.session_data->>'ip','')::inet; EXCEPTION WHEN invalid_text_representation THEN RETURN NEW; END;
 IF address IS NULL THEN RETURN NEW; END IF;
 UPDATE shared_observation_jobs j SET revision=j.revision+1,next_attempt_at=now(),
 dirty_since=CASE WHEN j.revision=j.completed_revision THEN now() ELSE j.dirty_since END
 WHERE j.ip=address AND NOT j.expired AND NEW.observed_at>=j.last_event_at-interval '10 minutes'
 AND EXISTS(SELECT 1 FROM shared_observation_mappings m WHERE m.active AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain
 AND m.identity_source=NEW.session_data->>'source' AND m.identity_sensor_id=NEW.session_data->>'sensor_id'
 AND m.identity_campus_id=NEW.session_data->>'campus_id' AND m.identity_access_domain=NEW.session_data->>'access_domain'
 AND m.valid_from<=j.last_event_at AND m.valid_until>j.last_event_at);
 RETURN NEW;
END $$;
CREATE TRIGGER shared_identity_ip_changed AFTER INSERT ON policy_identity_observations FOR EACH ROW EXECUTE FUNCTION shared_wake_identity_ip();
CREATE FUNCTION shared_wake_snapshot_scope() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 -- A complete snapshot both confirms present members and retires omitted ones.
 -- Only already active sharing IPs are scheduled, never the full inventory.
 UPDATE shared_observation_jobs j SET revision=j.revision+1,next_attempt_at=now(),
 dirty_since=CASE WHEN j.revision=j.completed_revision THEN now() ELSE j.dirty_since END
 WHERE NOT j.expired AND EXISTS(SELECT 1 FROM shared_observation_mappings m WHERE m.active
 AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain
 AND m.identity_source=NEW.source AND m.identity_sensor_id=NEW.sensor_id AND m.identity_campus_id=NEW.campus_id AND m.identity_access_domain=NEW.access_domain
 AND m.valid_from<=j.last_event_at AND m.valid_until>j.last_event_at);
 RETURN NEW;
END $$;
CREATE TRIGGER shared_identity_snapshot_changed AFTER INSERT ON shared_identity_snapshot_indexes FOR EACH ROW EXECUTE FUNCTION shared_wake_snapshot_scope();
CREATE FUNCTION shared_wake_health_scope() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE shared_observation_jobs j SET revision=j.revision+1,next_attempt_at=now(),
 dirty_since=CASE WHEN j.revision=j.completed_revision THEN now() ELSE j.dirty_since END
 WHERE NOT j.expired AND EXISTS(SELECT 1 FROM shared_observation_mappings m WHERE m.active AND m.health_bridge_id=NEW.bridge_id
 AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain
 AND m.valid_from<=j.last_event_at AND m.valid_until>j.last_event_at);
 RETURN NEW;
END $$;
CREATE TRIGGER shared_identity_health_changed AFTER INSERT OR UPDATE ON shared_identity_health_intervals FOR EACH ROW EXECUTE FUNCTION shared_wake_health_scope();
