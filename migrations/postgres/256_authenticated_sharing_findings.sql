-- Bounded reporting projection for post-release traffic. One compact row per observation.
-- The owning observation's retention also retires these rows.
SET LOCAL lock_timeout='5s';
CREATE TABLE shared_access_findings (
 observation_id text PRIMARY KEY REFERENCES shared_behavior_observations(observation_id) ON DELETE CASCADE,
 sensor_id text NOT NULL, campus_id text NOT NULL, access_domain text NOT NULL, ip inet NOT NULL,
 observed_at timestamptz NOT NULL, account_id text NOT NULL, outcome text NOT NULL, basis text NOT NULL,
 reason text NOT NULL, case_id text NOT NULL DEFAULT '', action_id text NOT NULL DEFAULT '',
 case_pending boolean NOT NULL DEFAULT false
);
CREATE INDEX shared_findings_window ON shared_access_findings(observed_at DESC,observation_id DESC);
CREATE INDEX shared_findings_case_pending ON shared_access_findings(observed_at,observation_id) WHERE case_pending;
CREATE OR REPLACE FUNCTION shared_record_identity_health() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE healthy_now boolean; old_healthy boolean; begin_at timestamptz; gap_at timestamptz;
BEGIN
 healthy_now := NEW.state='healthy' AND NEW.event_consecutive_failures=0 AND NEW.snapshot_consecutive_failures=0;
 -- Old quarantine counts do not describe the health of a new login. Record
 -- actual channel coverage from this heartbeat forward; preserve earlier gaps.
 IF EXISTS (SELECT 1 FROM shared_observation_mappings m WHERE m.active AND m.identity_source='ncu-srun4k' AND m.health_bridge_id=NEW.bridge_id) THEN
  healthy_now := NEW.online_channel_state='healthy' AND NEW.event_channel_state='healthy' AND NEW.snapshot_state='healthy'
   AND NEW.event_consecutive_failures=0 AND NEW.snapshot_consecutive_failures=0 AND NOT NEW.queue_sample_error
   AND NEW.processing_queue=0 AND NEW.source_queue=0 AND (TG_OP='INSERT' OR NEW.quarantine_queue<=OLD.quarantine_queue);
 END IF;
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

-- Role changes wake only already-observed addresses of this authenticated MAC.
CREATE FUNCTION shared_wake_router_role() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND (NEW.status,NEW.role,NEW.ambiguous,NEW.infrastructure,NEW.assessment->'score_components') IS NOT DISTINCT FROM
 (OLD.status,OLD.role,OLD.ambiguous,OLD.infrastructure,OLD.assessment->'score_components') AND NEW.first_seen<=OLD.expires_at THEN RETURN NEW; END IF;
 UPDATE shared_observation_jobs j SET revision=j.revision+1,dirty_since=clock_timestamp(),
 last_dependency_at=clock_timestamp(),next_attempt_at=LEAST(now(),j.next_attempt_at)
 FROM shared_observation_mappings m JOIN account_identity_session_projection p ON
 p.source=m.identity_source AND p.sensor_id=m.identity_sensor_id AND p.campus_id=m.identity_campus_id AND p.access_domain=m.identity_access_domain
 WHERE m.active AND m.sensor_id=j.sensor_id AND m.campus_id=j.campus_id AND m.access_domain=j.access_domain
 AND regexp_replace(lower(coalesce(p.document->>'mac','')),'[^0-9a-f]','','g')=replace(lower(NEW.mac),':','')
 AND coalesce(p.document->>'ended_at','')='' AND coalesce(p.document->>'mac','')<>'' AND p.ip=host(j.ip)
 AND j.revision=j.completed_revision AND NOT j.expired AND j.canceled_epoch='' AND j.last_event_at>=now()-interval '3 minutes';
 RETURN NEW;
END $$;
CREATE TRIGGER shared_wake_router_role AFTER INSERT OR UPDATE ON router_assessments FOR EACH ROW
 WHEN (NEW.mac<>'' AND NEW.role IN ('router','ap','switch','unknown')) EXECUTE FUNCTION shared_wake_router_role();
