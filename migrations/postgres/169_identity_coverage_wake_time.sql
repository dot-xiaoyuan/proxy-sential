SET LOCAL lock_timeout = '5s';
-- Scope coverage carries the snapshot's event time, independent of delayed
-- projection completion. Old applications ignore the optional metadata; legacy
-- requeue semantics and independent member/IP change wakes remain unchanged.
CREATE OR REPLACE FUNCTION shared_wake_snapshot_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE wake_mode text;
BEGIN
 SELECT mode INTO wake_mode FROM shared_observation_wake_mode WHERE singleton;
 -- The index is written before projection. Only the projected log is authoritative
 -- in async mode; legacy keeps the installed trigger behavior until cutover.
 IF TG_TABLE_NAME='shared_identity_snapshot_indexes' AND wake_mode='async' THEN RETURN NEW; END IF;
 IF wake_mode IN ('shadow','async') THEN
  INSERT INTO shared_observation_wakes(kind,producer_mode,source,sensor_id,campus_id,access_domain,covered_to)
  VALUES('snapshot_scope',wake_mode,NEW.source,NEW.sensor_id,NEW.campus_id,NEW.access_domain,NEW.observed_at);
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
