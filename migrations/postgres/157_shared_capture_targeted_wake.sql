-- A coverage heartbeat advances a bounded interval. Rechecking every partial
-- sharing IP in the scope on every heartbeat can itself outpace the worker.
SET LOCAL lock_timeout = '5s';

ALTER TABLE shared_observation_wakes ADD COLUMN covered_to timestamptz;
ALTER TABLE shared_observation_wakes ADD COLUMN previous_covered_to timestamptz;

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
   AND j.access_domain=NEW.access_domain AND NOT j.expired AND j.last_event_at>=now()-interval '1 hour'
   AND (changed OR (j.coverage_state<>'verified' AND j.last_event_at>COALESCE(previous_to,NEW.covered_from)
    AND j.last_event_at<=NEW.covered_to))
 ) THEN
  INSERT INTO shared_observation_wakes(kind,producer_mode,sensor_id,campus_id,access_domain,force_all,covered_to,previous_covered_to)
  VALUES('capture_scope',wake_mode,NEW.sensor_id,NEW.campus_id,NEW.access_domain,changed,NEW.covered_to,COALESCE(previous_to,NEW.covered_from));
 END IF;
 RETURN NEW;
END $$;
