-- One compact key per unfinished fragment. The lookup includes active leases,
-- unlike the claim index, and starts at the fixed fresh boundary. Terminal
-- fragments leave this index through the existing completion trigger. Cost:
-- one extra index insert/delete per fragment, no payload or history copy.
CREATE INDEX identity_derived_ready_source_age
 ON identity_derived_ready(sensor_id,accepted_at);

-- Source confirmation is distinct from a changed result's write time. Existing
-- rows keep their legacy fallback; only newly applied authentication updates
-- fill this column. No historical payload replay/backfill is required.
ALTER TABLE account_sessions ADD COLUMN last_confirmed_at timestamptz;
-- Old application binaries may continue writing metadata during a phased
-- switch or rollback. Keep the typed source time correct without a second row
-- update, queue wake, or historical scan.
CREATE FUNCTION maintain_account_session_confirmation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' OR NEW.policy_metadata IS DISTINCT FROM OLD.policy_metadata THEN
  NEW.last_confirmed_at=GREATEST(NEW.last_confirmed_at,
   NULLIF(NEW.policy_metadata->>'last_confirmed_at','')::timestamptz);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER account_session_confirmation BEFORE INSERT OR UPDATE OF policy_metadata ON account_sessions
 FOR EACH ROW EXECUTE FUNCTION maintain_account_session_confirmation();
CREATE INDEX account_sessions_current_confirmation
 ON account_sessions(last_confirmed_at)
 WHERE ended_at IS NULL AND last_confirmed_at IS NOT NULL;

-- A session can leave A, then B before the inventory cursor observes its row
-- at C. Remember each departed endpoint, not just the last previous value.
-- One row per endpoint; only actual relationship departures enqueue.
CREATE TABLE identity_endpoint_invalidations (
 endpoint_id text PRIMARY KEY REFERENCES endpoint_entities(endpoint_id) ON DELETE CASCADE,
 revision bigint NOT NULL DEFAULT 1,
 completed_revision bigint NOT NULL DEFAULT 0,
 dirty_since timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(completed_revision<=revision)
);
CREATE INDEX identity_endpoint_invalidations_pending
 ON identity_endpoint_invalidations(dirty_since,endpoint_id)
 WHERE completed_revision<revision;

-- Authentication dimensions belong to sessions. Changing them must not
-- recompute device fingerprints; actual device evidence, registration changes
-- and hourly liveness transitions retain the existing durable recognition wake.
DROP TRIGGER endpoint_recognition_entity_dirty ON endpoint_entities;
CREATE TRIGGER endpoint_recognition_entity_dirty AFTER UPDATE ON endpoint_entities
FOR EACH ROW WHEN (
 OLD.primary_mac IS DISTINCT FROM NEW.primary_mac
 OR OLD.entity_role IS DISTINCT FROM NEW.entity_role
 OR OLD.first_seen IS DISTINCT FROM NEW.first_seen
 OR OLD.identity_confidence IS DISTINCT FROM NEW.identity_confidence
 OR (OLD.attributes - ARRAY['auth_method','vlan','ap','switch_id','switch_port','nas_ip','nas_port_id','person_type','department','campus_id','building_id','network_zone_id','ssid','session_status','access_type']::text[])
    IS DISTINCT FROM (NEW.attributes - ARRAY['auth_method','vlan','ap','switch_id','switch_port','nas_ip','nas_port_id','person_type','department','campus_id','building_id','network_zone_id','ssid','session_status','access_type']::text[])
 OR (OLD.registration_status,OLD.owner_account,OLD.owner_name,OLD.owner_department,OLD.asset_tag,OLD.ownership_class,OLD.registered_by,OLD.registered_at,OLD.registration_note,OLD.merge_status,OLD.merged_into_endpoint_id,OLD.split_from_endpoint_id,OLD.registration_updated_by,OLD.registration_updated_at)
    IS DISTINCT FROM (NEW.registration_status,NEW.owner_account,NEW.owner_name,NEW.owner_department,NEW.asset_tag,NEW.ownership_class,NEW.registered_by,NEW.registered_at,NEW.registration_note,NEW.merge_status,NEW.merged_into_endpoint_id,NEW.split_from_endpoint_id,NEW.registration_updated_by,NEW.registration_updated_at)
 OR date_trunc('hour',OLD.last_seen) IS DISTINCT FROM date_trunc('hour',NEW.last_seen)
) EXECUTE FUNCTION enqueue_endpoint_recognition_job();
