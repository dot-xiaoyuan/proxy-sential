SET LOCAL lock_timeout = '5s';
-- Existing installations prebuild this index CONCURRENTLY. Migration 153
-- removed its predecessor before the scoped shared-identity reader became hot.
-- Retained events and business deduplication are unchanged. The index lives
-- with the fact table, adds one entry per fact, and needs no cache invalidation.
DO $$ BEGIN
 IF to_regclass('policy_identity_scope_ip_time_v2') IS NULL THEN
  CREATE INDEX policy_identity_scope_ip_time_v2 ON policy_identity_observations
   ((session_data->>'source'),(session_data->>'sensor_id'),(session_data->>'campus_id'),(session_data->>'access_domain'),(session_data->>'ip'),observed_at,event_id);
 ELSIF NOT EXISTS(SELECT 1 FROM pg_index WHERE indexrelid='policy_identity_scope_ip_time_v2'::regclass AND indisvalid AND indisready) THEN
  RAISE EXCEPTION 'prebuilt identity scope/IP lookup index is invalid';
 END IF;
END $$;
