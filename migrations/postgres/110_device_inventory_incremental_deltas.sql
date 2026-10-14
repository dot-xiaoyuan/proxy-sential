-- Incremental device inventory notifications. The source transaction records
-- one compact delta; it never scans history or rebuilds a device projection.
ALTER TABLE endpoint_inventory_projection_jobs
  ADD COLUMN IF NOT EXISTS delta_cursor bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS expiration_checked_at timestamptz NOT NULL DEFAULT '-infinity';

CREATE INDEX IF NOT EXISTS inventory_projection_generation_watermark
  ON endpoint_inventory_projection_jobs(dirty_generation DESC, processed_generation DESC);
CREATE INDEX IF NOT EXISTS inventory_projection_oldest_pending
  ON endpoint_inventory_projection_jobs(updated_at)
  WHERE processed_generation < dirty_generation;

CREATE INDEX IF NOT EXISTS inventory_projection_session_expiry
  ON endpoint_inventory_sessions(ended_at, endpoint_id)
  WHERE ended_at IS NOT NULL;

CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS discovery_latest_name_search
  ON discovery_observation_latest USING gin ((lower(coalesce(data->>'name',''))) gin_trgm_ops);
CREATE INDEX IF NOT EXISTS discovery_latest_manufacturer_search
  ON discovery_observation_latest USING gin ((lower(coalesce(data->>'manufacturer',''))) gin_trgm_ops);
CREATE INDEX IF NOT EXISTS discovery_latest_model_search
  ON discovery_observation_latest USING gin ((lower(coalesce(data->>'model_name',''))) gin_trgm_ops);
CREATE INDEX IF NOT EXISTS discovery_latest_ip_search
  ON discovery_observation_latest ((lower(coalesce(data->>'ip',''))));
CREATE INDEX IF NOT EXISTS discovery_latest_mac_search
  ON discovery_observation_latest ((lower(coalesce(data->>'mac',''))));

CREATE TABLE IF NOT EXISTS endpoint_inventory_projection_deltas (
  delta_id bigserial PRIMARY KEY,
  endpoint_id text NOT NULL,
  source_table text NOT NULL,
  operation char(1) NOT NULL CHECK (operation IN ('I','U','D')),
  event_id text NOT NULL DEFAULT '',
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS inventory_projection_deltas_endpoint
  ON endpoint_inventory_projection_deltas(endpoint_id, delta_id);

CREATE OR REPLACE FUNCTION record_inventory_projection_delta() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  body jsonb;
  endpoint text;
  event text;
BEGIN
  body := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
  endpoint := CASE
    WHEN TG_TABLE_NAME = 'account_identity_session_projection'
      THEN COALESCE(body->'document'->>'endpoint_id','')
    ELSE COALESCE(body->>'endpoint_id','')
  END;
  event := COALESCE(body->>'event_id', body->>'session_id', body->>'snapshot_id', '');
  IF endpoint <> '' THEN
    INSERT INTO endpoint_inventory_projection_deltas(endpoint_id,source_table,operation,event_id,payload)
    VALUES(endpoint,TG_TABLE_NAME,substr(TG_OP,1,1),event,body);
  END IF;
  RETURN NULL;
END $$;

DO $$
DECLARE
  table_name text;
  trigger_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'endpoint_entities', 'endpoint_recognition_summary', 'device_name_notes',
    'identity_ip_mac_history', 'identity_access_history', 'account_sessions',
    'account_identity_session_projection'
  ] LOOP
    trigger_name := 'inventory_projection_delta_' || table_name;
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', trigger_name, table_name);
    EXECUTE format(
      'CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION record_inventory_projection_delta()',
      trigger_name, table_name
    );
  END LOOP;
END $$;
