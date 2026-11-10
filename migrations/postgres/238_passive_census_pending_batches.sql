-- Compact, bounded derived facts are queued after the authoritative event
-- write. The worker projects them asynchronously and keeps the retry cursor.
CREATE TABLE IF NOT EXISTS passive_census_pending_batches (
 id bigserial PRIMARY KEY,
 sensor_id text NOT NULL,
 batch_key text NOT NULL,
 scope_version text NOT NULL,
 first_source_at timestamptz NOT NULL,
 last_source_at timestamptz NOT NULL,
 identifier_count integer NOT NULL,
 binding_count integer NOT NULL,
 payload jsonb NOT NULL,
 byte_size integer NOT NULL CHECK(byte_size<=2097152),
 first_enqueued_at timestamptz NOT NULL DEFAULT now(),
 lease_owner text NOT NULL DEFAULT '',
 lease_until timestamptz NOT NULL DEFAULT '-infinity',
 attempts integer NOT NULL DEFAULT 0,
 last_error text NOT NULL DEFAULT '',
 processed_at timestamptz,
 UNIQUE(sensor_id,batch_key)
);
CREATE INDEX IF NOT EXISTS passive_census_pending_claim
 ON passive_census_pending_batches(sensor_id,lease_until,id) WHERE processed_at IS NULL;
CREATE INDEX IF NOT EXISTS passive_census_pending_oldest
 ON passive_census_pending_batches(sensor_id,first_source_at,id) WHERE processed_at IS NULL;
CREATE INDEX IF NOT EXISTS passive_census_pending_retention
 ON passive_census_pending_batches(processed_at) WHERE processed_at IS NOT NULL;
ALTER TABLE passive_census_runtime
 ADD COLUMN IF NOT EXISTS last_batch_rows integer NOT NULL DEFAULT 0,
 ADD COLUMN IF NOT EXISTS last_batch_ms integer NOT NULL DEFAULT 0;
