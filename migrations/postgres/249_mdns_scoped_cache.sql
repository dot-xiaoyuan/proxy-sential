-- Derived, scope-isolated DNS-SD join cache. Leave the legacy cache unchanged
-- for application rollback; original events remain authoritative in ClickHouse.
-- One compact row per scope/RR/value, two indexes (identity and expiry).
-- Runtime cleanup removes at most 128 expired entries per discovery batch,
-- retaining a 30-day late-event window. No full original payload is duplicated.
CREATE TABLE IF NOT EXISTS passive_discovery_mdns_scoped_records (
 sensor_id text NOT NULL,
 interface_name text NOT NULL DEFAULT '',
 scope_key text NOT NULL,
 record_name text NOT NULL,
 record_type text NOT NULL,
 record_value text NOT NULL,
 observed_at timestamptz NOT NULL,
 valid_until timestamptz NOT NULL,
 event_id text NOT NULL,
 raw_ref jsonb NOT NULL DEFAULT '{}'::jsonb,
 PRIMARY KEY(sensor_id,interface_name,scope_key,record_name,record_type,record_value)
);
CREATE INDEX IF NOT EXISTS passive_mdns_scoped_expiry ON passive_discovery_mdns_scoped_records(valid_until);
