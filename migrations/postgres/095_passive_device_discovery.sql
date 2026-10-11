-- Passive discovery is a bounded read model over immutable normalized events.
-- New sensors start at migration/first-claim time; retained ClickHouse history is
-- deliberately not replayed automatically.
CREATE TABLE IF NOT EXISTS passive_discovery_state (
 sensor_id text PRIMARY KEY,
 cursor_timestamp timestamptz NOT NULL DEFAULT now(),
 cursor_event_id text NOT NULL DEFAULT '',
 lease_owner text NOT NULL DEFAULT '',
 lease_until timestamptz NOT NULL DEFAULT '-infinity',
 processed_events bigint NOT NULL DEFAULT 0,
 emitted_observations bigint NOT NULL DEFAULT 0,
 skipped_events bigint NOT NULL DEFAULT 0,
 protocol_counts jsonb NOT NULL DEFAULT '{}'::jsonb,
 skip_counts jsonb NOT NULL DEFAULT '{}'::jsonb,
 last_success_at timestamptz,
 last_error text NOT NULL DEFAULT '',
 updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS passive_discovery_mdns_records (
 sensor_id text NOT NULL,
 interface_name text NOT NULL DEFAULT '',
 record_name text NOT NULL,
 record_type text NOT NULL,
 record_value text NOT NULL,
 observed_at timestamptz NOT NULL,
 valid_until timestamptz NOT NULL,
 event_id text NOT NULL,
 payload jsonb NOT NULL DEFAULT '{}'::jsonb,
 PRIMARY KEY(sensor_id,interface_name,record_name,record_type,record_value)
);
CREATE INDEX IF NOT EXISTS passive_discovery_mdns_expiry
 ON passive_discovery_mdns_records(valid_until);
CREATE INDEX IF NOT EXISTS passive_discovery_mdns_lookup
 ON passive_discovery_mdns_records(sensor_id,interface_name,record_name,valid_until);

CREATE INDEX IF NOT EXISTS discovery_observation_recent
 ON discovery_observations(observed_at DESC,device_key);

INSERT INTO read_model_runtime_state(name,state,updated_at)
VALUES('passive-discovery','{"status":"waiting_for_new_events"}'::jsonb,now())
ON CONFLICT(name) DO NOTHING;
