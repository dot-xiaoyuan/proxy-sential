-- Per-source discovery watermarks and one current row per device identity.
-- Existing observation rows stay in place; this migration does not copy them.
CREATE TABLE IF NOT EXISTS passive_discovery_source_cursors (
 sensor_id text NOT NULL,
 source_event_type text NOT NULL,
 cursor_timestamp timestamptz NOT NULL,
 cursor_event_id text NOT NULL DEFAULT '',
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (sensor_id, source_event_type)
);

CREATE TABLE IF NOT EXISTS discovery_passive_device_current (
 identity_key text PRIMARY KEY,
 device_key text NOT NULL,
 device_keys text[] NOT NULL DEFAULT '{}',
 mac text NOT NULL DEFAULT '',
 ip text NOT NULL DEFAULT '',
 name text NOT NULL DEFAULT '',
 device_type text NOT NULL DEFAULT '',
 last_seen timestamptz NOT NULL,
 valid_until timestamptz NOT NULL,
 domain text NOT NULL DEFAULT '',
 vlan text NOT NULL DEFAULT '',
 origins text[] NOT NULL DEFAULT '{}',
 capabilities text[] NOT NULL DEFAULT '{}',
 random_mac boolean NOT NULL DEFAULT false,
 search_text text NOT NULL DEFAULT '',
 os_family text NOT NULL DEFAULT '',
 category text NOT NULL DEFAULT 'identity_only',
 effective_types text[] NOT NULL DEFAULT '{}',
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS discovery_passive_device_current_seen
 ON discovery_passive_device_current (last_seen DESC, identity_key);
CREATE INDEX IF NOT EXISTS discovery_passive_device_current_status
 ON discovery_passive_device_current (category, last_seen DESC);
