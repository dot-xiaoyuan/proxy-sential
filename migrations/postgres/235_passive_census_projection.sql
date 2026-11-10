-- Additive contract shared by the 204 passive asset line and the integration
-- baseline. These are derived indexes; discovery evidence remains authoritative.
CREATE TABLE IF NOT EXISTS passive_census_identifier_current (
 scope_key text NOT NULL,
 sensor_id text NOT NULL,
 campus_id text NOT NULL DEFAULT '',
 access_domain text NOT NULL DEFAULT '',
 vlan text NOT NULL DEFAULT '',
 vrf text NOT NULL DEFAULT '',
 kind text NOT NULL CHECK (kind IN ('ip','mac')),
 value text NOT NULL,
 ip_family smallint NOT NULL DEFAULT 0 CHECK (ip_family IN (0,4,6)),
 random_mac boolean NOT NULL DEFAULT false,
 first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL,
 last_event_id text NOT NULL,
 last_source text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(scope_key,kind,value)
);
CREATE INDEX IF NOT EXISTS passive_census_identifier_recent
 ON passive_census_identifier_current(kind,last_seen DESC,scope_key,value);

-- One compact row per observed identifier and five-minute interval. It is not
-- an original packet copy and may be retired after the hot comparison window.
CREATE TABLE IF NOT EXISTS passive_census_identifier_5m (
 bucket_at timestamptz NOT NULL,
 scope_key text NOT NULL,
 kind text NOT NULL CHECK (kind IN ('ip','mac')),
 value text NOT NULL,
 first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL,
 last_event_id text NOT NULL,
 PRIMARY KEY(bucket_at,scope_key,kind,value)
);
CREATE INDEX IF NOT EXISTS passive_census_bucket_retention ON passive_census_identifier_5m(bucket_at);

CREATE TABLE IF NOT EXISTS passive_census_binding_current (
 scope_key text NOT NULL,
 ip text NOT NULL,
 mac text NOT NULL,
 observed_at timestamptz NOT NULL,
 valid_until timestamptz NOT NULL,
 withdrawn boolean NOT NULL DEFAULT false,
 conflict boolean NOT NULL DEFAULT false,
 evidence_event_id text NOT NULL,
 source text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(scope_key,ip,mac)
);
CREATE INDEX IF NOT EXISTS passive_census_binding_active
 ON passive_census_binding_current(scope_key,valid_until DESC,ip,mac)
 WHERE NOT withdrawn;

CREATE TABLE IF NOT EXISTS passive_census_terminal_current (
 identity_key text PRIMARY KEY,
 scope_key text NOT NULL,
 device_key text NOT NULL,
 effective_type text NOT NULL,
 classification_status text NOT NULL,
 first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL,
 evidence_observed_at timestamptz,
 rule_version text NOT NULL DEFAULT '',
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS passive_census_terminal_filter
 ON passive_census_terminal_current(scope_key,classification_status,effective_type,last_seen DESC,identity_key);

CREATE TABLE IF NOT EXISTS passive_census_runtime (
 sensor_id text PRIMARY KEY,
 scope_version text NOT NULL DEFAULT '',
 available_from timestamptz,
 last_source_at timestamptz,
 last_success_at timestamptz,
 oldest_pending_at timestamptz,
 failed_batches bigint NOT NULL DEFAULT 0,
 last_error text NOT NULL DEFAULT '',
 updated_at timestamptz NOT NULL DEFAULT now()
);
