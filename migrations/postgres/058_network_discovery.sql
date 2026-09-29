-- Discovery observations are deliberately separate from risk terminal identity.
CREATE TABLE IF NOT EXISTS discovery_sources (
 id text PRIMARY KEY, config jsonb NOT NULL, encrypted_secret text NOT NULL,
 config_version integer NOT NULL DEFAULT 1, enabled boolean NOT NULL DEFAULT false,
 node text NOT NULL, next_poll timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS discovery_tasks (
 id text PRIMARY KEY, source_id text REFERENCES discovery_sources(id), node text NOT NULL,
 kind text NOT NULL, status text NOT NULL DEFAULT 'pending',
 config_version integer NOT NULL, config jsonb NOT NULL, encrypted_secret text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(), started_at timestamptz, completed_at timestamptz,
 lease_until timestamptz, attempt integer NOT NULL DEFAULT 0,
 cancel_requested boolean NOT NULL DEFAULT false, result jsonb, error text NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS discovery_source_active_task ON discovery_tasks(source_id) WHERE status IN ('pending','running');
CREATE INDEX IF NOT EXISTS discovery_task_claim ON discovery_tasks(node,status,created_at);
CREATE TABLE IF NOT EXISTS discovery_snapshots (
 id text PRIMARY KEY, source_id text NOT NULL, config_version integer NOT NULL,
 observed_at timestamptz NOT NULL, data jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS discovery_observations (
 id text PRIMARY KEY, device_key text NOT NULL, source_id text NOT NULL,
 origin text NOT NULL, observed_at timestamptz NOT NULL, valid_until timestamptz NOT NULL,
 withdrawn boolean NOT NULL, data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS discovery_observation_devices ON discovery_observations(device_key,observed_at DESC);
CREATE INDEX IF NOT EXISTS discovery_observation_retention ON discovery_observations(observed_at);
CREATE TABLE IF NOT EXISTS discovery_scan_profiles (
 id text PRIMARY KEY, node text NOT NULL, config jsonb NOT NULL,
 version integer NOT NULL DEFAULT 1, trial_version integer NOT NULL DEFAULT 0,
 enabled boolean NOT NULL DEFAULT false, next_scan timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE discovery_tasks ADD COLUMN IF NOT EXISTS profile_id text REFERENCES discovery_scan_profiles(id);
CREATE UNIQUE INDEX IF NOT EXISTS discovery_profile_active_task ON discovery_tasks(profile_id) WHERE status IN ('pending','running');
CREATE TABLE IF NOT EXISTS discovery_identity_links (
 observation_id text PRIMARY KEY REFERENCES discovery_observations(id) ON DELETE CASCADE,
 endpoint_id text NOT NULL, valid_until timestamptz NOT NULL, basis jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS discovery_identity_endpoint ON discovery_identity_links(endpoint_id,valid_until);
CREATE TABLE IF NOT EXISTS discovery_nodes (
 node text PRIMARY KEY, last_seen timestamptz NOT NULL, capabilities jsonb NOT NULL DEFAULT '[]'::jsonb
);
ALTER TABLE discovery_sources ADD COLUMN IF NOT EXISTS consecutive_failures integer NOT NULL DEFAULT 0;
