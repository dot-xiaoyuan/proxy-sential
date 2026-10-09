CREATE TABLE IF NOT EXISTS identity_bridge_configs (
  bridge_id text PRIMARY KEY,
  desired_host text NOT NULL,
  config_version bigint NOT NULL DEFAULT 1 CHECK(config_version > 0),
  updated_by text NOT NULL DEFAULT 'deployment',
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO identity_bridge_configs(bridge_id,desired_host)
VALUES('ncu-legacy-4k','222.204.3.224')
ON CONFLICT(bridge_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS identity_bridge_runtime (
  bridge_id text PRIMARY KEY REFERENCES identity_bridge_configs(bridge_id) ON DELETE CASCADE,
  active_host text NOT NULL DEFAULT '',
  active_config_version bigint NOT NULL DEFAULT 0 CHECK(active_config_version >= 0),
  state text NOT NULL DEFAULT 'starting' CHECK(state IN ('starting','healthy','degraded','switching','switch_failed','failed')),
  online_channel_state text NOT NULL DEFAULT 'pending',
  event_channel_state text NOT NULL DEFAULT 'pending',
  snapshot_state text NOT NULL DEFAULT 'pending',
  source_queue bigint NOT NULL DEFAULT 0 CHECK(source_queue >= 0),
  processing_queue bigint NOT NULL DEFAULT 0 CHECK(processing_queue >= 0),
  online_members bigint NOT NULL DEFAULT 0 CHECK(online_members >= 0),
  online_sessions bigint NOT NULL DEFAULT 0 CHECK(online_sessions >= 0),
  committed_messages bigint NOT NULL DEFAULT 0 CHECK(committed_messages >= 0),
  bad_messages bigint NOT NULL DEFAULT 0 CHECK(bad_messages >= 0),
  event_consecutive_failures integer NOT NULL DEFAULT 0 CHECK(event_consecutive_failures >= 0),
  snapshot_consecutive_failures integer NOT NULL DEFAULT 0 CHECK(snapshot_consecutive_failures >= 0),
  last_event_at timestamptz,
  last_snapshot_attempt_at timestamptz,
  last_snapshot_at timestamptz,
  last_error_type text NOT NULL DEFAULT '',
  started_at timestamptz,
  heartbeat_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS identity_bridge_runs (
  run_id text PRIMARY KEY,
  bridge_id text NOT NULL REFERENCES identity_bridge_configs(bridge_id) ON DELETE CASCADE,
  kind text NOT NULL CHECK(kind IN ('snapshot','config_switch')),
  status text NOT NULL CHECK(status IN ('running','completed','failed')),
  records_read integer NOT NULL DEFAULT 0 CHECK(records_read >= 0),
  records_emitted integer NOT NULL DEFAULT 0 CHECK(records_emitted >= 0),
  records_skipped integer NOT NULL DEFAULT 0 CHECK(records_skipped >= 0),
  records_malformed integer NOT NULL DEFAULT 0 CHECK(records_malformed >= 0),
  retry_count integer NOT NULL DEFAULT 0 CHECK(retry_count >= 0),
  duration_ms bigint NOT NULL DEFAULT 0 CHECK(duration_ms >= 0),
  error_type text NOT NULL DEFAULT '',
  started_at timestamptz NOT NULL,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS identity_bridge_runs_recent
  ON identity_bridge_runs(bridge_id,started_at DESC,run_id DESC);
