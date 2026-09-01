CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  checksum TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS control_plane_settings (
  setting_key TEXT PRIMARY KEY,
  setting_value JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO control_plane_settings(setting_key, setting_value)
VALUES ('global_emergency_stop', 'false'::jsonb)
ON CONFLICT (setting_key) DO NOTHING;

ALTER TABLE risk_case_timeline ADD COLUMN IF NOT EXISTS event_id TEXT;
UPDATE risk_case_timeline
SET event_id = 'legacy-' || timeline_id::text
WHERE event_id IS NULL;
ALTER TABLE risk_case_timeline ALTER COLUMN event_id SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_case_timeline_event_id
ON risk_case_timeline(event_id);

CREATE TABLE IF NOT EXISTS identity_ingest_batches (
  batch_id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  sensor_id TEXT NOT NULL,
  status TEXT NOT NULL,
  records_read INTEGER NOT NULL DEFAULT 0,
  records_emitted INTEGER NOT NULL DEFAULT 0,
  records_skipped INTEGER NOT NULL DEFAULT 0,
  records_malformed INTEGER NOT NULL DEFAULT 0,
  error_message TEXT,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_identity_ingest_batches_received
ON identity_ingest_batches(received_at DESC);

CREATE TABLE IF NOT EXISTS local_auth_sessions (
  session_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES local_users(user_id) ON DELETE CASCADE,
  csrf_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_local_auth_sessions_expiry
ON local_auth_sessions(expires_at);

CREATE TABLE IF NOT EXISTS login_rate_limits (
  remote_key TEXT PRIMARY KEY,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  window_started_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
