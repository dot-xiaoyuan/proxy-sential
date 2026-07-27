CREATE TABLE IF NOT EXISTS sensors (
  sensor_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  collector_kind TEXT NOT NULL,
  collector_version TEXT,
  interface_name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS collector_runs (
  run_id TEXT PRIMARY KEY,
  sensor_id TEXT NOT NULL REFERENCES sensors(sensor_id),
  started_at TIMESTAMPTZ NOT NULL,
  finished_at TIMESTAMPTZ,
  previous_offset BIGINT NOT NULL DEFAULT 0,
  new_offset BIGINT NOT NULL DEFAULT 0,
  truncated BOOLEAN NOT NULL DEFAULT false,
  normalized_read BIGINT NOT NULL DEFAULT 0,
  normalized_emitted BIGINT NOT NULL DEFAULT 0,
  normalized_skipped BIGINT NOT NULL DEFAULT 0,
  normalized_malformed BIGINT NOT NULL DEFAULT 0,
  evidence_count BIGINT NOT NULL DEFAULT 0,
  risk_count BIGINT NOT NULL DEFAULT 0,
  risk_list_count BIGINT NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'finished',
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT PRIMARY KEY,
  ip INET NOT NULL,
  type TEXT NOT NULL,
  "window" TEXT NOT NULL,
  score INTEGER NOT NULL,
  confidence DOUBLE PRECISION NOT NULL,
  severity TEXT NOT NULL,
  reason TEXT NOT NULL,
  samples JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_snapshots (
  ip INET PRIMARY KEY,
  score INTEGER NOT NULL,
  level TEXT NOT NULL,
  confidence DOUBLE PRECISION NOT NULL,
  "window" TEXT NOT NULL,
  evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  summary TEXT NOT NULL,
  recommended_action TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_snapshot_history (
  history_id BIGSERIAL PRIMARY KEY,
  ip INET NOT NULL,
  snapshot JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS labels (
  label_id TEXT PRIMARY KEY,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  label TEXT NOT NULL,
  reason TEXT NOT NULL,
  evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  audit_id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  outcome TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rulesets (
  ruleset_id TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'shadow',
  body JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS decision_actions (
  action_id TEXT PRIMARY KEY,
  ip INET NOT NULL,
  risk_level TEXT NOT NULL,
  action TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'shadow',
  cooldown_until TIMESTAMPTZ,
  audit_id TEXT REFERENCES audit_logs(audit_id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_collector_runs_sensor_started ON collector_runs(sensor_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_ip_created ON evidence(ip, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_snapshots_level_score ON risk_snapshots(level, score DESC);
CREATE INDEX IF NOT EXISTS idx_labels_target ON labels(target_type, target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);
