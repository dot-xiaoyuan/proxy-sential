ALTER TABLE enforcement_connectors
  ADD COLUMN IF NOT EXISTS circuit_open_until TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS shadow_started_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS shadow_candidate_count INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS shadow_reviewed_count INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS shadow_accuracy DOUBLE PRECISION NOT NULL DEFAULT 0;

ALTER TABLE enforcement_actions
  ADD COLUMN IF NOT EXISTS parent_action_id TEXT REFERENCES enforcement_actions(action_id),
  ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_actions_due
  ON enforcement_actions(status, next_attempt_at, expires_at);

CREATE INDEX IF NOT EXISTS idx_actions_parent
  ON enforcement_actions(parent_action_id, created_at DESC);

CREATE TABLE IF NOT EXISTS enforcement_action_attempts (
  attempt_id TEXT PRIMARY KEY,
  action_id TEXT NOT NULL REFERENCES enforcement_actions(action_id) ON DELETE CASCADE,
  attempt_number INTEGER NOT NULL,
  request_body JSONB NOT NULL,
  response_body JSONB,
  http_status INTEGER,
  error_text TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
