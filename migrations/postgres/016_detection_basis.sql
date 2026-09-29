ALTER TABLE risk_snapshots
  ADD COLUMN IF NOT EXISTS detection_basis TEXT NOT NULL DEFAULT 'behavioral_only',
  ADD COLUMN IF NOT EXISTS independent_signal_groups JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE subject_risk_snapshots
  ADD COLUMN IF NOT EXISTS detection_basis TEXT NOT NULL DEFAULT 'behavioral_only',
  ADD COLUMN IF NOT EXISTS independent_signal_groups JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_risk_snapshots_detection_basis
  ON risk_snapshots(detection_basis, updated_at DESC);
