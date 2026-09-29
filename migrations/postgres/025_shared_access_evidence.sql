-- Run by the migration transaction. Fail promptly rather than waiting behind
-- ongoing evidence writes; deployment must retry during a suitable interval.
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '60s';
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_shared_evidence_recent
ON evidence(created_at DESC, evidence_id DESC)
WHERE type = 'shared_access_window';
