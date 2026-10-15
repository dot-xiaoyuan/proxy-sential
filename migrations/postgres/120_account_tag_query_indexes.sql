CREATE INDEX IF NOT EXISTS account_sessions_account_recent_tag
ON account_sessions(account_id, (COALESCE(ended_at, started_at)) DESC)
INCLUDE(endpoint_id, mac)
WHERE account_id<>'';

CREATE INDEX IF NOT EXISTS subject_risk_snapshots_account_updated
ON subject_risk_snapshots(account_id, updated_at DESC)
WHERE account_id IS NOT NULL AND account_id<>'';
