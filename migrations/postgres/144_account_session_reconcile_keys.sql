-- The table is hot. Fail fast if the ACCESS EXCLUSIVE lock is queued behind long transactions,
-- rather than blocking every session write until they finish.
SET LOCAL lock_timeout = '5s';

-- Snapshot reconciliation matches a login by its generation and checks the collector scope.
-- Rows written before this migration keep empty values and are matched by source, campus and
-- access domain only. Partial indexes cover just the keyed rows and the open rows, so existing
-- history is not indexed.
ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS login_key TEXT NOT NULL DEFAULT '';
ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS sensor_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS account_sessions_login_key_lookup ON account_sessions (login_key) WHERE login_key <> '';
CREATE INDEX IF NOT EXISTS account_sessions_open_source_lookup ON account_sessions (source) WHERE ended_at IS NULL;
