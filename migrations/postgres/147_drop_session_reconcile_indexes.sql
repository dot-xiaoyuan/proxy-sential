-- Snapshot session reconciliation was removed: nothing reads login_key or open rows by source any
-- more, and both indexes were maintained on every account_sessions write. The columns from 144 stay.
SET LOCAL lock_timeout = '5s';

DROP INDEX IF EXISTS account_sessions_login_key_lookup;
DROP INDEX IF EXISTS account_sessions_open_source_lookup;
