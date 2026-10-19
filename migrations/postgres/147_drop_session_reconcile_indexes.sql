-- Snapshot session reconciliation was removed: nothing reads login_key or open rows by source any
-- more, and both indexes were maintained on every account_sessions write. The columns from 144 stay.
--
-- account_sessions is written and read continuously, so this transaction cannot take the ACCESS
-- EXCLUSIVE lock (it failed on 184 with lock_timeout). On an existing installation drop both indexes
-- first with DROP INDEX CONCURRENTLY; these statements then record the migration as a no-op.
SET LOCAL lock_timeout = '5s';

DROP INDEX IF EXISTS account_sessions_login_key_lookup;
DROP INDEX IF EXISTS account_sessions_open_source_lookup;
