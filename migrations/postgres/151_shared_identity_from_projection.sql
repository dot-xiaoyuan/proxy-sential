-- Shared observation reads a sharing IP's identity from the snapshot projection and the snapshot log
-- instead of a copy of every snapshot's members. A projected snapshot now wakes the scope's shared
-- observation jobs, which the per-snapshot index rows used to do.
SET LOCAL lock_timeout = '5s';

CREATE TRIGGER identity_snapshot_projected_wake
 AFTER UPDATE OF projected ON identity_snapshot_log
 FOR EACH ROW WHEN (NEW.projected AND NOT OLD.projected)
 EXECUTE FUNCTION shared_wake_snapshot_scope();

-- The projection is written continuously; on an existing installation build this index first with
-- CREATE INDEX CONCURRENTLY, and this statement then records the migration as a no-op.
CREATE INDEX IF NOT EXISTS account_identity_projection_ip
 ON account_identity_session_projection (ip, confirmed_at);
