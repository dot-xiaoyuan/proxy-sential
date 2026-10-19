-- Shared-observation snapshot members are kept only for the retention window (about three hours).
-- An index on received_at lets expired rows be deleted in small ordered batches instead of a scan.
-- Run after the member table was emptied, so the build is immediate.
SET LOCAL lock_timeout = '5s';

CREATE INDEX IF NOT EXISTS shared_identity_members_received ON shared_identity_snapshot_members (received_at);
