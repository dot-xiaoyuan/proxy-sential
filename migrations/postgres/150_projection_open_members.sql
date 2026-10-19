-- Policy reads load the open members of the snapshot projection on every call. Without this partial
-- index that read scanned the whole projection, which keeps ended members for 30 days.
--
-- account_identity_session_projection is written continuously; on an existing installation build the
-- index first with CREATE INDEX CONCURRENTLY, and this statement then records the migration as a no-op.
SET LOCAL lock_timeout = '5s';

CREATE INDEX IF NOT EXISTS account_identity_projection_open_members
 ON account_identity_session_projection (campus_id, access_domain)
 WHERE COALESCE(document->>'ended_at','')='';
