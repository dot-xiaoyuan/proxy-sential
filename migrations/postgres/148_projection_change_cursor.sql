-- The terminal list updater reads snapshot projection changes after a (confirmed_at, endpoint) keyset
-- every 15 seconds. Without this index that read scanned a whole index each round. Projection rows
-- are now written only when a member changes, so the write cost of this index stays small.
SET LOCAL lock_timeout = '5s';

CREATE INDEX IF NOT EXISTS account_identity_projection_change_cursor
 ON account_identity_session_projection (confirmed_at, (document->>'endpoint_id'));
