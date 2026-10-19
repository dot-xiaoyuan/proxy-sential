-- Account and session totals are read-side statistics, each batch counted once (counted_sequence). They live in their own row per scope, so
-- the apply transaction, which also advances processing progress, no longer locks them.
-- The table is keyed by scope_key with no foreign key: a statistics write never locks the scope row.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS identity_scope_statistics (
 scope_key text PRIMARY KEY,
 accounts bigint NOT NULL DEFAULT 0 CHECK(accounts>=0),
 sessions bigint NOT NULL DEFAULT 0 CHECK(sessions>=0),
 counted_sequence bigint NOT NULL DEFAULT 0,
 statistics_at timestamptz NOT NULL DEFAULT now()
);
