-- Ended members of the identity snapshot projection leave PostgreSQL after the 30-day hot window.
-- They are the only copy of snapshot-derived address history, so they are archived here first and
-- deleted from the hot table only after this archive is verified. An ended member's confirmed_at is
-- the time it ended, never before its first ingest, so the TTL keeps it at least one year from ingest.
CREATE TABLE IF NOT EXISTS identity_projection_history_archive (
 batch_id String, ordinal UInt32,
 source String, sensor_id String, campus_id String, access_domain String,
 session_id String, ip String, account_id String,
 confirmed_at DateTime64(6,'UTC'),
 content_hash FixedString(64), document String,
 archived_at DateTime64(6,'UTC') DEFAULT now64(6)
) ENGINE=MergeTree
PARTITION BY toYYYYMM(confirmed_at)
ORDER BY (batch_id,ordinal,content_hash)
TTL toDateTime(confirmed_at)+INTERVAL 1 YEAR DELETE;
