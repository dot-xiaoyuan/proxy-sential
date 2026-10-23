-- Verified archive for closed intervals retained before a session/IP is reused.
CREATE TABLE IF NOT EXISTS identity_projection_intervals_archive (
 batch_id String,ordinal UInt32,
 source String,sensor_id String,campus_id String,access_domain String,
 session_id String,ip String,account_id String,
 confirmed_at DateTime64(6,'UTC'),first_received_at DateTime64(6,'UTC'),
 content_hash FixedString(64),document String,
 archived_at DateTime64(6,'UTC') DEFAULT now64(6)
) ENGINE=MergeTree
PARTITION BY toYYYYMM(first_received_at)
ORDER BY (batch_id,ordinal,content_hash)
TTL toDateTime(greatest(confirmed_at,first_received_at))+INTERVAL 1 YEAR DELETE;
