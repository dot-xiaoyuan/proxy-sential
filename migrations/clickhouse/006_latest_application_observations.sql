-- Event timestamps are immutable standard-event identity fields. Reclassification
-- replaces classification/measurement fields, never the timestamp or event key.
CREATE TABLE IF NOT EXISTS application_latest_observations (
 timestamp DateTime64(9, 'UTC'),
 sensor_id String,
 event_id String,
 campus_id String,
 ip String,
 connection_id String,
 event_type LowCardinality(String),
 domain String,
 source_field LowCardinality(String),
 bundle_version String,
 target_id String,
 target_type LowCardinality(String),
 name String,
 category String,
 upload_bytes Nullable(UInt64),
 download_bytes Nullable(UInt64),
 observation_json String,
 classification_revision UInt64,
 batch_id UInt64,
 dedup_version UInt128 MATERIALIZED toUInt128(classification_revision)*toUInt128('18446744073709551616')+toUInt128('18446744073709551615')-toUInt128(batch_id)
) ENGINE = ReplacingMergeTree(dedup_version)
PARTITION BY toDate(timestamp)
ORDER BY (timestamp,sensor_id,event_id)
TTL toDateTime(timestamp) + INTERVAL 7 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS application_latest_observations_mv
TO application_latest_observations AS SELECT * FROM application_observations;
