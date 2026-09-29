CREATE TABLE IF NOT EXISTS application_observations (
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
 batch_id UInt64
) ENGINE = MergeTree
PARTITION BY toDate(timestamp)
ORDER BY (sensor_id,campus_id,timestamp,event_id)
TTL toDateTime(timestamp) + INTERVAL 7 DAY DELETE;
