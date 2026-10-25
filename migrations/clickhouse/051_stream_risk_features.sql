-- Short-lived, rule-versioned inputs for incremental risk evaluation. This
-- table contains selected fields only; the event body and source bytes remain
-- in their single authoritative stream tables.
CREATE TABLE IF NOT EXISTS stream_risk_features_v1 (
 archive_month UInt32,
 scope_id String,
 event_key String,
 content_sha256 FixedString(64),
 feature_sha256 FixedString(64),
 feature_version LowCardinality(String),
 accepted_at DateTime64(6,'UTC'),
 observed_at DateTime64(6,'UTC'),
 sensor_id String,
 subject_ip String,
 account_id String,
 event_type LowCardinality(String),
 feature_json String
) ENGINE=MergeTree
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (sensor_id,subject_ip,observed_at,event_key)
TTL toDateTime(accepted_at)+INTERVAL 8 DAY DELETE
SETTINGS non_replicated_deduplication_window=1000;
