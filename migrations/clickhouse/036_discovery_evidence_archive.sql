-- Only device-discovery evidence gets the one-year retention contract.
CREATE TABLE IF NOT EXISTS discovery_evidence_archive (
 batch_id String, ordinal UInt32, event_id String,
 accepted_at DateTime64(6,'UTC'), observed_at DateTime64(6,'UTC'),
 sensor_id String, protocol LowCardinality(String),
 content_hash FixedString(64), document String
) ENGINE=MergeTree
PARTITION BY toYYYYMM(accepted_at)
ORDER BY (batch_id,ordinal,content_hash)
TTL toDateTime(accepted_at)+INTERVAL 1 YEAR DELETE;
