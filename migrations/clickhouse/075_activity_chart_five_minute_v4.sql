-- Two physical slots keep a published bucket intact while its replacement is
-- built. ReplacingMergeTree can compact each slot independently. A missing
-- metric key receives a tombstone before the next revision is published.
CREATE TABLE IF NOT EXISTS activity_chart_facts_5m_v4 (
 bucket_start DateTime('UTC'), sensor_id String, campus_id String,
 slot UInt8, dimension LowCardinality(String), value String,
 version UInt64, deleted UInt8, event_count UInt64,
 first_seen DateTime64(6,'UTC'), last_seen DateTime64(6,'UTC')
) ENGINE=ReplacingMergeTree(version)
PARTITION BY toDate(bucket_start)
ORDER BY(sensor_id,campus_id,bucket_start,slot,dimension,value)
TTL toDateTime(bucket_start)+INTERVAL 8 DAY DELETE;

CREATE TABLE IF NOT EXISTS activity_chart_bucket_versions_v4 (
 bucket_start DateTime('UTC'), sensor_id String, campus_id String,
 slot UInt8, revision UInt64, source_revision UInt64, source_as_of DateTime64(9,'UTC'),
 published_at DateTime64(9,'UTC'), finalized UInt8,
 metric_keys UInt64, event_count UInt64, content_hash UInt64
) ENGINE=ReplacingMergeTree(published_at)
PARTITION BY toYYYYMM(bucket_start)
ORDER BY(sensor_id,campus_id,bucket_start)
TTL toDateTime(bucket_start)+INTERVAL 8 DAY DELETE;
