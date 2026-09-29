-- Narrow idempotency lookup. The materialized view intentionally starts at
-- migration time. Pre-cutover events continue to use the bounded legacy path.
CREATE TABLE IF NOT EXISTS normalized_event_ids_v1 (
 timestamp DateTime64(6,'Asia/Shanghai'),
 event_id String
) ENGINE=MergeTree
PARTITION BY toDate(timestamp)
ORDER BY(event_id,timestamp)
TTL toDateTime(timestamp)+INTERVAL 8 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS normalized_event_ids_v1_mv
TO normalized_event_ids_v1 AS
SELECT timestamp,event_id FROM normalized_events;

CREATE TABLE IF NOT EXISTS activity_chart_facts_5m_v3 (
 bucket_start DateTime('UTC'),sensor_id String,campus_id String,revision UInt64,
 dimension LowCardinality(String),value String,event_count UInt64,
 first_seen DateTime64(6,'UTC'),last_seen DateTime64(6,'UTC')
) ENGINE=MergeTree
PARTITION BY toDate(bucket_start)
ORDER BY(sensor_id,campus_id,bucket_start,revision,dimension,value)
TTL toDateTime(bucket_start)+INTERVAL 8 DAY DELETE;

CREATE TABLE IF NOT EXISTS activity_chart_facts_hour_v3 (
 bucket_start DateTime('UTC'),sensor_id String,campus_id String,revision UInt64,
 dimension LowCardinality(String),value String,event_count UInt64,
 first_seen DateTime64(6,'UTC'),last_seen DateTime64(6,'UTC')
) ENGINE=MergeTree
PARTITION BY toDate(bucket_start)
ORDER BY(sensor_id,campus_id,bucket_start,revision,dimension,value)
TTL toDateTime(bucket_start)+INTERVAL 31 DAY DELETE;

CREATE TABLE IF NOT EXISTS activity_chart_facts_day_v3 (
 bucket_start DateTime('UTC'),sensor_id String,campus_id String,revision UInt64,
 dimension LowCardinality(String),value String,event_count UInt64,
 first_seen DateTime64(6,'UTC'),last_seen DateTime64(6,'UTC')
) ENGINE=MergeTree
PARTITION BY toDate(bucket_start)
ORDER BY(sensor_id,campus_id,bucket_start,revision,dimension,value)
TTL toDateTime(bucket_start)+INTERVAL 31 DAY DELETE;

CREATE TABLE IF NOT EXISTS activity_chart_bucket_versions_v3 (
 granularity LowCardinality(String),bucket_start DateTime('UTC'),
 sensor_id String,campus_id String,revision UInt64,
 source_as_of DateTime64(9,'UTC'),published_at DateTime64(9,'UTC'),finalized UInt8
) ENGINE=ReplacingMergeTree(published_at)
PARTITION BY toYYYYMM(bucket_start)
ORDER BY(granularity,sensor_id,campus_id,bucket_start)
TTL toDateTime(bucket_start)+INTERVAL 31 DAY DELETE;
