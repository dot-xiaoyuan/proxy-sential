CREATE TABLE IF NOT EXISTS activity_chart_bucket_facts (
 window_start DateTime('UTC'),sensor_id String,campus_id String,dimension LowCardinality(String),value String,
 event_count UInt64,first_seen DateTime64(6,'UTC'),last_seen DateTime64(6,'UTC'),revision UInt64
) ENGINE=ReplacingMergeTree(revision)
PARTITION BY toDate(window_start)
ORDER BY(dimension,window_start,sensor_id,campus_id,value)
TTL toDateTime(last_seen)+INTERVAL 7 DAY DELETE;

CREATE TABLE IF NOT EXISTS activity_chart_dirty_log (
 written_at DateTime64(9,'UTC'),window_start DateTime('UTC'),sensor_id String,campus_id String
) ENGINE=MergeTree PARTITION BY toDate(written_at)
ORDER BY(written_at,window_start,sensor_id,campus_id)
TTL toDateTime(written_at)+INTERVAL 7 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS activity_chart_dirty_log_mv
TO activity_chart_dirty_log AS
SELECT now64(9) AS written_at,toStartOfFiveMinutes(timestamp) AS window_start,sensor_id,campus_id
FROM normalized_event_features GROUP BY window_start,sensor_id,campus_id;
