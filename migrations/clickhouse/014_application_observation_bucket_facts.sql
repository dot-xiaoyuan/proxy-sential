CREATE TABLE IF NOT EXISTS application_observation_bucket_facts (
 window_start DateTime('UTC'),sensor_id String,campus_id String,
 bundle_version String,event_type LowCardinality(String),target_type LowCardinality(String),target_id String,
 unknown_domain UInt8,missing_connection UInt8,event_count UInt64,
 name String,category String,last_seen DateTime64(9,'UTC'),terminals Array(Tuple(String,String)),revision UInt64
) ENGINE=ReplacingMergeTree(revision) PARTITION BY toDate(window_start)
ORDER BY(window_start,sensor_id,campus_id,bundle_version,event_type,target_type,target_id,unknown_domain,missing_connection)
TTL window_start+INTERVAL 8 DAY DELETE;

CREATE TABLE IF NOT EXISTS application_observation_dirty_log (
 written_at DateTime64(9,'UTC'),window_start DateTime('UTC'),sensor_id String,campus_id String
) ENGINE=MergeTree PARTITION BY toDate(written_at)
ORDER BY(written_at,window_start,sensor_id,campus_id)
TTL toDateTime(written_at)+INTERVAL 8 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS application_observation_dirty_log_mv TO application_observation_dirty_log AS
SELECT now64(9) AS written_at,toStartOfFiveMinutes(timestamp) AS window_start,sensor_id,campus_id
FROM application_latest_observations GROUP BY window_start,sensor_id,campus_id;
