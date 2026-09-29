CREATE TABLE IF NOT EXISTS application_connection_observations AS application_latest_observations
ENGINE = ReplacingMergeTree(dedup_version)
PARTITION BY toDate(timestamp)
ORDER BY (sensor_id,campus_id,connection_id,timestamp,event_id)
TTL toDateTime(timestamp) + INTERVAL 7 DAY DELETE;
ALTER TABLE application_connection_observations DROP COLUMN IF EXISTS observation_json;

CREATE MATERIALIZED VIEW IF NOT EXISTS application_connection_observations_mv
TO application_connection_observations AS
SELECT timestamp,sensor_id,event_id,campus_id,ip,connection_id,event_type,domain,source_field,bundle_version,target_id,target_type,name,category,upload_bytes,download_bytes,classification_revision,batch_id
FROM application_observations WHERE event_type!='dns' AND connection_id!='';

CREATE TABLE IF NOT EXISTS application_connection_dirty_log (
 written_at DateTime64(9,'UTC'),sensor_id String,campus_id String,connection_id String
) ENGINE = MergeTree PARTITION BY toDate(written_at)
ORDER BY (written_at,sensor_id,campus_id,connection_id)
TTL toDateTime(written_at) + INTERVAL 7 DAY DELETE;
CREATE MATERIALIZED VIEW IF NOT EXISTS application_connection_dirty_log_mv
TO application_connection_dirty_log AS
SELECT now64(9) AS written_at,sensor_id,campus_id,connection_id
FROM application_connection_observations GROUP BY sensor_id,campus_id,connection_id;

CREATE TABLE IF NOT EXISTS application_connection_summaries (
 sensor_id String,campus_id String,connection_id String,
 first_seen DateTime64(9,'UTC'),last_seen DateTime64(9,'UTC'),
 events Array(Tuple(DateTime64(9,'UTC'),String,String,String,String,String,Nullable(UInt64),Nullable(UInt64),String)),
 revision UInt64
) ENGINE = ReplacingMergeTree(revision)
ORDER BY (sensor_id,campus_id,connection_id)
TTL toDateTime(last_seen) + INTERVAL 7 DAY DELETE;
