-- The historical observation body remains in application_observations. This
-- current-classification index keeps only structured filters and an exact
-- (timestamp,sensor_id,event_id,classification_revision,batch_id) locator.
CREATE TABLE IF NOT EXISTS application_latest_observations_v2 (
 timestamp DateTime64(9,'UTC'), sensor_id String, event_id String,
 campus_id String, ip String, connection_id String,
 event_type LowCardinality(String), domain String,
 source_field LowCardinality(String), bundle_version String,
 target_id String, target_type LowCardinality(String), name String,
 category String, upload_bytes Nullable(UInt64),
 download_bytes Nullable(UInt64), classification_revision UInt64,
 batch_id UInt64,
 dedup_version UInt128 MATERIALIZED toUInt128(classification_revision)*toUInt128('18446744073709551616')+toUInt128('18446744073709551615')-toUInt128(batch_id)
) ENGINE=ReplacingMergeTree(dedup_version)
PARTITION BY toDate(timestamp)
ORDER BY(timestamp,sensor_id,event_id)
TTL toDateTime(timestamp)+INTERVAL 7 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS application_latest_observations_v2_mv
TO application_latest_observations_v2 AS
SELECT timestamp,sensor_id,event_id,campus_id,ip,connection_id,event_type,
 domain,source_field,bundle_version,target_id,target_type,name,category,
 upload_bytes,download_bytes,classification_revision,batch_id
FROM application_observations;
