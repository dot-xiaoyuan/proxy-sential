-- Random connection rebuilds touch nearly every 8,192-row mark once a batch
-- contains a few thousand keys. A fine-grained copy keeps the same immutable
-- observation semantics while bounding reads to roughly 64 rows per key.
CREATE TABLE IF NOT EXISTS application_connection_observations_v2
AS application_latest_observations
ENGINE = ReplacingMergeTree(dedup_version)
PARTITION BY toDate(timestamp)
ORDER BY (sensor_id,campus_id,connection_id,timestamp,event_id)
TTL toDateTime(timestamp) + INTERVAL 7 DAY DELETE
SETTINGS index_granularity=64,index_granularity_bytes=262144;

ALTER TABLE application_connection_observations_v2
DROP COLUMN IF EXISTS observation_json;

CREATE MATERIALIZED VIEW IF NOT EXISTS application_connection_observations_v2_mv
TO application_connection_observations_v2 AS
SELECT timestamp,sensor_id,event_id,campus_id,ip,connection_id,event_type,domain,
       source_field,bundle_version,target_id,target_type,name,category,
       upload_bytes,download_bytes,classification_revision,batch_id
FROM application_observations
WHERE event_type!='dns' AND connection_id!='';

INSERT INTO application_connection_observations_v2
(timestamp,sensor_id,event_id,campus_id,ip,connection_id,event_type,domain,
 source_field,bundle_version,target_id,target_type,name,category,upload_bytes,
 download_bytes,classification_revision,batch_id)
SELECT timestamp,sensor_id,event_id,campus_id,ip,connection_id,event_type,domain,
       source_field,bundle_version,target_id,target_type,name,category,upload_bytes,
       download_bytes,classification_revision,batch_id
FROM application_connection_observations
SETTINGS max_threads=2,max_block_size=8192,min_insert_block_size_rows=65536,
         min_insert_block_size_bytes=8388608,max_memory_usage=536870912,
         max_execution_time=120,async_insert=0;
