-- A separate derived model keeps upgrades resumable and avoids mutating the
-- primary-index settings of an existing ReplacingMergeTree table.
CREATE TABLE IF NOT EXISTS application_connection_summaries_v2
AS application_connection_summaries
ENGINE=ReplacingMergeTree(revision)
ORDER BY (sensor_id,campus_id,connection_id)
TTL toDateTime(last_seen)+INTERVAL 7 DAY DELETE
SETTINGS index_granularity=512,index_granularity_bytes=1048576;

INSERT INTO application_connection_summaries_v2(sensor_id,campus_id,connection_id,first_seen,last_seen,events,revision)
SELECT sensor_id,campus_id,connection_id,first_seen,last_seen,events,revision
FROM application_connection_summaries FINAL
SETTINGS max_threads=1,max_block_size=1024,min_insert_block_size_rows=8192,min_insert_block_size_bytes=1048576,max_memory_usage=268435456,async_insert=0;
