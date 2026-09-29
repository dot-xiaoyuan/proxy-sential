-- One stable key per connection and observed five-minute bucket. Rebuilding a
-- connection replaces all its retained buckets, including reclassification.
CREATE TABLE IF NOT EXISTS application_connection_bucket_facts (
 bucket_at DateTime('UTC'),sensor_id String,campus_id String,connection_id String,
 bucket_first_seen DateTime64(9,'UTC'),bucket_last_seen DateTime64(9,'UTC'),
 connection_first_seen DateTime64(9,'UTC'),connection_last_seen DateTime64(9,'UTC'),
 bucket_count UInt32,apps Array(String),up Nullable(UInt64),down Nullable(UInt64),
 terminals Array(Tuple(String,String)),label Tuple(String,String),revision UInt64
) ENGINE=ReplacingMergeTree(revision)
PARTITION BY toDate(bucket_at)
ORDER BY (bucket_at,sensor_id,campus_id,connection_id)
TTL toDateTime(bucket_last_seen)+INTERVAL 7 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS application_connection_bucket_facts_mv
TO application_connection_bucket_facts AS
SELECT
 arrayJoin(arrayDistinct(arrayMap(o->toStartOfFiveMinutes(o.1),events))) AS bucket_at,
 sensor_id,campus_id,connection_id,
 arrayMin(arrayMap(o->o.1,arrayFilter(o->toStartOfFiveMinutes(o.1)=bucket_at,events))) AS bucket_first_seen,
 arrayMax(arrayMap(o->o.1,arrayFilter(o->toStartOfFiveMinutes(o.1)=bucket_at,events))) AS bucket_last_seen,
 first_seen AS connection_first_seen,last_seen AS connection_last_seen,
 toUInt32(length(arrayDistinct(arrayMap(o->toStartOfFiveMinutes(o.1),events)))) AS bucket_count,
 summary_apps AS apps,summary_upload AS up,summary_download AS down,
 arrayDistinct(arrayMap(o->tuple(campus_id,o.2),arrayFilter(o->o.2!='' AND toStartOfFiveMinutes(o.1)=bucket_at,events))) AS terminals,
 summary_label AS label,revision
FROM application_connection_summaries_v2;

INSERT INTO application_connection_bucket_facts
SELECT
 arrayJoin(arrayDistinct(arrayMap(o->toStartOfFiveMinutes(o.1),events))) AS bucket_at,
 sensor_id,campus_id,connection_id,
 arrayMin(arrayMap(o->o.1,arrayFilter(o->toStartOfFiveMinutes(o.1)=bucket_at,events))) AS bucket_first_seen,
 arrayMax(arrayMap(o->o.1,arrayFilter(o->toStartOfFiveMinutes(o.1)=bucket_at,events))) AS bucket_last_seen,
 first_seen AS connection_first_seen,last_seen AS connection_last_seen,
 toUInt32(length(arrayDistinct(arrayMap(o->toStartOfFiveMinutes(o.1),events)))) AS bucket_count,
 summary_apps AS apps,summary_upload AS up,summary_download AS down,
 arrayDistinct(arrayMap(o->tuple(campus_id,o.2),arrayFilter(o->o.2!='' AND toStartOfFiveMinutes(o.1)=bucket_at,events))) AS terminals,
 summary_label AS label,revision
FROM application_connection_summaries_v2 FINAL
SETTINGS max_threads=1,max_block_size=1024,min_insert_block_size_rows=8192,min_insert_block_size_bytes=1048576,max_memory_usage=268435456,async_insert=0;
