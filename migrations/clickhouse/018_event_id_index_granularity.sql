-- MergeTree index granularity is immutable after table creation. This table is
-- deliberately not backfilled, so recreating only the post-cutover id index is
-- safe. The rollout records a fresh cutover immediately after this migration.
DROP VIEW IF EXISTS normalized_event_ids_v1_mv;

DROP TABLE IF EXISTS normalized_event_ids_v1;

CREATE TABLE normalized_event_ids_v1 (
 timestamp DateTime64(6,'Asia/Shanghai'),
 event_id String
) ENGINE=MergeTree
PARTITION BY toDate(timestamp)
ORDER BY(event_id,timestamp)
TTL toDateTime(timestamp)+INTERVAL 8 DAY DELETE
SETTINGS index_granularity=256,index_granularity_bytes=0;

CREATE MATERIALIZED VIEW normalized_event_ids_v1_mv
TO normalized_event_ids_v1 AS
SELECT timestamp,event_id FROM normalized_events;
