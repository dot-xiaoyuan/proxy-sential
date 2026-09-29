-- Fine-grained post-cutover idempotency index. The exact event_id remains in
-- the primary key so UInt64 hash collisions cannot suppress a valid event.
-- A fresh cutover is recorded when this migration is deployed; older retries
-- continue through v1 and the bounded legacy path until their TTL expires.
CREATE TABLE IF NOT EXISTS normalized_event_ids_v2 (
 timestamp DateTime64(6,'Asia/Shanghai'),
 event_id String,
 event_id_hash UInt64 MATERIALIZED sipHash64(event_id)
) ENGINE=MergeTree
PARTITION BY toDate(timestamp)
ORDER BY(event_id_hash,event_id,timestamp)
TTL toDateTime(timestamp)+INTERVAL 8 DAY DELETE
SETTINGS index_granularity=64,index_granularity_bytes=0;

CREATE MATERIALIZED VIEW IF NOT EXISTS normalized_event_ids_v2_mv
TO normalized_event_ids_v2 AS
SELECT timestamp,event_id FROM normalized_events;
