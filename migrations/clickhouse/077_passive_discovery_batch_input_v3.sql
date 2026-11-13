-- The ingest batch writes this bounded, idempotent input before confirming its
-- source checkpoint. A failed normalized-event or PostgreSQL commit replays
-- the same batch and ordinal; no asynchronous MV gap can hide the source body.
CREATE TABLE IF NOT EXISTS passive_discovery_events_v3 (
 ingested_at DateTime64(6,'UTC'), batch_started_at DateTime64(6,'UTC'), batch_id String, ordinal UInt32,
 event_content_sha256 String, event_json String,
 timestamp DateTime64(6,'UTC'), event_id String,
 sensor_id String, source_event_type LowCardinality(String)
) ENGINE=ReplacingMergeTree(ingested_at)
PARTITION BY toDate(batch_started_at)
ORDER BY(sensor_id,batch_id,ordinal)
;
-- No age-only TTL: a pending batch may remain unresolved beyond 30 days.
-- Delete a source slice only after its PostgreSQL progress is complete and
-- the one-year evidence archive has been verified. This is a controlled
-- maintenance operation, never an automatic MergeTree expiry.
