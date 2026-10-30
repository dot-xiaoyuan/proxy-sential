-- Phase 2 shadow receipts for the discovery event bus.
-- Additive only: this table is not read by the current query path. It exists to
-- verify Kafka -> consumer -> ClickHouse delivery before any projection switch.
CREATE TABLE IF NOT EXISTS eventbus_discovery_receipts
(
    event_id String,
    device_key String,
    observed_at DateTime64(6, 'UTC'),
    accepted_at DateTime64(6, 'UTC'),
    segment_id String,
    content_hash String,
    sensor_id LowCardinality(String),
    scope_id String,
    source LowCardinality(String),
    source_path String,
    kafka_partition Int32,
    kafka_offset Int64,
    envelope String CODEC(ZSTD(3)),
    consumed_at DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree(consumed_at)
PARTITION BY toYYYYMM(observed_at)
ORDER BY (device_key, observed_at, event_id)
TTL toDateTime(observed_at) + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;
