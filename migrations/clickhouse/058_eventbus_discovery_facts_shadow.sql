-- Phase 2b shadow current facts for discovery. Additive and not read by any
-- query path. Each row is the latest observation for one (device_key, fact_key);
-- ReplacingMergeTree(version) makes a late older event lose to a newer one.
CREATE TABLE IF NOT EXISTS eventbus_discovery_facts_shadow
(
    device_key String,
    fact_key String,
    event_id String,
    sensor_id LowCardinality(String),
    source_id LowCardinality(String),
    site LowCardinality(String),
    domain LowCardinality(String),
    vlan String,
    interface_name String,
    protocol LowCardinality(String),
    service_instance String,
    ip String,
    mac String,
    observed_at DateTime64(6, 'UTC'),
    valid_until DateTime64(6, 'UTC'),
    withdrawn UInt8,
    content_hash String,
    version UInt64,
    observation String CODEC(ZSTD(3)),
    consumed_at DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(observed_at)
ORDER BY (device_key, fact_key)
TTL toDateTime(observed_at) + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;
