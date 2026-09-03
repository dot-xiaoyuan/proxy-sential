CREATE TABLE IF NOT EXISTS domain_ecosystem_observations (
  observed_at DateTime64(6, 'Asia/Shanghai'),
  event_id String,
  sensor_id LowCardinality(String),
  campus_id LowCardinality(String),
  endpoint_id String,
  attributed UInt8,
  domain String,
  ecosystem LowCardinality(String),
  event_source LowCardinality(String),
  category LowCardinality(String),
  rule_source String,
  rule_version String,
  confidence Float64,
  updated_at DateTime64(6, 'Asia/Shanghai') DEFAULT now64(6)
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (rule_version, event_id, ecosystem)
TTL toDateTime(observed_at) + INTERVAL 30 DAY;
