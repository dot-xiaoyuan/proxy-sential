CREATE TABLE IF NOT EXISTS normalized_events (
  timestamp DateTime64(6, 'Asia/Shanghai'),
  event_id String,
  schema_version LowCardinality(String),
  source LowCardinality(String),
  source_event_type LowCardinality(String),
  type LowCardinality(String),
  sensor_id LowCardinality(String),
  subject_ip String,
  src_ip String,
  dst_ip String,
  src_port UInt32,
  dst_port UInt32,
  proto LowCardinality(String),
  direction LowCardinality(String),
  observer_json String,
  payload_json String,
  flow_json String,
  raw_ref_json String,
  confidence Float64
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (sensor_id, subject_ip, timestamp, event_id)
TTL toDateTime(timestamp) + INTERVAL 7 DAY;

CREATE TABLE IF NOT EXISTS ingest_diagnostics (
  timestamp DateTime64(6, 'Asia/Shanghai'),
  diagnostic_id String,
  schema_version LowCardinality(String),
  sensor_id LowCardinality(String),
  collector_kind LowCardinality(String),
  collector_version String,
  interface_name String,
  stage LowCardinality(String),
  type LowCardinality(String),
  severity LowCardinality(String),
  summary String,
  counters_json String,
  by_type_json String,
  raw_ref_json String,
  details_json String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (sensor_id, stage, type, timestamp, diagnostic_id)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS collector_event_counts_10m
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(window_start)
ORDER BY (sensor_id, type, window_start)
AS
SELECT
  sensor_id,
  type,
  toStartOfInterval(timestamp, INTERVAL 10 MINUTE) AS window_start,
  count() AS events
FROM normalized_events
GROUP BY sensor_id, type, window_start;

CREATE MATERIALIZED VIEW IF NOT EXISTS ip_event_features_10m
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMMDD(window_start)
ORDER BY (sensor_id, subject_ip, window_start)
AS
SELECT
  sensor_id,
  subject_ip,
  toStartOfInterval(timestamp, INTERVAL 10 MINUTE) AS window_start,
  countState() AS event_count,
  uniqState(type) AS event_type_count,
  uniqState(dst_port) AS dst_port_count
FROM normalized_events
GROUP BY sensor_id, subject_ip, window_start;
