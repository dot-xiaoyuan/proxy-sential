CREATE TABLE IF NOT EXISTS activity_rollup_10m (
  bucket DateTime('Asia/Shanghai'),
  sensor_id LowCardinality(String),
  campus_id LowCardinality(String),
  dimension LowCardinality(String),
  value String,
  event_count UInt64,
  last_seen DateTime64(6,'Asia/Shanghai')
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(bucket)
ORDER BY (sensor_id,campus_id,dimension,bucket,value)
TTL bucket + INTERVAL 7 DAY;

CREATE TABLE IF NOT EXISTS activity_rollup_10m_stage AS activity_rollup_10m
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(bucket)
ORDER BY (sensor_id,campus_id,dimension,bucket,value)
TTL bucket + INTERVAL 7 DAY;

CREATE TABLE IF NOT EXISTS activity_rollup_refreshes (
  date Date,
  refreshed_at DateTime64(6,'Asia/Shanghai')
)
ENGINE = ReplacingMergeTree(refreshed_at)
ORDER BY date
TTL date + INTERVAL 8 DAY;
