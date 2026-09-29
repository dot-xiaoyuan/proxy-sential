-- Decode chart fields once during ingestion, rather than parsing retained JSON
-- separately for every chart. Stable event keys collapse backfill/MV overlap.
CREATE TABLE IF NOT EXISTS normalized_event_features (
 timestamp DateTime64(6,'UTC'),event_id String,sensor_id String,campus_id String,
 type LowCardinality(String),proto LowCardinality(String),subject_ip String,
 dst_ip String,dst_port UInt32,dns_query String,http_host String,sni String,
 user_agent String,ja3 String,ja4 String,ttl Int64,app_protocol String
) ENGINE=ReplacingMergeTree
PARTITION BY toDate(timestamp) ORDER BY(timestamp,sensor_id,campus_id,event_id)
TTL toDateTime(timestamp)+INTERVAL 7 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS normalized_event_features_mv
TO normalized_event_features AS
SELECT timestamp,event_id,sensor_id,campus_id,type,proto,subject_ip,dst_ip,dst_port,
 JSONExtractString(payload_json,'query') AS dns_query,
 JSONExtractString(payload_json,'host') AS http_host,
 JSONExtractString(payload_json,'sni') AS sni,
 JSONExtractString(payload_json,'user_agent') AS user_agent,
 JSONExtractString(payload_json,'ja3') AS ja3,
 JSONExtractString(payload_json,'ja4') AS ja4,
 JSONExtractInt(flow_json,'ttl') AS ttl,
 JSONExtractString(flow_json,'app_protocol') AS app_protocol
FROM normalized_events;
