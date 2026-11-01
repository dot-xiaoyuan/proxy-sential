-- The list reads exact DNS-SD service/port announcements from narrow buckets.
-- Only structured fields and the event key are retained; normalized_events
-- remains the authoritative body. Hourly partitions let four-hour TTL drop
-- whole parts after the two-hour read window. This view takes new input only.
CREATE TABLE IF NOT EXISTS discovery_service_clues_10m (
 window_start DateTime('UTC'),
 sensor_id String,
 source_ip String,
 mac String,
 service_type String,
 service_name String,
 service_target String,
 port Int64,
 last_seen AggregateFunction(max, DateTime64(6,'Asia/Shanghai')),
 evidence_id AggregateFunction(argMax, String, DateTime64(6,'Asia/Shanghai'))
) ENGINE=AggregatingMergeTree
PARTITION BY toStartOfHour(window_start)
ORDER BY (sensor_id,source_ip,window_start,mac,service_type,service_name,service_target,port)
TTL window_start + INTERVAL 4 HOUR DELETE
SETTINGS ttl_only_drop_parts=1;

CREATE MATERIALIZED VIEW IF NOT EXISTS discovery_service_clues_10m_mv
TO discovery_service_clues_10m AS
SELECT toStartOfInterval(timestamp,INTERVAL 10 MINUTE) AS window_start,
 sensor_id,
 subject_ip AS source_ip,
 lower(JSONExtractString(payload_json,'ethernet_source_mac')) AS mac,
 JSONExtractString(payload_json,'service_type') AS service_type,
 JSONExtractString(payload_json,'service_instance') AS service_name,
 JSONExtractString(payload_json,'service_target') AS service_target,
 JSONExtractInt(payload_json,'service_port') AS port,
 maxState(timestamp) AS last_seen,
 argMaxState(event_id,timestamp) AS evidence_id
FROM normalized_events
WHERE source_event_type='dns_sd' AND JSONHas(payload_json,'service_port')
GROUP BY window_start,sensor_id,source_ip,mac,service_type,service_name,service_target,port;
