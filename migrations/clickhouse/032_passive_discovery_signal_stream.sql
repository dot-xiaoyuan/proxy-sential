-- Narrow, time-ordered input for passive discovery. The materialized view is
-- intentionally created without POPULATE: deployment starts from new traffic
-- and never replays retained normalized events into the discovery read model.
CREATE TABLE IF NOT EXISTS passive_discovery_events_v1 (
 timestamp DateTime64(6,'UTC'),
 event_id String,
 source LowCardinality(String),
 source_event_type LowCardinality(String),
 type LowCardinality(String),
 sensor_id String,
 campus_id String,
 subject_ip String,
 subject_mac String,
 observer_json String,
 payload_json String,
 flow_json String,
 confidence Float64
) ENGINE=MergeTree
PARTITION BY toDate(timestamp)
ORDER BY(sensor_id,timestamp,event_id)
TTL toDateTime(timestamp)+INTERVAL 30 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS passive_discovery_events_v1_mv
TO passive_discovery_events_v1 AS
SELECT timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,
 subject_ip,subject_mac,observer_json,payload_json,flow_json,confidence
FROM normalized_events
WHERE source_event_type IN ('dhcp','arp','ndp','mdns','ssdp','ws_discovery','lldp','cdp','ieee1905_client_association');
