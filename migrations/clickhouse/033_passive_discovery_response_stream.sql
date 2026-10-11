-- V2 excludes mDNS questions before they enter the discovery work queue. The
-- source standard events remain immutable in normalized_events; only response
-- evidence is needed by the passive discovery read model.
CREATE TABLE IF NOT EXISTS passive_discovery_events_v2 (
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

CREATE MATERIALIZED VIEW IF NOT EXISTS passive_discovery_events_v2_mv
TO passive_discovery_events_v2 AS
SELECT timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,
 subject_ip,subject_mac,observer_json,payload_json,flow_json,confidence
FROM normalized_events
WHERE source_event_type IN ('dhcp','arp','ndp','ssdp','ws_discovery','lldp','cdp','ieee1905_client_association')
 OR (source_event_type='mdns' AND JSONExtractBool(payload_json,'is_response'));
