ALTER TABLE normalized_events
ADD COLUMN IF NOT EXISTS subject_mac String AFTER subject_ip;

CREATE TABLE IF NOT EXISTS router_signal_events_v1 (
 timestamp DateTime64(6,'UTC'),
 event_id String,
 source LowCardinality(String),
 source_event_type LowCardinality(String),
 type LowCardinality(String),
 sensor_id String,
 campus_id String,
 endpoint_id String,
 subject_ip String,
 subject_mac String,
 observer_json String,
 payload_json String,
 flow_json String,
 confidence Float64
) ENGINE=MergeTree
PARTITION BY toDate(timestamp)
ORDER BY(sensor_id,timestamp,event_id)
TTL toDateTime(timestamp)+INTERVAL 8 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS router_signal_events_v1_mv
TO router_signal_events_v1 AS
SELECT timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,endpoint_id,
 subject_ip,subject_mac,observer_json,payload_json,flow_json,confidence
FROM normalized_events
WHERE source_event_type IN ('dhcp','software','lldp','cdp','ssdp')
 OR (source_event_type IN ('http','ssl','tls','x509','quic')
  AND multiSearchAnyCaseInsensitiveUTF8(payload_json,
   ['huawei','honor','h3c','new h3c','comware','airengine','secpath','msr','magic '])>0);
