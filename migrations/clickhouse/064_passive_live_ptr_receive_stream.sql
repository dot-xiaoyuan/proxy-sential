-- Only a responder's direct-L2 multicast PTR record enters this small
-- receive-ordered lane. Event time alone cannot track late or replayed input.
-- The full standard event and historical passive stream remain unchanged.
CREATE TABLE IF NOT EXISTS passive_live_ptr_events (
 received_at DateTime64(6,'UTC'),
 timestamp DateTime64(6,'UTC'),
 event_id String,
 sensor_id String,
 campus_id String,
 subject_ip String,
 flow_src_ip String,
 flow_dst_ip String,
 interface_name String,
 responder_mac String,
 record_name String,
 service_target String,
 record_ttl_raw String
) ENGINE=MergeTree
PARTITION BY toDate(received_at)
ORDER BY(sensor_id,received_at,event_id)
TTL toDateTime(received_at)+INTERVAL 30 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS passive_live_ptr_events_mv
TO passive_live_ptr_events AS
SELECT now64(6,'UTC') AS received_at,toTimeZone(timestamp,'UTC') AS timestamp,
 event_id,sensor_id,campus_id,subject_ip,
 JSONExtractString(flow_json,'src_ip') AS flow_src_ip,
 JSONExtractString(flow_json,'dst_ip') AS flow_dst_ip,
 JSONExtractString(observer_json,'interface') AS interface_name,
 JSONExtractString(payload_json,'responder_l2_mac') AS responder_mac,
 JSONExtractString(payload_json,'record_name') AS record_name,
 JSONExtractString(payload_json,'service_target') AS service_target,
 JSONExtractRaw(payload_json,'record_ttl') AS record_ttl_raw
FROM normalized_events
WHERE source='zeek' AND source_event_type='mdns'
 AND JSONExtractBool(payload_json,'is_response')
 AND JSONExtractBool(payload_json,'l2_source_mac_direct')
 AND JSONExtractString(payload_json,'record_type')='PTR';
