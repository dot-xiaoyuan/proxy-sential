CREATE MATERIALIZED VIEW IF NOT EXISTS router_control_signal_events_v1_mv
TO router_signal_events_v1 AS
SELECT timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,endpoint_id,
 subject_ip,subject_mac,observer_json,payload_json,flow_json,confidence
FROM normalized_events
WHERE source_event_type IN ('vrrp','hsrp');
