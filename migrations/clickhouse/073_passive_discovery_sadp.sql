-- Keep the existing passive discovery projection compatible while admitting
-- SADP self-reported product evidence. This changes future inserts only.
ALTER TABLE passive_discovery_events_v2 ADD COLUMN IF NOT EXISTS raw_ref_json String DEFAULT '{}';
DROP VIEW IF EXISTS passive_discovery_events_v2_mv;
CREATE MATERIALIZED VIEW IF NOT EXISTS passive_discovery_events_v2_mv
TO passive_discovery_events_v2 AS
SELECT timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,
 subject_ip,subject_mac,observer_json,payload_json,flow_json,raw_ref_json,confidence
FROM normalized_events
WHERE source_event_type IN ('dhcp','arp','ndp','ssdp','ws_discovery','sadp','lldp','cdp','ieee1905_client_association','ieee1905_topology','ttl','sip')
 OR (source_event_type='mdns' AND JSONExtractBool(payload_json,'is_response'));
