-- SIP phone User-Agent evidence joins the passive discovery projection.
-- Recreate the view so the source filter includes sip; existing rows are not
-- backfilled (the materializer only reads forward from its cursor).
DROP VIEW IF EXISTS passive_discovery_events_v2_mv;
CREATE MATERIALIZED VIEW IF NOT EXISTS passive_discovery_events_v2_mv
TO passive_discovery_events_v2 AS
SELECT timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,
 subject_ip,subject_mac,observer_json,payload_json,flow_json,confidence
FROM normalized_events
WHERE source_event_type IN ('dhcp','arp','ndp','ssdp','ws_discovery','lldp','cdp','ieee1905_client_association','ieee1905_topology','ttl','sip')
 OR (source_event_type='mdns' AND JSONExtractBool(payload_json,'is_response'));
