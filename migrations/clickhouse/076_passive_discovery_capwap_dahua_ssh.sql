-- 增量接纳 CAPWAP 无线接入点控制/保活、大华设备发现及 SSH 服务端 Banner 事件进入被动发现管道，
-- 仅作用于后续新写入，不重放历史数据。
DROP VIEW IF EXISTS passive_discovery_events_v2_mv;
CREATE MATERIALIZED VIEW IF NOT EXISTS passive_discovery_events_v2_mv
TO passive_discovery_events_v2 AS
SELECT timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,
 subject_ip,subject_mac,observer_json,payload_json,flow_json,raw_ref_json,confidence
FROM normalized_events
WHERE source_event_type IN ('dhcp','arp','ndp','ssdp','ws_discovery','sadp','capwap','dahua_discovery','lldp','cdp','ieee1905_client_association','ieee1905_topology','ttl','http-device','snmp','tls','ssl','x509','sip','rtsp','bacnet','modbus','ssh')
 OR (source_event_type='mdns' AND JSONExtractBool(payload_json,'is_response'));
