DROP VIEW IF EXISTS router_signal_events_v1_mv;

CREATE MATERIALIZED VIEW router_signal_events_v1_mv
TO router_signal_events_v1 AS
SELECT timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,endpoint_id,
 subject_ip,subject_mac,observer_json,payload_json,flow_json,confidence
FROM normalized_events
WHERE source_event_type IN ('dhcp','software','lldp','cdp','ssdp','snmp')
 OR (source_event_type IN ('http','ssl','tls','x509','quic')
  AND multiSearchAnyCaseInsensitiveUTF8(payload_json,
   ['huawei','honor','h3c','new h3c','comware','airengine','secpath','msr','magic ',
    'tp-link technologies','tplinkcloud.com.cn'])>0);

-- Materialized views only process new rows. Refill the bounded router stream
-- with sanitized SNMP identities retained during the current evidence TTL.
INSERT INTO router_signal_events_v1
SELECT timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,endpoint_id,
 subject_ip,subject_mac,observer_json,payload_json,flow_json,confidence
FROM normalized_events
WHERE timestamp>=now()-INTERVAL 24 HOUR
 AND source_event_type='snmp';
