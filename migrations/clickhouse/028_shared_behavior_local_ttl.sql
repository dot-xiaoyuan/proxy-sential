DROP VIEW IF EXISTS shared_behavior_signal_events_v1_mv;

CREATE MATERIALIZED VIEW shared_behavior_signal_events_v1_mv
TO shared_behavior_signal_events_v1 AS
SELECT timestamp,event_id,sensor_id,campus_id,
 JSONExtractString(payload_json,'access_domain') AS access_domain,
 subject_ip,source,
 JSONExtractString(observer_json,'collector_instance_id') AS collector_instance_id,
 feature.1 AS feature_family,feature.2 AS feature_value
FROM normalized_events
ARRAY JOIN arrayFilter(item -> item.2!='', [
 tuple('ua_os',multiIf(
  positionCaseInsensitiveUTF8(JSONExtractString(payload_json,'user_agent'),'android')>0,'Android',
  positionCaseInsensitiveUTF8(JSONExtractString(payload_json,'user_agent'),'iphone')>0 OR positionCaseInsensitiveUTF8(JSONExtractString(payload_json,'user_agent'),'ipad')>0,'iOS',
  positionCaseInsensitiveUTF8(JSONExtractString(payload_json,'user_agent'),'windows')>0,'Windows',
  positionCaseInsensitiveUTF8(JSONExtractString(payload_json,'user_agent'),'mac os')>0 OR positionCaseInsensitiveUTF8(JSONExtractString(payload_json,'user_agent'),'macintosh')>0,'macOS',
  positionCaseInsensitiveUTF8(JSONExtractString(payload_json,'user_agent'),'linux')>0,'Linux','')),
 tuple('ttl_path',if(source_event_type='ttl'
  AND JSONExtractInt(payload_json,'ttl') BETWEEN 1 AND 255
  AND (JSONExtractString(flow_json,'direction')='outbound'
   OR (JSONExtractString(flow_json,'direction')='unknown' AND JSONExtractString(payload_json,'neighbor_mac')!='')),
  concat('initial=',toString(multiIf(JSONExtractInt(payload_json,'ttl')<=32,32,JSONExtractInt(payload_json,'ttl')<=64,64,JSONExtractInt(payload_json,'ttl')<=128,128,255)),
   ',hops=',toString(multiIf(JSONExtractInt(payload_json,'ttl')<=32,32,JSONExtractInt(payload_json,'ttl')<=64,64,JSONExtractInt(payload_json,'ttl')<=128,128,255)-JSONExtractInt(payload_json,'ttl')),
   ',observed=',toString(JSONExtractInt(payload_json,'ttl'))),'')),
 tuple('tcp_stack',if(source_event_type='ttl',JSONExtractString(payload_json,'tcp_stack'),'')),
 tuple('tls_stack',if(JSONExtractString(payload_json,'ja4')!='',concat('ja4:',JSONExtractString(payload_json,'ja4')),if(JSONExtractString(payload_json,'ja3')!='',concat('ja3:',JSONExtractString(payload_json,'ja3')),''))),
 tuple('dhcp_stack',if(source_event_type='dhcp' AND JSONExtractString(payload_json,'requested_options')!='',
  hex(MD5(concat(JSONExtractString(payload_json,'vendor_class'),'|',JSONExtractString(payload_json,'requested_options')))),''))
]) AS feature
WHERE subject_ip!='';

-- Device-signal TTL events describe an internal endpoint even when their
-- aggregate flow direction is unknown. Refill only the new TTL-path feature.
INSERT INTO shared_behavior_signal_events_v1
SELECT timestamp,event_id,sensor_id,campus_id,
 JSONExtractString(payload_json,'access_domain') AS access_domain,
 subject_ip,source,
 JSONExtractString(observer_json,'collector_instance_id') AS collector_instance_id,
 'ttl_path' AS feature_family,
 concat('initial=',toString(multiIf(JSONExtractInt(payload_json,'ttl')<=32,32,JSONExtractInt(payload_json,'ttl')<=64,64,JSONExtractInt(payload_json,'ttl')<=128,128,255)),
  ',hops=',toString(multiIf(JSONExtractInt(payload_json,'ttl')<=32,32,JSONExtractInt(payload_json,'ttl')<=64,64,JSONExtractInt(payload_json,'ttl')<=128,128,255)-JSONExtractInt(payload_json,'ttl')),
  ',observed=',toString(JSONExtractInt(payload_json,'ttl'))) AS feature_value
FROM normalized_events
WHERE timestamp>=now()-INTERVAL 15 MINUTE
 AND subject_ip!=''
 AND source_event_type='ttl'
 AND JSONExtractInt(payload_json,'ttl') BETWEEN 1 AND 255
 AND (JSONExtractString(flow_json,'direction')='outbound'
  OR (JSONExtractString(flow_json,'direction')='unknown' AND JSONExtractString(payload_json,'neighbor_mac')!=''));
