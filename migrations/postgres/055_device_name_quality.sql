-- Remove unusable automatic names only. Raw protocol events and manual notes remain intact.
-- Keep the predicate aligned with usableAutomaticDeviceName and its replay tests.
WITH normalized AS (
 SELECT sensor_id,event_id,source,value,
   regexp_replace(btrim(value),'\.$','') AS name,
   coalesce(evidence->>'kind','hostname') AS kind
 FROM device_name_evidence
 WHERE source IN ('dhcp_fqdn','dhcp_hostname','mdns_hostname','mdns_service')
), labels AS (
 SELECT *, CASE WHEN kind='service' THEN
   regexp_replace(name,'\._[^.]+\._(tcp|udp)\.local$','','i') ELSE name END AS label
 FROM normalized
)
DELETE FROM device_name_evidence n USING labels q
WHERE n.sensor_id=q.sensor_id AND n.event_id=q.event_id AND n.source=q.source AND n.value=q.value
AND (
 q.name='' OR char_length(q.name)>255 OR q.name ~ '[[:cntrl:]]'
 OR (q.kind='service' AND q.name !~* '\._[^.]+\._(tcp|udp)\.local$')
 OR q.label ~ '[_:/\\]'
 OR split_part(q.label,'.',1)=''
 OR split_part(q.label,'.',1) ~* '^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{12,}|([0-9a-f]{2}-){5}[0-9a-f]{2}|[0-9]+)$'
);
