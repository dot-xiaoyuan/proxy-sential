-- Restore readable legacy DHCP descriptions rejected by the initial punctuation
-- filter. These remain historical attributes without fabricated event references.
INSERT INTO device_name_evidence(sensor_id,event_id,source,value,endpoint_id,observed_at,evidence)
SELECT '', 'legacy:'||e.endpoint_id, n.source, n.value,e.endpoint_id,coalesce(e.last_seen,now()),
 jsonb_build_object('endpoint_id',e.endpoint_id,'value',n.value,'source',n.source,'kind','hostname','sensor_id','','observed_at',coalesce(e.last_seen,now()),'valid_until',coalesce(e.last_seen,now()),'attribution','legacy_attribute')
FROM endpoint_entities e CROSS JOIN LATERAL (VALUES ('dhcp_fqdn',e.attributes->>'client_fqdn'),('dhcp_hostname',e.attributes->>'hostname')) n(source,value)
WHERE char_length(n.value) BETWEEN 1 AND 255
 AND n.value ~ '[_:]' AND n.value !~ '[/\\[:cntrl:]]'
 AND n.value !~ '(^|\.)_' AND split_part(n.value,'.',1)<>''
 AND split_part(n.value,'.',1) !~* '^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{12,}|([0-9a-f]{2}-){5}[0-9a-f]{2}|[0-9]+)$'
 -- Pure IP/MAC strings carry no device description.
 AND n.value !~* '^[0-9a-f:.%-]+$'
ON CONFLICT DO NOTHING;
