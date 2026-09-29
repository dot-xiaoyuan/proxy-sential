CREATE TABLE IF NOT EXISTS device_name_evidence (
 sensor_id text NOT NULL, event_id text NOT NULL, source text NOT NULL,
 value text NOT NULL, endpoint_id text NOT NULL DEFAULT '', observed_at timestamptz NOT NULL,
 evidence jsonb NOT NULL, processed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(sensor_id,event_id,source,value)
);
CREATE INDEX IF NOT EXISTS device_name_endpoint_time ON device_name_evidence(endpoint_id,observed_at DESC);
CREATE TABLE IF NOT EXISTS device_name_notes (
 endpoint_id text PRIMARY KEY REFERENCES endpoint_entities(endpoint_id),
 value text NOT NULL, updated_by text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS device_name_note_audit (
 id bigserial PRIMARY KEY, endpoint_id text NOT NULL, old_value text NOT NULL,
 new_value text NOT NULL, actor text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
-- Legacy attributes have no reconstructed event reference and remain historical.
INSERT INTO device_name_evidence(sensor_id,event_id,source,value,endpoint_id,observed_at,evidence)
SELECT '', 'legacy:'||e.endpoint_id, n.source, n.value,e.endpoint_id,coalesce(e.last_seen,now()),
 jsonb_build_object('endpoint_id',e.endpoint_id,'value',n.value,'source',n.source,'kind','hostname','sensor_id','','observed_at',coalesce(e.last_seen,now()),'valid_until',coalesce(e.last_seen,now()),'attribution','legacy_attribute')
FROM endpoint_entities e CROSS JOIN LATERAL (VALUES ('dhcp_fqdn',e.attributes->>'client_fqdn'),('dhcp_hostname',e.attributes->>'hostname')) n(source,value)
WHERE coalesce(n.value,'')<>'' ON CONFLICT DO NOTHING;
