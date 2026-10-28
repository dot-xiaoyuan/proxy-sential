-- Only CTE data is used; no application tables are read or written.
WITH cases(id,input_patch,endpoints,jobs,expected) AS (VALUES
 ('unique_endpoint','{}'::jsonb,'[{"endpoint_id":"e1","primary_mac":"02:00:00:00:00:01","entity_role":"endpoint"}]'::jsonb,
  '[{"endpoint_id":"e1","dirty_generation":3}]'::jsonb,'[{"endpoint_id":"e1","generation":3}]'::jsonb),
 ('duplicate_mac','{}','[{"endpoint_id":"e1","primary_mac":"02:00:00:00:00:01","entity_role":"endpoint"},{"endpoint_id":"e2","primary_mac":"02:00:00:00:00:01","entity_role":"endpoint"}]',
  '[{"endpoint_id":"e1","dirty_generation":3},{"endpoint_id":"e2","dirty_generation":4}]','[]'),
 ('wrong_role','{}','[{"endpoint_id":"e1","primary_mac":"02:00:00:00:00:01","entity_role":"router"}]','[{"endpoint_id":"e1","dirty_generation":3}]','[]'),
 ('missing_job','{}','[{"endpoint_id":"e1","primary_mac":"02:00:00:00:00:01","entity_role":"endpoint"}]','[]','[]'),
 ('wrong_mac','{}','[{"endpoint_id":"e1","primary_mac":"02:00:00:00:00:02","entity_role":"endpoint"}]','[{"endpoint_id":"e1","dirty_generation":3}]','[]'),
 ('existing_target','{"targets":[{"endpoint_id":"previous","generation":2}]}','[{"endpoint_id":"e1","primary_mac":"02:00:00:00:00:01","entity_role":"endpoint"}]','[{"endpoint_id":"e1","dirty_generation":3}]','[]'),
 ('uppercase_client','{"mac":"02:00:00:00:00:0A"}','[{"endpoint_id":"e1","primary_mac":"02:00:00:00:00:0a","entity_role":"endpoint"}]','[{"endpoint_id":"e1","dirty_generation":9}]','[{"endpoint_id":"e1","generation":9}]'),
 ('unbound_service','{"protocol":"dns_sd","mac":"","ip":"192.0.2.1"}','[{"endpoint_id":"e1","primary_mac":"02:00:00:00:00:01","entity_role":"endpoint"}]','[{"endpoint_id":"e1","dirty_generation":3}]','[]')
), stream_source_cutovers(epoch,state) AS (SELECT NULL::text,NULL::text WHERE false),
stream_discovery_facts AS (
 SELECT NULL::text AS epoch,NULL::text AS protocol,NULL::text AS mac,NULL::text AS ip,
 NULL::text AS sensor_id,NULL::text AS site,NULL::text AS domain,NULL::text AS vlan,
 NULL::text AS vrf,NULL::text AS interface_name,false AS address_binding,false AS withdrawn,
 now() AS observed_at,now() AS valid_until WHERE false
)
SELECT scenario.id,scenario.expected,actual.targets FROM cases scenario
LEFT JOIN LATERAL (
 WITH endpoint_entities AS (
  SELECT * FROM jsonb_to_recordset(scenario.endpoints) e(endpoint_id text,primary_mac text,entity_role text)
 ), endpoint_recognition_jobs AS (
  SELECT * FROM jsonb_to_recordset(scenario.jobs) j(endpoint_id text,dirty_generation bigint)
 )
 SELECT ownership.targets FROM (
  SELECT '{"protocol":"dhcp","mac":"02:00:00:00:00:01"}'::jsonb||scenario.input_patch AS recognition_input
 ) v
 /* TARGETS_LATERAL */
) actual ON true ORDER BY scenario.id;
