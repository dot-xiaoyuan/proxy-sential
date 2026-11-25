-- One read-only snapshot of visible identifiers and unexpired binding claims.
-- Copy to a local CSV using psql -Xq -v ON_ERROR_STOP=1; use with inventory_compare.py.
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '30s';
SET LOCAL max_parallel_workers_per_gather = 0;
COPY (
 WITH ids AS MATERIALIZED (
   SELECT scope_key, sensor_id, campus_id, access_domain, vlan, vrf, kind, value, last_event_id
   FROM passive_census_identifier_current
   WHERE sensor_id='campus-204' AND last_seen BETWEEN now()-interval '24 hours' AND now()
 ), records AS MATERIALIZED (
   SELECT kind, sensor_id, campus_id, access_domain, vlan, vrf,
          CASE WHEN kind='ip' THEN value END ip, CASE WHEN kind='mac' THEN value END mac,
          ''::text state, ''::text device_type, ''::text model, last_event_id evidence
   FROM ids
   UNION ALL
   SELECT 'binding', i.sensor_id,i.campus_id,i.access_domain,i.vlan,i.vrf,b.ip,b.mac,
          CASE WHEN b.conflict THEN 'binding_conflict'
               WHEN h.hardware_model_status='conflict' OR h.hardware_type_status='conflict' THEN 'product_conflict'
               ELSE coalesce(h.hardware_type_status,'candidate') END,
          CASE WHEN h.hardware_type_status='identified' THEN h.hardware_type END,
          CASE WHEN h.hardware_model_status='identified' THEN h.hardware_model END, b.evidence_event_id
   FROM ids i JOIN passive_census_binding_current b ON i.kind='ip' AND b.scope_key=i.scope_key AND b.ip=i.value
   LEFT JOIN passive_hardware_current h ON h.sensor_id=i.sensor_id AND h.scope_key=b.scope_key AND h.mac=b.mac
   WHERE NOT b.withdrawn AND b.observed_at<=now() AND b.valid_until>now()
 )
 SELECT 'manifest'::text AS record, ''::text AS sensor, ''::text AS site, ''::text AS domain, ''::text AS vlan,
        ''::text AS vrf,''::text AS ip,''::text AS mac,''::text AS state,''::text AS device_type,''::text AS model,
        ''::text AS evidence,now() AS snapshot_at,(SELECT count(*) FROM records) AS total,
        (SELECT last_source_at FROM passive_census_runtime WHERE sensor_id='campus-204') AS source_through
 UNION ALL
 SELECT kind,sensor_id,campus_id,access_domain,vlan,vrf,ip,mac,state,device_type,model,evidence,NULL,NULL,NULL FROM records
) TO STDOUT WITH CSV HEADER;
ROLLBACK;
