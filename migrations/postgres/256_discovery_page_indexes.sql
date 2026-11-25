-- Current facts only. The ordered path reuses the existing observation time
-- index. Prebuild on populated installations with the statements produced by
-- scripts/deploy/prebuild-discovery-page-indexes.py before normal migration.
DO $page_indexes$
DECLARE
 spec record; existing oid; target regclass; checked boolean; populated boolean;
 actual text; expected text; ns text := current_schema();
BEGIN
 FOR spec IN SELECT * FROM (
-- BEGIN PAGE INDEX SPECIFICATIONS
VALUES
 ('discovery_page_mac','discovery_list_observation',$key$(lower(raw_mac),base_identity)$key$),
 ('discovery_page_product','discovery_list_observation',$key$(product_type,base_identity)
 WHERE product_status='identified' AND product_type<>''$key$),
 ('discovery_page_dhcp','discovery_list_observation',$key$(dhcp_type,base_identity)
 WHERE origin IN ('dhcp','dhcp_client') AND dhcp_type<>''$key$),
 ('discovery_page_hardware_type','passive_hardware_current',$key$(hardware_type,identity_key)
 WHERE hardware_type<>''$key$),
 ('discovery_page_link_endpoint','discovery_address_link_current',$key$(lower(endpoint_id),observation_id)$key$),
 ('discovery_page_exception_endpoint','discovery_identity_links',$key$(lower(endpoint_id),observation_id)
 WHERE coalesce(basis->>'mac','')='' OR lower(endpoint_id)<>'mac:'||lower(basis->>'mac')$key$),
 ('discovery_page_claimed_mac','discovery_observation_latest',$key$(lower(data->'evidence'->'payload'->>'claimed_mac'),id)
 WHERE origin='sadp' AND NOT withdrawn AND coalesce(data->>'mac','')=''
 AND data->'evidence'->'payload'->>'identity_status'='l2_mismatch'$key$)
-- END PAGE INDEX SPECIFICATIONS
 ) v(index_name,table_name,key_sql) LOOP
   target:=format('%I.%I',ns,spec.table_name)::regclass;
   existing:=to_regclass(format('%I.%I',ns,spec.index_name));
   IF existing IS NULL THEN
     IF current_setting('proxy_sentinel.discovery_page_verify_only',true)='on' THEN
       RAISE EXCEPTION 'missing prebuilt index %',spec.index_name;
     END IF;
     EXECUTE format('SELECT EXISTS(SELECT FROM %s LIMIT 1)',target) INTO populated;
     IF populated THEN RAISE EXCEPTION 'prebuild % concurrently on % before migration 256',spec.index_name,target; END IF;
     EXECUTE format('LOCK TABLE %s IN SHARE MODE NOWAIT',target);
     EXECUTE format('SELECT EXISTS(SELECT FROM %s LIMIT 1)',target) INTO populated;
     IF populated THEN RAISE EXCEPTION 'prebuild % concurrently on % before migration 256',spec.index_name,target; END IF;
     EXECUTE format('CREATE INDEX %I ON %s %s',spec.index_name,target,spec.key_sql);
     existing:=to_regclass(format('%I.%I',ns,spec.index_name));
   END IF;

   -- Generate the canonical expected expression/predicate on an empty local
   -- relation using the running PostgreSQL version. Compare method, ordered
   -- keys, collation, opclass, INCLUDE, options and predicate verbatim.
   EXECUTE format('CREATE TEMP TABLE discovery_page_index_template (LIKE %s) ON COMMIT DROP',target);
   EXECUTE format('CREATE INDEX discovery_page_expected ON pg_temp.discovery_page_index_template %s',spec.key_sql);
   SELECT substring(pg_get_indexdef('pg_temp.discovery_page_expected'::regclass) FROM ' USING .*') INTO expected;
   SELECT i.indrelid=target AND i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique AND NOT i.indisexclusion,
          substring(pg_get_indexdef(i.indexrelid) FROM ' USING .*')
     INTO checked,actual FROM pg_index i WHERE i.indexrelid=existing;
   IF checked IS DISTINCT FROM true OR actual IS DISTINCT FROM expected THEN
     RAISE EXCEPTION 'invalid or mismatched prebuilt index % on %: expected %, got %',spec.index_name,target,expected,actual;
   END IF;
   DROP TABLE pg_temp.discovery_page_index_template;
 END LOOP;
END $page_indexes$;

-- Inverse candidate membership is a superset. The normal reader evaluates
-- capture scope, link priority, trust, time and classification on these facts.
-- A tuple locator is consumed in the same statement (never stored or exported).
CREATE FUNCTION discovery_list_page_sources(keys text[]) RETURNS SETOF tid
LANGUAGE sql STABLE AS $$
 WITH parts AS MATERIALIZED (
  SELECT k,CASE WHEN pg_input_is_valid(k,'jsonb') THEN k::jsonb END a FROM unnest(keys) k
 ), endpoints AS MATERIALIZED (
  SELECT DISTINCT CASE a->>6 WHEN 'mac' THEN 'mac:'||(a->>7) WHEN 'endpoint' THEN a->>7 END e
  FROM parts WHERE a->>0='identity' AND a->>6 IN ('mac','endpoint')
 ), linked AS (
  SELECT c.observation_id FROM endpoints e JOIN discovery_address_link_current c ON lower(c.endpoint_id)=e.e
  UNION ALL
  SELECT i.observation_id FROM discovery_address_link_dirty d JOIN discovery_identity_links i USING(observation_id)
  WHERE lower(i.endpoint_id) IN (SELECT e FROM endpoints)
  UNION ALL
  SELECT i.observation_id FROM endpoints e JOIN discovery_identity_links i ON lower(i.endpoint_id)=e.e
  WHERE coalesce(i.basis->>'mac','')='' OR lower(i.endpoint_id)<>'mac:'||lower(i.basis->>'mac')
 ), claimed AS (
  SELECT o.id FROM endpoints e JOIN discovery_observation_latest o
   ON lower(o.data->'evidence'->'payload'->>'claimed_mac')=substring(e.e FROM 5)
  WHERE e.e LIKE 'mac:%' AND o.origin='sadp' AND NOT o.withdrawn AND coalesce(o.data->>'mac','')=''
  AND o.data->'evidence'->'payload'->>'identity_status'='l2_mismatch'
 )
 SELECT f.ctid FROM unnest(keys) k JOIN discovery_list_observation f ON f.base_identity=k
 UNION ALL SELECT f.ctid FROM linked i JOIN discovery_list_observation f ON f.id=i.observation_id
 UNION ALL SELECT f.ctid FROM claimed s JOIN discovery_list_observation f ON f.id=s.id
 -- Lease endpoints with unusable source MACs resolve to an endpoint key.
 UNION ALL SELECT f.ctid FROM parts p JOIN discovery_list_observation f ON lower(f.raw_mac)=substring(p.a->>7 FROM 5)
  AND (f.sensor_id,f.site_id,f.access_domain,f.vlan,f.vrf)=(p.a->>1,p.a->>2,p.a->>3,p.a->>4,p.a->>5)
 WHERE p.a->>6='endpoint' AND p.a->>7 LIKE 'mac:%'
$$;
