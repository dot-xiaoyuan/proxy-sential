-- Index the current network-device candidates examined by the shared profile
-- reader in its existing newest-observation order (including ID tie breaking).
-- On populated installations prebuild with scripts/deploy/prebuild-discovery-page-indexes.py
-- passing this migration path. The guard also handles an empty installation.
DO $page_indexes$
DECLARE
 spec record; existing oid; target regclass; checked boolean; populated boolean;
 actual text; expected text; ns text := current_schema();
BEGIN
 FOR spec IN SELECT * FROM (
-- BEGIN PAGE INDEX SPECIFICATIONS
VALUES
 ('discovery_latest_network_device_recent','discovery_observation_latest',$key$(observed_at DESC,id DESC)
 WHERE coalesce(data->>'device_type','') IN ('router','gateway','access_point','switch','network_device')$key$)
-- END PAGE INDEX SPECIFICATIONS
 ) v(index_name,table_name,key_sql) LOOP
   target:=format('%I.%I',ns,spec.table_name)::regclass;
   existing:=to_regclass(format('%I.%I',ns,spec.index_name));
   IF existing IS NULL THEN
     IF current_setting('proxy_sentinel.discovery_page_verify_only',true)='on' THEN
       RAISE EXCEPTION 'missing prebuilt index %',spec.index_name;
     END IF;
     EXECUTE format('SELECT EXISTS(SELECT FROM %s LIMIT 1)',target) INTO populated;
     IF populated THEN RAISE EXCEPTION 'prebuild % concurrently on % before migration 257',spec.index_name,target; END IF;
     EXECUTE format('LOCK TABLE %s IN SHARE MODE NOWAIT',target);
     EXECUTE format('SELECT EXISTS(SELECT FROM %s LIMIT 1)',target) INTO populated;
     IF populated THEN RAISE EXCEPTION 'prebuild % concurrently on % before migration 257',spec.index_name,target; END IF;
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
