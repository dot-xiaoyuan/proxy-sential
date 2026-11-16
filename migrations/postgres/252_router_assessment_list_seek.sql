-- Read router role assessments in confidence/recency order with a seek cursor.
-- The existing device_key/status_rank index supports the per-device winner
-- check; this index lets the outer page stop after limit+1 winners.
-- On a busy existing installation, prebuild this exact index with CREATE INDEX
-- CONCURRENTLY outside the migration transaction, verify pg_index.indisvalid,
-- then apply the migration. PostgreSQL migration files run inside a transaction;
-- lock_timeout limits waiting for a lock, not the duration of a regular build.
-- Prebuild (separate psql session, outside BEGIN):
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS router_assessment_list_seek
--  ON public.router_assessments(confidence DESC,last_seen DESC,assessment_id)
--  WHERE ip IS NOT NULL AND brand_reference_only=false;
-- Verify: SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
--         WHERE c.relname='router_assessment_list_seek';
SET LOCAL lock_timeout = '5s';

DO $$
DECLARE
 index_oid oid := to_regclass('public.router_assessment_list_seek');
 predicate text;
BEGIN
 IF index_oid IS NULL THEN
  -- A populated installation must build this outside the transactional
  -- migration with CONCURRENTLY. The empty-table path serves new installs.
  IF EXISTS (SELECT 1 FROM public.router_assessments LIMIT 1) THEN
   RAISE EXCEPTION 'prebuild router_assessment_list_seek CONCURRENTLY before migration 252 on a populated installation';
  END IF;
  CREATE INDEX router_assessment_list_seek
   ON public.router_assessments(confidence DESC,last_seen DESC,assessment_id)
   WHERE ip IS NOT NULL AND brand_reference_only=false;
  index_oid := to_regclass('public.router_assessment_list_seek');
 END IF;
 SELECT regexp_replace(lower(pg_get_expr(i.indpred,i.indrelid)), '[[:space:]()]', '', 'g')
  INTO predicate FROM pg_index i WHERE i.indexrelid=index_oid;
 IF NOT EXISTS (
  SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
  JOIN pg_am a ON a.oid=c.relam
  WHERE i.indexrelid=index_oid AND i.indrelid='public.router_assessments'::regclass
   AND i.indisvalid AND i.indisready AND i.indislive
   AND NOT i.indisunique AND NOT i.indisexclusion
   AND a.amname='btree' AND i.indnkeyatts=3 AND i.indnatts=3
   AND i.indexprs IS NULL AND i.indoption::text='3 3 0'
   AND pg_get_indexdef(index_oid,1,true)='confidence'
   AND pg_get_indexdef(index_oid,2,true)='last_seen'
   AND pg_get_indexdef(index_oid,3,true)='assessment_id'
   AND predicate IN (
    'ipisnotnullandnotbrand_reference_only',
    'notbrand_reference_onlyandipisnotnull',
    'ipisnotnullandbrand_reference_only=false',
    'brand_reference_only=falseandipisnotnull'
   )
 ) THEN
  RAISE EXCEPTION 'router_assessment_list_seek is invalid or differs from migration 252; inspect before retry';
 END IF;
END $$;
