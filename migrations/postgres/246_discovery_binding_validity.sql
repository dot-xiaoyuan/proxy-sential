-- Device response ownership must retain the full event-time lease semantics.
-- The observed-at index alone can scan years of expired rows for one address;
-- this index seeks on valid_until without inventing a maximum historical TTL.
-- Each non-withdrawn ARP/NDP/DHCP fact with a MAC adds one index entry. Updates
-- maintain that entry; withdrawal and the existing history lifecycle remove it.
-- The older 096 index remains available for the withdrawal anti-join.
--
-- The migration runner is transactional and cannot run CREATE INDEX CONCURRENTLY.
-- On an existing large installation, first run this exact CREATE INDEX outside
-- a transaction with CONCURRENTLY, then run the normal migration runner. The
-- validation below refuses invalid or different same-name indexes before the
-- runner records this file's checksum. No migration ledger is written manually.
SET LOCAL lock_timeout = '5s';
DO $$
DECLARE
 index_oid oid := to_regclass('public.discovery_observation_binding_validity');
BEGIN
 IF index_oid IS NULL THEN
  CREATE INDEX discovery_observation_binding_validity
   ON public.discovery_observations
    ((data->>'node'), (data->>'ip'), valid_until DESC, observed_at DESC, id DESC)
   WHERE origin IN ('dhcp','arp','ndp')
    AND coalesce(data->>'mac','')<>'' AND NOT withdrawn;
  index_oid := to_regclass('public.discovery_observation_binding_validity');
 END IF;
 IF NOT EXISTS (
  SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
  JOIN pg_am a ON a.oid=c.relam
  WHERE i.indexrelid=index_oid AND i.indrelid='public.discovery_observations'::regclass
   AND i.indisvalid AND i.indisready AND i.indislive
   AND NOT i.indisunique AND NOT i.indisexclusion
   AND a.amname='btree' AND i.indnkeyatts=5 AND i.indnatts=5
   AND i.indoption::text='0 0 3 3 3'
   AND pg_get_indexdef(index_oid,1,true)=$expr$(data ->> 'node'::text)$expr$
   AND pg_get_indexdef(index_oid,2,true)=$expr$(data ->> 'ip'::text)$expr$
   AND pg_get_indexdef(index_oid,3,true)='valid_until'
   AND pg_get_indexdef(index_oid,4,true)='observed_at'
   AND pg_get_indexdef(index_oid,5,true)='id'
   AND pg_get_expr(i.indpred,i.indrelid)=$predicate$((origin = ANY (ARRAY['dhcp'::text, 'arp'::text, 'ndp'::text])) AND (COALESCE((data ->> 'mac'::text), ''::text) <> ''::text) AND (NOT withdrawn))$predicate$
   AND pg_get_indexdef(index_oid)=$definition$CREATE INDEX discovery_observation_binding_validity ON public.discovery_observations USING btree (((data ->> 'node'::text)), ((data ->> 'ip'::text)), valid_until DESC, observed_at DESC, id DESC) WHERE ((origin = ANY (ARRAY['dhcp'::text, 'arp'::text, 'ndp'::text])) AND (COALESCE((data ->> 'mac'::text), ''::text) <> ''::text) AND (NOT withdrawn))$definition$
 ) THEN
  RAISE EXCEPTION 'discovery_observation_binding_validity is invalid or differs from migration 246; inspect before retry';
 END IF;
END $$;
