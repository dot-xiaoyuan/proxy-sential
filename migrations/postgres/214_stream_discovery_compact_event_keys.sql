-- Add a smaller primary index for the next passive event-key scheme. The
-- existing ledger remains authoritative for earlier keys and rollback.
CREATE FUNCTION sentinel_stream_discovery_key_hash(epoch text, scope_id text, event_key text)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT sha256(convert_to(jsonb_build_array(epoch,scope_id,event_key)::text,'UTF8'))
$$;

CREATE TABLE stream_discovery_event_keys_compact (
 key_hash bytea PRIMARY KEY,
 epoch text NOT NULL,
 scope_id text NOT NULL,
 event_key text NOT NULL,
 content_sha256 text NOT NULL,
 accepted_month date NOT NULL,
 first_accepted_at timestamptz NOT NULL,
 CHECK(octet_length(key_hash)=32),
 CHECK(key_hash=sentinel_stream_discovery_key_hash(epoch,scope_id,event_key))
);
-- Time is append-oriented; a BRIN gives bounded retention scans without a
-- second per-event B-tree write on the hot path.
CREATE INDEX stream_discovery_event_keys_compact_retention
 ON stream_discovery_event_keys_compact USING brin(first_accepted_at);

-- Both ledgers are readable before compact-only writing is enabled. A v1
-- rollback can still process every segment written during this compatibility
-- release because stream2 keys are dual-written until a compatible previous
-- release is established.
CREATE OR REPLACE FUNCTION sentinel_protect_stream_discovery_case_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ref jsonb; saved stream_discovery_case_evidence%ROWTYPE; archived boolean;
BEGIN
 IF NEW.evidence ? 'stream_discovery_evidence_refs' THEN
  IF jsonb_typeof(NEW.evidence->'stream_discovery_evidence_refs') <> 'array'
   OR jsonb_array_length(NEW.evidence->'stream_discovery_evidence_refs')>100
  THEN RAISE EXCEPTION 'invalid stream discovery evidence references'; END IF;
  FOR ref IN SELECT value FROM jsonb_array_elements(NEW.evidence->'stream_discovery_evidence_refs') LOOP
   IF jsonb_typeof(ref)<>'object' OR ref->>'class'<>'evidence'
    OR coalesce(ref->>'epoch','')='' OR coalesce(ref->>'scope','')=''
    OR coalesce(ref->>'key','')='' OR coalesce(ref->>'month','')=''
    OR coalesce(ref->>'sha256','')=''
   THEN RAISE EXCEPTION 'invalid stream discovery evidence reference'; END IF;
   SELECT EXISTS(SELECT 1 FROM (VALUES (ref->>'epoch',ref->>'scope',ref->>'key',ref->>'sha256'))
    AS v(epoch,scope_id,event_key,content_sha256)
    LEFT JOIN stream_discovery_event_keys k ON k.epoch=v.epoch
     AND k.scope_id=v.scope_id AND k.event_key=v.event_key
    LEFT JOIN stream_discovery_event_keys_compact kc
     ON kc.key_hash=sentinel_stream_discovery_key_hash(v.epoch,v.scope_id,v.event_key)
     AND kc.epoch=v.epoch AND kc.scope_id=v.scope_id AND kc.event_key=v.event_key
    JOIN stream_discovery_receipts r ON r.accepted_month=coalesce(kc.accepted_month,k.accepted_month)
     AND r.epoch=v.epoch AND r.scope_id=v.scope_id AND r.event_key=v.event_key
    WHERE (k.event_key IS NOT NULL OR kc.event_key IS NOT NULL)
     AND (k.event_key IS NULL OR k.content_sha256=v.content_sha256)
     AND (kc.event_key IS NULL OR kc.content_sha256=v.content_sha256)
     AND (k.event_key IS NULL OR kc.event_key IS NULL OR k.accepted_month=kc.accepted_month)
     AND r.archive_state IN ('confirmed','verified') AND r.body_ref=ref)
   INTO archived;
   SELECT * INTO saved FROM stream_discovery_case_evidence
    WHERE case_id=NEW.case_id AND epoch=ref->>'epoch'
     AND scope_id=ref->>'scope' AND event_key=ref->>'key';
   IF NOT archived OR saved.document IS NULL OR saved.content_sha256<>ref->>'sha256'
    OR saved.body_ref<>ref OR encode(sha256(convert_to(saved.document,'UTF8')),'hex')<>saved.content_sha256
   THEN RAISE EXCEPTION 'stream discovery original evidence unavailable'; END IF;
   UPDATE stream_discovery_changes SET protected=true
    WHERE epoch=ref->>'epoch' AND event_key=ref->>'key';
  END LOOP;
 END IF;
 RETURN NEW;
END $$;
