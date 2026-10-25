-- A case owns a verified copy of its referenced fresh-stream original. This
-- is the deliberate exception to one ordinary authoritative event body.
CREATE TABLE stream_discovery_case_evidence (
 case_id text NOT NULL REFERENCES risk_cases(case_id),
 epoch text NOT NULL,
 scope_id text NOT NULL,
 event_key text NOT NULL,
 content_sha256 text NOT NULL,
 body_ref jsonb NOT NULL,
 document text NOT NULL,
 captured_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(case_id,epoch,scope_id,event_key),
 CHECK(octet_length(document)<=4194304),
 CHECK(encode(sha256(convert_to(document,'UTF8')),'hex')=content_sha256),
 CHECK(jsonb_typeof(document::jsonb)='object')
);

CREATE FUNCTION sentinel_protect_stream_discovery_case_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
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
   SELECT EXISTS(SELECT 1 FROM stream_discovery_event_keys k
    JOIN stream_discovery_receipts r ON r.accepted_month=k.accepted_month
     AND r.epoch=k.epoch AND r.scope_id=k.scope_id AND r.event_key=k.event_key
    WHERE k.epoch=ref->>'epoch' AND k.scope_id=ref->>'scope'
     AND k.event_key=ref->>'key' AND k.content_sha256=ref->>'sha256'
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
CREATE TRIGGER protect_stream_discovery_case_evidence
 AFTER INSERT OR UPDATE OF evidence ON risk_case_evidence_snapshots
 FOR EACH ROW EXECUTE FUNCTION sentinel_protect_stream_discovery_case_evidence();
