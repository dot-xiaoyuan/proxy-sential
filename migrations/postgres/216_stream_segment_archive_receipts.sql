-- Readers can understand segment-confirmed receipts before any writer uses
-- them. Existing receipts remain in event mode and keep their original state.
SET LOCAL lock_timeout = '5s';

ALTER TABLE stream_discovery_receipts
 ADD COLUMN archive_segment_id text;
ALTER TABLE stream_projection_segments
 ADD COLUMN archive_receipt_mode text DEFAULT 'event';
ALTER TABLE stream_projection_segments
 ADD CONSTRAINT stream_projection_archive_receipt_mode
 CHECK (archive_receipt_mode IS NOT NULL AND archive_receipt_mode IN ('event','segment')) NOT VALID;

-- Keep this migration metadata-only. Before enabling segment-mode writes, a
-- later release must add a bounded pending-segment index and freshness read,
-- then replace the old receipt-pending index that would retain every new row.

-- Case protection must use the same effective confirmation as the API. A
-- missing or mismatched segment cannot authorize protection of an original.
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
    LEFT JOIN stream_projection_segments s ON s.segment_id=r.archive_segment_id
     AND s.epoch=r.epoch AND s.archive_receipt_mode='segment'
    WHERE (k.event_key IS NOT NULL OR kc.event_key IS NOT NULL)
     AND (k.event_key IS NULL OR k.content_sha256=v.content_sha256)
     AND (kc.event_key IS NULL OR kc.content_sha256=v.content_sha256)
     AND (k.event_key IS NULL OR kc.event_key IS NULL OR k.accepted_month=kc.accepted_month)
     AND (r.archive_state='verified'
      OR (r.archive_state<>'failed' AND
       ((r.archive_segment_id IS NULL AND r.archive_state='confirmed')
        OR (r.archive_segment_id IS NOT NULL AND s.lanes_finalized_at IS NOT NULL))))
     AND r.body_ref=ref)
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
