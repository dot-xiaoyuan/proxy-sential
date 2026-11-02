-- A later writer may omit the per-event receipt only when its segment has a
-- durable manifest. Keep existing receipts authoritative while shadow writes
-- are compared; a missing shadow receipt in segment mode must still fail.
SET LOCAL lock_timeout = '5s';

CREATE INDEX stream_projection_segments_manifest_pending_by_epoch
 ON stream_projection_segments(epoch,accepted_at)
 WHERE archive_receipt_mode='manifest' AND lanes_finalized_at IS NULL;

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
    WHERE (k.event_key IS NOT NULL OR kc.event_key IS NOT NULL)
     AND (k.event_key IS NULL OR k.content_sha256=v.content_sha256)
     AND (kc.event_key IS NULL OR kc.content_sha256=v.content_sha256)
     AND (k.event_key IS NULL OR kc.event_key IS NULL OR k.accepted_month=kc.accepted_month)
     AND (
      EXISTS(SELECT 1 FROM stream_discovery_receipts r
       LEFT JOIN stream_projection_segments s ON s.segment_id=r.archive_segment_id
        AND s.epoch=r.epoch AND s.archive_receipt_mode IN ('segment','manifest')
       WHERE r.accepted_month=coalesce(kc.accepted_month,k.accepted_month)
        AND r.epoch=v.epoch AND r.scope_id=v.scope_id AND r.event_key=v.event_key
        AND (r.archive_state='verified'
         OR (r.archive_state<>'failed' AND
          ((r.archive_segment_id IS NULL AND r.archive_state='confirmed')
           OR (r.archive_segment_id IS NOT NULL AND s.lanes_finalized_at IS NOT NULL))))
        AND r.body_ref=ref)
      OR (kc.receipt_segment_id IS NOT NULL
       AND NOT EXISTS(SELECT 1 FROM stream_discovery_receipts r
        WHERE r.accepted_month=kc.accepted_month AND r.epoch=v.epoch
         AND r.scope_id=v.scope_id AND r.event_key=v.event_key)
       AND EXISTS(SELECT 1 FROM stream_discovery_segment_receipt_manifests m
        JOIN stream_projection_segments s ON s.segment_id=m.segment_id
        WHERE m.segment_id=kc.receipt_segment_id AND s.epoch=v.epoch
         AND s.source_kind='passive-discovery' AND s.projected_at IS NOT NULL
         AND s.archive_receipt_mode='manifest' AND s.lanes_finalized_at IS NOT NULL
         AND s.source_file_id IS NOT NULL AND s.source_file_id<>''
         AND s.source_start_offset IS NOT NULL
         AND s.source_end_offset>s.source_start_offset
         AND m.archive_month=to_char(kc.accepted_month,'YYYYMM')
         AND m.body_layout IN ('','v2')
         AND jsonb_array_length(m.results)=s.event_count
         AND kc.receipt_ordinal BETWEEN 0 AND s.event_count-1
         AND jsonb_typeof(m.results->kc.receipt_ordinal)='string'
         AND m.results->>kc.receipt_ordinal<>''
         AND (jsonb_build_object('class','evidence','epoch',v.epoch,
          'scope',v.scope_id,'key',v.event_key,'month',m.archive_month,
          'sha256',v.content_sha256)
          || CASE WHEN m.body_layout<>'' THEN jsonb_build_object('body_layout',m.body_layout)
             ELSE '{}'::jsonb END)=ref))
     ))
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
