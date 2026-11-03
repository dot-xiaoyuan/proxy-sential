-- Reader compatibility metadata for a future segment-located passive key.
-- Current stream2 manifests keep their existing authoritative key ledger.
SET LOCAL lock_timeout = '5s';

-- Projection locks its segment row before inserting a receipt manifest.
ALTER TABLE stream_projection_segments
 ADD COLUMN passive_key_scheme text NOT NULL DEFAULT 'legacy',
 ADD COLUMN source_generation bigint NOT NULL DEFAULT 0,
 ADD CONSTRAINT stream_projection_passive_key_scheme
  CHECK (passive_key_scheme IN ('legacy','stream3')) NOT VALID,
 ADD CONSTRAINT stream_projection_source_generation_nonnegative
  CHECK (source_generation>=0) NOT VALID;

ALTER TABLE stream_discovery_segment_receipt_manifests
 ADD COLUMN key_scheme text NOT NULL DEFAULT 'stream2',
 ADD COLUMN scope_id text,
 ADD COLUMN content_hashes bytea;

ALTER TABLE stream_discovery_segment_receipt_manifests
 ADD CONSTRAINT stream_discovery_manifest_key_scheme
 CHECK (key_scheme IN ('stream2','stream3') AND
  (key_scheme <> 'stream3' OR
   (scope_id IS NOT NULL AND scope_id <> '' AND length(scope_id)<=256
    AND content_hashes IS NOT NULL
    AND octet_length(content_hashes)=32*jsonb_array_length(results)))) NOT VALID;

-- Once a stream3 segment is published, its source and receipt identity must
-- remain stable. Finalization is the sole permitted state transition: NULL
-- may become a timestamp once, but that timestamp cannot be withdrawn or
-- replaced. Legacy and stream2 rows keep their previous DML behavior.
CREATE FUNCTION sentinel_protect_stream3_segment_metadata() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  IF OLD.passive_key_scheme='stream3' THEN
   RAISE EXCEPTION 'stream3 segment metadata cannot be deleted';
  END IF;
  RETURN OLD;
 END IF;
 IF OLD.passive_key_scheme='stream3' OR NEW.passive_key_scheme='stream3' THEN
  IF (to_jsonb(NEW)-'lanes_finalized_at') IS DISTINCT FROM
     (to_jsonb(OLD)-'lanes_finalized_at')
   OR (OLD.lanes_finalized_at IS NOT NULL AND
    NEW.lanes_finalized_at IS DISTINCT FROM OLD.lanes_finalized_at)
  THEN RAISE EXCEPTION 'stream3 segment metadata is immutable'; END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE TRIGGER protect_stream3_segment_metadata
BEFORE UPDATE OR DELETE ON stream_projection_segments
FOR EACH ROW EXECUTE FUNCTION sentinel_protect_stream3_segment_metadata();

-- A manifest is the compact per-event proof for the whole segment. Protect
-- every column, including future additions, and require an audited migration
-- before a stream3 manifest can be retired.
CREATE FUNCTION sentinel_protect_stream3_manifest_metadata() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  IF OLD.key_scheme='stream3' THEN
   RAISE EXCEPTION 'stream3 receipt manifest cannot be deleted';
  END IF;
  RETURN OLD;
 END IF;
 IF OLD.key_scheme='stream3' OR NEW.key_scheme='stream3' THEN
  IF to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
   RAISE EXCEPTION 'stream3 receipt manifest is immutable';
  END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE TRIGGER protect_stream3_manifest_metadata
BEFORE UPDATE OR DELETE ON stream_discovery_segment_receipt_manifests
FOR EACH ROW EXECUTE FUNCTION sentinel_protect_stream3_manifest_metadata();

-- PostgreSQL text cannot contain a NUL byte; construct the exact journal
-- source-interval identity as bytea before hashing it.
CREATE FUNCTION sentinel_stream_source_segment_id(p_epoch text,p_source text,p_path text,
 p_file text,p_start bigint,p_end bigint,p_generation bigint) RETURNS text
LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT encode(sha256(
  convert_to(p_epoch,'UTF8')||decode('00','hex')||
  convert_to(p_source,'UTF8')||decode('00','hex')||
  convert_to(p_path,'UTF8')||decode('00','hex')||
  convert_to(p_file,'UTF8')||decode('00','hex')||
  convert_to(p_start::text,'UTF8')||decode('00','hex')||
  convert_to(p_end::text,'UTF8')||
  CASE WHEN p_generation<>0 THEN decode('00','hex')||
   convert_to('generation:'||p_generation::text,'UTF8')
  ELSE decode('','hex') END),'hex')
$$;

-- The exact epoch prefix is compared as text, not as a regex or LIKE
-- pattern, so punctuation in an epoch cannot broaden the accepted keys.
CREATE FUNCTION sentinel_stream3_locator(p_epoch text,p_key text)
RETURNS TABLE(segment_id text,ordinal integer) LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE tail text; parts text[];
BEGIN
 IF p_epoch='' OR left(p_key,char_length(p_epoch)+9)<>p_epoch||':stream3-' THEN RETURN; END IF;
 tail:=substr(p_key,char_length(p_epoch)+10);
 parts:=regexp_match(tail,'^([0-9a-f]{64})-(0|[1-9][0-9]{0,3})$');
 IF parts IS NULL THEN RETURN; END IF;
 ordinal:=parts[2]::integer;
 IF ordinal>=2000 THEN RETURN; END IF;
 segment_id:=parts[1];
 RETURN NEXT;
END $$;

-- Preserve the stream2/legacy proof and add a separate segment-key proof.
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
   -- A stream3 key cannot borrow a legacy per-event ledger to bypass its
   -- segment proof. The application reader follows the same prefix route.
   IF left(ref->>'key',char_length(ref->>'epoch')+9)=(ref->>'epoch')||':stream3-' THEN
    archived:=false;
   END IF;
   IF NOT archived THEN
    SELECT EXISTS(SELECT 1 FROM sentinel_stream3_locator(ref->>'epoch',ref->>'key') loc
     JOIN stream_projection_segments s ON s.segment_id=loc.segment_id
     JOIN stream_discovery_segment_receipt_manifests m ON m.segment_id=s.segment_id
     WHERE s.epoch=ref->>'epoch' AND s.source_kind='passive-discovery'
      AND s.passive_key_scheme='stream3' AND s.archive_receipt_mode='manifest'
      AND s.projected_at IS NOT NULL AND s.lanes_finalized_at IS NOT NULL
      AND s.source_path<>'' AND s.source_file_id IS NOT NULL AND s.source_file_id<>''
      AND s.source_start_offset IS NOT NULL AND s.source_start_offset>=0
      AND s.source_end_offset>s.source_start_offset AND s.source_generation>=0
      AND s.event_count BETWEEN 1 AND 2000 AND loc.ordinal<s.event_count
      AND s.segment_id=sentinel_stream_source_segment_id(s.epoch,s.source_kind,s.source_path,
       s.source_file_id,s.source_start_offset,s.source_end_offset,s.source_generation)
      AND NOT EXISTS(SELECT 1 FROM stream_discovery_event_keys old
       WHERE old.epoch=s.epoch AND old.scope_id=ref->>'scope' AND old.event_key=ref->>'key')
      AND NOT EXISTS(SELECT 1 FROM stream_discovery_event_keys_compact old
       WHERE old.key_hash=sentinel_stream_discovery_key_hash(s.epoch,ref->>'scope',ref->>'key')
        AND old.epoch=s.epoch AND old.scope_id=ref->>'scope' AND old.event_key=ref->>'key')
      AND m.key_scheme='stream3' AND m.scope_id=ref->>'scope'
      AND m.archive_month=to_char(s.accepted_at AT TIME ZONE 'UTC','YYYYMM')
      AND m.body_layout IN ('','v2')
      AND jsonb_array_length(m.results)=s.event_count
      AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(m.results) AS result(value)
       WHERE jsonb_typeof(result.value) IS DISTINCT FROM 'string'
        OR result.value='""'::jsonb)
      AND octet_length(m.content_hashes)=32*s.event_count
      AND jsonb_typeof(m.results->loc.ordinal)='string' AND m.results->>loc.ordinal<>''
      AND encode(substring(m.content_hashes FROM loc.ordinal*32+1 FOR 32),'hex')=ref->>'sha256'
      AND (jsonb_build_object('class','evidence','epoch',s.epoch,'scope',m.scope_id,
       'key',ref->>'key','month',m.archive_month,'sha256',ref->>'sha256')
       || CASE WHEN m.body_layout<>'' THEN jsonb_build_object('body_layout',m.body_layout)
          ELSE '{}'::jsonb END)=ref
      -- Diagnostic rows are optional, but a present row cannot contradict
      -- the immutable segment proof or override an explicit archive failure.
      AND NOT EXISTS(SELECT 1 FROM stream_discovery_receipts diagnostic
       WHERE diagnostic.accepted_month=date_trunc('month',s.accepted_at AT TIME ZONE 'UTC')::date
        AND diagnostic.epoch=s.epoch AND diagnostic.scope_id=m.scope_id
        AND diagnostic.event_key=ref->>'key'
        AND (diagnostic.archive_state='failed'
         OR diagnostic.archive_segment_id IS DISTINCT FROM s.segment_id
         OR diagnostic.content_sha256 IS DISTINCT FROM ref->>'sha256'
         OR diagnostic.body_ref IS DISTINCT FROM ref
         OR diagnostic.result IS DISTINCT FROM (m.results->>loc.ordinal)
         OR diagnostic.accepted_at IS NULL
         OR diagnostic.accepted_at<s.accepted_at
         OR diagnostic.accepted_at>s.accepted_at+interval '1 microsecond')))
    INTO archived;
   END IF;
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
