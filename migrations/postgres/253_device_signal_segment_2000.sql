-- Packet segments on the mechanical disk now batch up to 2000 events, the
-- same ceiling passive discovery already uses. Stream4 ordinals stay within
-- the existing four-digit locator. Old 1..1000 rows remain valid.
SET LOCAL lock_timeout = '15s';
LOCK TABLE stream_projection_segments IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE stream_discovery_segment_receipt_manifests IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE stream_projection_segments
 DROP CONSTRAINT stream_projection_device_stream4_shape;
ALTER TABLE stream_projection_segments
 ADD CONSTRAINT stream_projection_device_stream4_shape
 CHECK (passive_key_scheme<>'stream4' OR
  (source_kind='device-signals' AND archive_receipt_mode='manifest'
   AND event_count BETWEEN 1 AND 2000)) NOT VALID;

ALTER TABLE stream_discovery_segment_receipt_manifests
 DROP CONSTRAINT stream_discovery_manifest_key_scheme;
ALTER TABLE stream_discovery_segment_receipt_manifests
 ADD CONSTRAINT stream_discovery_manifest_key_scheme
 CHECK (key_scheme IN ('stream2','stream3','stream4','device-signals') AND
  (key_scheme<>'stream4' OR jsonb_array_length(results) BETWEEN 1 AND 2000) AND
  (key_scheme NOT IN ('stream3','stream4') OR
   (scope_id IS NOT NULL AND scope_id<>'' AND length(scope_id)<=256
    AND content_hashes IS NOT NULL
    AND octet_length(content_hashes)=32*jsonb_array_length(results))) AND
  (key_scheme<>'device-signals' OR
   (scope_id IS NULL AND content_hashes IS NULL))) NOT VALID;

CREATE OR REPLACE FUNCTION sentinel_device_stream4_locator(p_epoch text,p_key text)
RETURNS TABLE(segment_id text,ordinal integer) LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE tail text; parts text[];
BEGIN
 IF p_epoch='' OR left(p_key,char_length(p_epoch)+9)<>p_epoch||':stream4-' THEN RETURN; END IF;
 tail:=substr(p_key,char_length(p_epoch)+10);
 parts:=regexp_match(tail,'^([0-9a-f]{64})-(0|[1-9][0-9]{0,3})$');
 IF parts IS NULL THEN RETURN; END IF;
 ordinal:=parts[2]::integer;
 IF ordinal>=2000 THEN RETURN; END IF;
 segment_id:=parts[1];
 RETURN NEXT;
END $$;

CREATE OR REPLACE FUNCTION sentinel_device_stream4_evidence(ref jsonb) RETURNS boolean
LANGUAGE sql STABLE STRICT AS $$
 SELECT EXISTS(
  SELECT 1 FROM sentinel_device_stream4_locator(ref->>'epoch',ref->>'key') loc
  JOIN stream_projection_segments s ON s.segment_id=loc.segment_id
  JOIN stream_discovery_segment_receipt_manifests m ON m.segment_id=s.segment_id
  WHERE s.epoch=ref->>'epoch' AND s.source_kind='device-signals'
   AND s.passive_key_scheme='stream4' AND s.archive_receipt_mode='manifest'
   AND s.projected_at IS NOT NULL AND s.lanes_finalized_at IS NOT NULL
   AND s.source_path<>'' AND s.source_file_id IS NOT NULL AND s.source_file_id<>''
   AND s.source_start_offset IS NOT NULL AND s.source_start_offset>=0
   AND s.source_end_offset>s.source_start_offset AND s.source_generation>=0
   AND s.event_count BETWEEN 1 AND 2000 AND loc.ordinal<s.event_count
   AND s.segment_id=sentinel_stream_source_segment_id(s.epoch,s.source_kind,s.source_path,
    s.source_file_id,s.source_start_offset,s.source_end_offset,s.source_generation)
   AND NOT EXISTS(SELECT 1 FROM stream_discovery_event_keys legacy_key
    WHERE legacy_key.epoch=s.epoch AND legacy_key.scope_id=ref->>'scope'
     AND legacy_key.event_key=ref->>'key')
   AND NOT EXISTS(SELECT 1 FROM stream_discovery_event_keys_compact compact_key
    WHERE compact_key.key_hash=sentinel_stream_discovery_key_hash(s.epoch,ref->>'scope',ref->>'key')
     AND compact_key.epoch=s.epoch AND compact_key.scope_id=ref->>'scope'
     AND compact_key.event_key=ref->>'key')
   AND m.key_scheme='stream4' AND m.scope_id=ref->>'scope'
   AND m.archive_month=to_char(s.accepted_at AT TIME ZONE 'UTC','YYYYMM')
   AND m.body_layout IN ('','v2') AND jsonb_array_length(m.results)=s.event_count
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
   AND NOT EXISTS(SELECT 1 FROM stream_discovery_receipts diagnostic
    WHERE diagnostic.accepted_month=date_trunc('month',s.accepted_at AT TIME ZONE 'UTC')::date
     AND diagnostic.epoch=s.epoch AND diagnostic.scope_id=m.scope_id
     AND diagnostic.event_key=ref->>'key'
     AND (diagnostic.archive_state='failed'
      OR diagnostic.archive_segment_id IS DISTINCT FROM s.segment_id
      OR diagnostic.content_sha256 IS DISTINCT FROM ref->>'sha256'
      OR diagnostic.body_ref IS DISTINCT FROM ref
      OR diagnostic.result IS DISTINCT FROM (m.results->>loc.ordinal)
      OR diagnostic.accepted_at IS NULL OR diagnostic.accepted_at<s.accepted_at
      OR diagnostic.accepted_at>s.accepted_at+interval '1 microsecond')))
$$;
