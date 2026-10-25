-- New discovery tasks use bounded payload segments. Legacy tasks keep their
-- original events document and processing offset; no historical rewrite.
ALTER TABLE discovery_batch_work
 ADD COLUMN selected_event_count integer,
 ADD COLUMN payload_sha256 text;
ALTER TABLE discovery_batch_work
 ADD CONSTRAINT discovery_selected_event_count_valid
 CHECK (selected_event_count IS NULL OR selected_event_count > 0);

CREATE TABLE discovery_batch_segments (
 batch_id text NOT NULL REFERENCES discovery_batch_work(batch_id),
 first_offset integer NOT NULL CHECK (first_offset >= 0),
 event_count integer NOT NULL CHECK (event_count BETWEEN 1 AND 50),
 byte_count integer NOT NULL CHECK (byte_count BETWEEN 2 AND 1048576),
 content_sha256 text NOT NULL,
 events jsonb,
 archive_verified_at timestamptz,
 released_at timestamptz,
 PRIMARY KEY(batch_id,first_offset),
 CHECK ((events IS NULL) = (released_at IS NOT NULL))
);

-- Existing receipts already identify one event revision. The ordinal locates
-- its immutable archive document after the transient segment is released.
ALTER TABLE discovery_event_receipts
 ADD COLUMN event_ordinal integer,
 ADD COLUMN archive_batch_id text,
 ADD COLUMN archive_ordinal integer;
ALTER TABLE discovery_case_evidence_v2 ADD COLUMN content_hash text;

-- Keep case protection working for both task layouts. A released segment must
-- be materialized by the application from the verified archive before the
-- snapshot is inserted; this trigger fails closed if no protected copy exists.
CREATE OR REPLACE FUNCTION sentinel_protect_discovery_case_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ref jsonb; receipt discovery_event_receipts%ROWTYPE; original jsonb; protected_hash text;
BEGIN
 IF NEW.evidence ? 'discovery_evidence_refs' THEN
  IF jsonb_typeof(NEW.evidence->'discovery_evidence_refs') <> 'array' OR jsonb_array_length(NEW.evidence->'discovery_evidence_refs')>100 THEN RAISE EXCEPTION 'invalid discovery evidence references'; END IF;
  FOR ref IN SELECT value FROM jsonb_array_elements(NEW.evidence->'discovery_evidence_refs') LOOP
   SELECT * INTO STRICT receipt FROM discovery_event_receipts WHERE sensor_id=ref->>'sensor_id' AND source_id=ref->>'source_id' AND event_id=ref->>'event_id' AND revision=(ref->>'revision')::bigint;
   original := NULL; protected_hash := NULL;
   SELECT document,content_hash INTO original,protected_hash FROM discovery_case_evidence_v2
    WHERE case_id=NEW.case_id AND sensor_id=receipt.sensor_id AND source_id=receipt.source_id AND event_id=receipt.event_id AND revision=receipt.revision;
   IF original IS NULL THEN
    SELECT item INTO original FROM discovery_batch_work w CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(w.events)='array' THEN w.events ELSE '[]'::jsonb END) item
     WHERE w.batch_id=receipt.batch_id AND item->>'event_id'=receipt.event_id
      AND coalesce((item->'payload'->>'revision')::bigint,0)=receipt.revision
      AND item->'observer'->>'sensor_id'=receipt.sensor_id
      AND coalesce(item->'observer'->>'source_id',item->>'source')=receipt.source_id LIMIT 1;
   END IF;
   IF original IS NULL AND receipt.event_ordinal IS NOT NULL THEN
    SELECT s.events->(receipt.event_ordinal-s.first_offset) INTO original
     FROM discovery_batch_segments s WHERE s.batch_id=receipt.batch_id
      AND receipt.event_ordinal>=s.first_offset AND receipt.event_ordinal<s.first_offset+s.event_count
      AND s.events IS NOT NULL AND jsonb_typeof(s.events)='array' LIMIT 1;
   END IF;
   IF original IS NULL OR (protected_hash IS NOT NULL AND protected_hash<>receipt.content_hash)
    OR (protected_hash IS NULL AND (original->>'event_id'<>receipt.event_id
    OR coalesce((original->'payload'->>'revision')::bigint,0)<>receipt.revision
    OR original->'observer'->>'sensor_id'<>receipt.sensor_id
    OR coalesce(original->'observer'->>'source_id',original->>'source')<>receipt.source_id))
   THEN RAISE EXCEPTION 'discovery original evidence unavailable'; END IF;
   INSERT INTO discovery_case_evidence_v2(case_id,event_id,sensor_id,source_id,revision,document)
    VALUES(NEW.case_id,receipt.event_id,receipt.sensor_id,receipt.source_id,receipt.revision,original) ON CONFLICT DO NOTHING;
   UPDATE discovery_device_changes_v2 SET protected=true WHERE event_id=receipt.event_id
    AND document->'evidence'->'observer'->>'sensor_id'=receipt.sensor_id
    AND coalesce(document->'evidence'->'observer'->>'source_id',document->'evidence'->>'source')=receipt.source_id;
  END LOOP;
 END IF;
 RETURN NEW;
END $$;
