-- Shadow compact receipts alongside the existing per-event receipts. Readers
-- continue to use the old table until a separate compatible release.
SET LOCAL lock_timeout = '5s';

-- Match the projector's segment-then-key lock order.
CREATE TABLE stream_discovery_segment_receipt_manifests (
 segment_id text PRIMARY KEY REFERENCES stream_projection_segments(segment_id),
 archive_month text NOT NULL,
 body_layout text NOT NULL DEFAULT '',
 results jsonb NOT NULL,
 CHECK (jsonb_typeof(results)='array' AND jsonb_array_length(results) BETWEEN 1 AND 1000)
);

ALTER TABLE stream_discovery_event_keys_compact
 ADD COLUMN receipt_segment_id text,
 ADD COLUMN receipt_ordinal integer;
ALTER TABLE stream_discovery_event_keys_compact
 ADD CONSTRAINT stream_discovery_compact_receipt_locator
 CHECK ((receipt_segment_id IS NULL AND receipt_ordinal IS NULL)
  OR (receipt_segment_id IS NOT NULL AND receipt_ordinal BETWEEN 0 AND 999)) NOT VALID;
