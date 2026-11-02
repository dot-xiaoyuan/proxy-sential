-- A compatible reader/finalizer release must be the rollback target before
-- enabling manifest-only receipts for new durable passive stream2 segments.
SET LOCAL lock_timeout = '5s';

ALTER TABLE stream_discovery_segment_receipt_manifests
 ADD COLUMN recognition_summary jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE stream_projection_segments
 DROP CONSTRAINT stream_projection_archive_receipt_mode;
ALTER TABLE stream_projection_segments
 ADD CONSTRAINT stream_projection_archive_receipt_mode
 CHECK (archive_receipt_mode IS NOT NULL
  AND archive_receipt_mode IN ('event','segment','manifest')) NOT VALID;

-- The minute observer reads completed and pending manifests by acceptance
-- minute; the pending-only index from migration 219 cannot serve that scan.
CREATE INDEX stream_projection_segments_manifest_by_accepted
 ON stream_projection_segments(accepted_at)
 WHERE archive_receipt_mode='manifest';

-- Only segment metadata is scanned to find acceptance minutes projected late.
CREATE INDEX stream_projection_segments_projected_cursor
 ON stream_projection_segments(projected_at,segment_id);
INSERT INTO read_model_runtime_state(name,state,updated_at)
VALUES('recognition-minute-shadow-projection-cursor',
 jsonb_build_object('projected_at',clock_timestamp(),'segment_id',''),now())
ON CONFLICT DO NOTHING;

-- Existing minute rows predate the durable cursor. New rows enter a bounded
-- ten-minute recheck window after their first calculation.
ALTER TABLE recognition_coverage_minute_shadow
 ADD COLUMN first_computed_at timestamptz NOT NULL DEFAULT '-infinity';
