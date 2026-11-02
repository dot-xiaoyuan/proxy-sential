-- The reader-compatible release must be the rollback target before new
-- segments use a single finalization witness instead of 1,000 receipt updates.
SET LOCAL lock_timeout = '5s';

-- The segment table is locked before receipts by the live projector. Keep
-- this order for the new pending index and state constraint.
CREATE INDEX stream_projection_segments_pending_archive_by_epoch
 ON stream_projection_segments(epoch,accepted_at)
 WHERE archive_receipt_mode='segment' AND lanes_finalized_at IS NULL;

ALTER TABLE stream_discovery_receipts
 DROP CONSTRAINT stream_discovery_receipts_archive_state_check;
ALTER TABLE stream_discovery_receipts
 ADD CONSTRAINT stream_discovery_receipts_archive_state_check
 CHECK (archive_state IN ('pending','segment','confirmed','verified','failed')
  AND (archive_state<>'segment' OR archive_segment_id IS NOT NULL)) NOT VALID;
