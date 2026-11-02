-- Permit larger passive discovery segments while retaining the existing
-- 1000-event bound for shared file-source receipts. Fence projection at its
-- segment table first, then acquire compact keys and manifest in write order.
SET LOCAL lock_timeout = '5s';
LOCK TABLE stream_projection_segments IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE stream_discovery_event_keys_compact
 DROP CONSTRAINT stream_discovery_compact_receipt_locator,
 ADD CONSTRAINT stream_discovery_compact_receipt_locator
 CHECK ((receipt_segment_id IS NULL AND receipt_ordinal IS NULL)
  OR (receipt_segment_id IS NOT NULL AND receipt_ordinal BETWEEN 0 AND 1999)) NOT VALID;

ALTER TABLE stream_discovery_segment_receipt_manifests
 DROP CONSTRAINT stream_discovery_segment_receipt_manifests_results_check,
 ADD CONSTRAINT stream_discovery_segment_receipt_manifests_results_check
 CHECK (jsonb_typeof(results)='array' AND jsonb_array_length(results) BETWEEN 1 AND 2000) NOT VALID;
