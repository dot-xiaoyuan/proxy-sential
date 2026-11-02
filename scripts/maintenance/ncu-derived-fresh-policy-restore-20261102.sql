-- One-time 184 test-environment repair after the r60 b3 inbox cutover.
-- Reinstates the user's immutable 2026-10-29 fresh derivation boundary only
-- when no older NCU batch or fragment remains in this PostgreSQL database.
-- Run with psql -X -v ON_ERROR_STOP=1 -f; never edit migration 199.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
-- Freeze inbox inserts while proving the old side of the fixed boundary is empty.
LOCK TABLE identity_ingest_batches, identity_ingest_fragments IN SHARE MODE;
LOCK TABLE identity_derived_fresh_starts, identity_derived_cancel_progress
  IN SHARE ROW EXCLUSIVE MODE NOWAIT;

DO $repair$
DECLARE
  fixed_after CONSTANT timestamptz := '2026-10-29T05:11:29Z';
  fixed_id CONSTANT text := 'ncu-derived-fresh-20261029T051129Z';
  epoch_id CONSTANT text := 'identity-fresh-b3-20261102T1227Z';
BEGIN
  IF EXISTS (SELECT 1 FROM identity_derived_fresh_starts
             WHERE sensor_id = 'ncu-auth-redis' OR cancel_id = fixed_id) THEN
    RAISE EXCEPTION 'NCU derived fresh policy already exists';
  END IF;
  IF (SELECT count(*) FROM identity_fresh_recovery_gaps
      WHERE new_epoch = epoch_id AND state = 'unverifiable_gap'
        AND accepted_sequence = 673156 AND processed_sequence = 672823) <> 1 THEN
    RAISE EXCEPTION 'expected immutable b3 recovery gap is absent';
  END IF;
  IF (SELECT count(*) FROM stream_source_cutovers
      WHERE epoch = epoch_id AND source_kind = 'identity-http'
        AND sensor_id = 'ncu-auth-redis' AND state = 'active') <> 1 THEN
    RAISE EXCEPTION 'expected b3 NCU source is not active';
  END IF;
  IF EXISTS (SELECT 1 FROM identity_materializer_cursors
             WHERE sensor_id = 'ncu-auth-redis') THEN
    RAISE EXCEPTION 'an NCU legacy materializer cursor exists';
  END IF;
  IF EXISTS (SELECT 1 FROM identity_ingest_batches
             WHERE sensor_id = 'ncu-auth-redis'
               AND COALESCE(accepted_at, received_at) < fixed_after) THEN
    RAISE EXCEPTION 'older NCU inbox batches require per-batch cancellation';
  END IF;
  IF EXISTS (SELECT 1 FROM identity_ingest_fragments f
             JOIN identity_ingest_batches b USING (batch_id)
             WHERE b.sensor_id = 'ncu-auth-redis'
               AND COALESCE(b.accepted_at, b.received_at) < fixed_after) THEN
    RAISE EXCEPTION 'older NCU fragments require per-fragment cancellation';
  END IF;

  INSERT INTO identity_derived_fresh_starts
    (cancel_id, sensor_id, accepted_after, reason, legacy_cursors)
  VALUES
    (fixed_id, 'ncu-auth-redis', fixed_after,
     'Restore the user-fixed 2026-10-29 fresh boundary after 184 ledger absence; b3 recovery gap remains unverifiable and no pre-boundary NCU batch or fragment exists in this database',
     '[]'::jsonb);
  -- Zero pre-boundary physical fragments means there is no page to cancel.
  -- This does not mark the separate b2 legacy scope gap as processed.
  INSERT INTO identity_derived_cancel_progress
    (cancel_id, scanned_fragments, cancelled_fragments, cancelled_events, done)
  VALUES (fixed_id, 0, 0, 0, true);
END
$repair$;

SELECT s.cancel_id, s.sensor_id, s.accepted_after,
       p.scanned_fragments, p.cancelled_fragments, p.cancelled_events, p.done
FROM identity_derived_fresh_starts s
JOIN identity_derived_cancel_progress p USING (cancel_id)
WHERE s.cancel_id = 'ncu-derived-fresh-20261029T051129Z';
COMMIT;
