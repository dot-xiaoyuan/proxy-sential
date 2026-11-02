-- One-time 184 repair for the migration 198 singleton missing from the live DB.
-- Rebuild only the empty scan cursor. Existing ready keys and fragment states stay.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
LOCK TABLE identity_derived_ready_scan IN SHARE ROW EXCLUSIVE MODE NOWAIT;

DO $repair$
BEGIN
  IF EXISTS (SELECT 1 FROM identity_derived_ready_scan) THEN
    RAISE EXCEPTION 'derived ready scan cursor already exists';
  END IF;
  IF (SELECT count(*) FROM identity_derived_fresh_starts
      WHERE cancel_id = 'ncu-derived-fresh-20261029T051129Z'
        AND sensor_id = 'ncu-auth-redis'
        AND accepted_after = '2026-10-29T05:11:29Z') <> 1 THEN
    RAISE EXCEPTION 'expected immutable NCU derivation boundary is absent';
  END IF;
  IF EXISTS (SELECT 1 FROM identity_ingest_batches
             WHERE sensor_id = 'ncu-auth-redis'
               AND COALESCE(accepted_at, received_at) < '2026-10-29T05:11:29Z') THEN
    RAISE EXCEPTION 'old NCU batches need separate cancellation audit';
  END IF;
  IF (SELECT count(*) FROM pg_trigger
      WHERE tgrelid = 'identity_ingest_batches'::regclass
        AND tgname = 'identity_derived_ready_on_progress'
        AND NOT tgisinternal) <> 1 THEN
    RAISE EXCEPTION 'derived ready progress trigger is absent';
  END IF;

  INSERT INTO identity_derived_ready_scan(id) VALUES (true);
END
$repair$;

SELECT id, cursor_batch, cursor_ordinal, next_scan_at, done
FROM identity_derived_ready_scan WHERE id;
COMMIT;
