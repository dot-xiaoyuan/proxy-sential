-- ClaimRiskSubjects selects the oldest eligible subjects with a small LIMIT.
-- Index the same per-sensor order so a normal claim can stop at the limit.
-- first_dirty_at is stable while a subject is pending. Refreshing or leasing
-- an existing pending subject does not change its key in this index.
-- Each pending subject adds one entry, removed when the subject leaves the
-- queue. Keep the existing lease index for queries that filter by lease time.
--
-- On a busy installation this may be built outside the migration transaction:
-- CREATE INDEX CONCURRENTLY risk_feature_dirty_fifo_idx
--  ON public.risk_feature_dirty_subjects(sensor_id,first_dirty_at,subject_type,subject_id);
-- The normal transactional runner still verifies and records this migration.
SET LOCAL lock_timeout = '5s';

DO $$
DECLARE
 index_oid oid := to_regclass('public.risk_feature_dirty_fifo_idx');
BEGIN
 IF index_oid IS NULL THEN
  CREATE INDEX risk_feature_dirty_fifo_idx
   ON public.risk_feature_dirty_subjects(sensor_id,first_dirty_at,subject_type,subject_id);
  index_oid := 'public.risk_feature_dirty_fifo_idx'::regclass;
 END IF;
 IF NOT EXISTS (
  SELECT 1 FROM pg_index
   WHERE indexrelid=index_oid AND indisvalid AND indisready AND indislive
    AND pg_get_indexdef(indexrelid)='CREATE INDEX risk_feature_dirty_fifo_idx ON public.risk_feature_dirty_subjects USING btree (sensor_id, first_dirty_at, subject_type, subject_id)'
 ) THEN
  RAISE EXCEPTION 'risk_feature_dirty_fifo_idx is invalid or differs from migration 255; inspect before retry';
 END IF;
END $$;
