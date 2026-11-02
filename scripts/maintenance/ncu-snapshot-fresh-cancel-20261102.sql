-- One-time 184 operation after PG223 and the compatible app are installed,
-- while the global snapshot projector is temporarily paused.
-- The user explicitly chose to cancel these 137 pre-b3 projection jobs one by
-- one, retaining each original job, full document, metadata row and hash.
-- Run with psql -X -v ON_ERROR_STOP=1 -f; never move the b3 cutoff.
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
LOCK TABLE identity_snapshot_projection_jobs IN SHARE ROW EXCLUSIVE MODE;

DO $audit$
DECLARE
  boundary timestamptz;
  all_old_jobs bigint;
  old_jobs bigint;
  inserted bigint;
BEGIN
  SELECT c.cutover_at INTO STRICT boundary
  FROM stream_source_cutovers c
  JOIN identity_fresh_recovery_gaps g
    ON g.new_epoch=c.epoch AND g.scope_key=c.source_path
  WHERE c.epoch='identity-fresh-b3-20261102T1227Z'
    AND c.source_kind='identity-http' AND c.sensor_id='ncu-auth-redis'
    AND c.state='active' AND g.state='unverifiable_gap';
  IF EXISTS (SELECT 1 FROM identity_snapshot_projection_cancellations
             WHERE sensor_id='ncu-auth-redis') THEN
    RAISE EXCEPTION 'NCU snapshot cancellation already exists';
  END IF;
  IF EXISTS (
    SELECT 1 FROM identity_snapshot_projection_jobs j
    LEFT JOIN identity_full_snapshots f USING(source,sensor_id,campus_id,access_domain,snapshot_id)
    LEFT JOIN identity_snapshot_log l USING(source,sensor_id,campus_id,access_domain,snapshot_id)
    WHERE j.source='ncu-srun4k' AND j.sensor_id='ncu-auth-redis'
      AND j.campus_id='ncu' AND j.access_domain='campus-auth'
      AND (f.snapshot_id IS NULL OR l.snapshot_id IS NULL
           OR f.content_sha256<>l.content_sha256
           OR f.content_sha256 !~ '^[0-9a-f]{64}$'
           OR f.observed_at<>j.observed_at OR l.observed_at<>j.observed_at
           OR f.received_at<>l.received_at)
  ) THEN
    RAISE EXCEPTION 'NCU snapshot job lacks matching raw, metadata or hash';
  END IF;
  SELECT count(*),count(*) FILTER (WHERE NOT l.projected)
    INTO all_old_jobs,old_jobs
  FROM identity_snapshot_projection_jobs j
  JOIN identity_full_snapshots f USING(source,sensor_id,campus_id,access_domain,snapshot_id)
  JOIN identity_snapshot_log l USING(source,sensor_id,campus_id,access_domain,snapshot_id)
  WHERE j.source='ncu-srun4k' AND j.sensor_id='ncu-auth-redis'
    AND j.campus_id='ncu' AND j.access_domain='campus-auth'
    AND f.received_at<boundary;
  IF all_old_jobs<>137 OR old_jobs<>137 THEN
    RAISE EXCEPTION 'expected 137 unprocessed pre-b3 NCU snapshots, found total % / unprojected %', all_old_jobs,old_jobs;
  END IF;
  IF EXISTS (
    SELECT 1 FROM identity_delta_runs r
    JOIN identity_full_snapshots f USING(source,sensor_id,campus_id,access_domain,snapshot_id)
    WHERE r.source='ncu-srun4k' AND r.sensor_id='ncu-auth-redis'
      AND r.campus_id='ncu' AND r.access_domain='campus-auth'
      AND f.received_at<boundary
  ) THEN
    RAISE EXCEPTION 'pre-b3 NCU snapshot has a delta run to reconcile first';
  END IF;

  INSERT INTO identity_snapshot_projection_cancellations
    (source,sensor_id,campus_id,access_domain,snapshot_id,new_epoch,cutover_at,
     observed_at,received_at,content_sha256,reason)
  SELECT j.source,j.sensor_id,j.campus_id,j.access_domain,j.snapshot_id,
         'identity-fresh-b3-20261102T1227Z',boundary,
         f.observed_at,f.received_at,f.content_sha256,
         'Explicit 2026-11-02 test-environment decision: retire pre-b3 snapshot projection unprocessed; retain its job, original full document and hash'
  FROM identity_snapshot_projection_jobs j
  JOIN identity_full_snapshots f USING(source,sensor_id,campus_id,access_domain,snapshot_id)
  JOIN identity_snapshot_log l USING(source,sensor_id,campus_id,access_domain,snapshot_id)
  WHERE j.source='ncu-srun4k' AND j.sensor_id='ncu-auth-redis'
    AND j.campus_id='ncu' AND j.access_domain='campus-auth'
    AND f.received_at<boundary AND NOT l.projected
  ORDER BY f.received_at,j.snapshot_id;
  GET DIAGNOSTICS inserted=ROW_COUNT;
  IF inserted<>old_jobs THEN
    RAISE EXCEPTION 'cancellation inserted % of % required rows', inserted, old_jobs;
  END IF;
END
$audit$;

SELECT count(*) AS cancelled_unprocessed,
       min(received_at) AS first_received_at,
       max(received_at) AS last_received_at
FROM identity_snapshot_projection_cancellations
WHERE new_epoch='identity-fresh-b3-20261102T1227Z';
COMMIT;
