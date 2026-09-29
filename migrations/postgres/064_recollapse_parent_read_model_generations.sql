-- The previous migration can run before an already-running realtime worker is
-- replaced during an in-place upgrade. Collapse any generations it emitted in
-- that interval after workers have been stopped by the rollout procedure.
UPDATE read_model_jobs
SET dirty_generation=processed_generation+1,
    status='pending',
    attempts=0,
    lease_owner='',
    lease_until='-infinity',
    not_before=LEAST(not_before,now()),
    last_error='',
    updated_at=now()
WHERE model IN ('activity-hour-v3','activity-day-v3')
  AND processed_generation<dirty_generation;
