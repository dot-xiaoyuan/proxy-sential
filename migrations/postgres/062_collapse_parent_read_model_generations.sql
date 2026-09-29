-- A finalized child bucket is a dirty receipt, not a request to rebuild the
-- parent once per child. Collapse pre-fix backlog to one pending generation;
-- future UPSERTs keep this invariant in application code.
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
