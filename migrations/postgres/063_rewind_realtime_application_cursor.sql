-- Revisit the short interval skipped before realtime processing gained a late
-- arrival safety watermark. Existing observations are idempotent by event key.
UPDATE application_processing_jobs
SET job=jsonb_set(
      jsonb_set(job,'{status}',to_jsonb('completed'::text)),
      '{to}',
      to_jsonb(to_char(now()-interval '20 minutes','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
    ),
    lease_owner='',
    lease_until='-infinity',
    updated_at=now()
WHERE lane='realtime';
