-- A completed realtime cursor can overlap retained observations only when an
-- upgrade explicitly rewound its next window. Preserve that old high-water mark
-- so the application worker deduplicates the replay portion and then returns to
-- its monotonic no-lookup hot path. A currently running post-upgrade job is left
-- unchanged because its durable cursor/pending batches already define progress.
UPDATE application_processing_jobs
SET job = jsonb_set(
      job,
      '{deduplicate_until}',
      to_jsonb(job->>'available_to')
    ),
    updated_at = now()
WHERE lane = 'realtime'
  AND job->>'status' = 'completed'
  AND COALESCE(job->>'available_to', '') <> ''
  AND COALESCE(job->>'to', '') <> ''
  AND (job->>'available_to')::timestamptz > (job->>'to')::timestamptz;
