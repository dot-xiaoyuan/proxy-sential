-- One read-only observation. Compare the same generation across snapshots.
BEGIN READ ONLY;
SET LOCAL statement_timeout='8s';
WITH models(model) AS (VALUES ('activity-5m-v3'), ('activity-hour-v3'), ('activity-day-v3')),
jobs AS (
  SELECT model, bucket_start, not_before, attempts, last_error,
    status='running' AND lease_until>=now() AS leased
  FROM read_model_jobs
  WHERE model IN (SELECT model FROM models) AND processed_generation<dirty_generation
)
SELECT now() AS sampled_at,m.model,count(j.model) AS unfinished,
       count(j.model) FILTER(WHERE NOT leased) AS waiting,
       count(j.model) FILTER(WHERE NOT leased AND not_before<=now()) AS due_unclaimed,
       count(j.model) FILTER(WHERE attempts>0 OR last_error<>'') AS errors,
       min(bucket_start) FILTER(WHERE NOT leased) AS oldest_waiting
FROM models m LEFT JOIN jobs j USING(model) GROUP BY m.model ORDER BY m.model;
COMMIT;
