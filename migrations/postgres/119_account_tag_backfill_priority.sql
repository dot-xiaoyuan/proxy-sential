ALTER TABLE account_tag_projection_jobs
ADD COLUMN IF NOT EXISTS priority SMALLINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS account_tag_projection_jobs_priority_claim
ON account_tag_projection_jobs(priority DESC, not_before, updated_at, account_id)
WHERE dirty_generation > processed_generation;

CREATE OR REPLACE FUNCTION enqueue_account_tag_projection(value TEXT) RETURNS void AS $$
BEGIN
  IF value IS NULL OR btrim(value) = '' THEN RETURN; END IF;
  INSERT INTO account_tag_projection_jobs(account_id, priority) VALUES(value, 100)
  ON CONFLICT(account_id) DO UPDATE SET
    dirty_generation=account_tag_projection_jobs.dirty_generation+1,
    priority=100,
    not_before=now(),
    updated_at=now();
END;
$$ LANGUAGE plpgsql;

UPDATE account_tag_projection_jobs
SET not_before=now() + (mod(abs(hashtext(account_id)::bigint), 86400) * interval '1 second')
WHERE priority=0 AND dirty_generation>processed_generation AND not_before<=now();
