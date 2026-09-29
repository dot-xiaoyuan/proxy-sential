CREATE SEQUENCE IF NOT EXISTS application_revision_seq;
CREATE TABLE IF NOT EXISTS application_processing_jobs (
 lane text PRIMARY KEY CHECK (lane IN ('realtime','history','reconcile')),
 job jsonb NOT NULL,
 lease_owner text NOT NULL DEFAULT '',
 lease_until timestamptz NOT NULL DEFAULT '-infinity',
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS application_processing_batches (
 id bigserial PRIMARY KEY,
 lane text NOT NULL REFERENCES application_processing_jobs(lane),
 job_id text NOT NULL,
 after_key text NOT NULL,
 observations jsonb NOT NULL,
 next_job jsonb NOT NULL,
 committed boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(lane,job_id,after_key)
);
CREATE INDEX IF NOT EXISTS application_batches_pending ON application_processing_batches(lane,job_id) WHERE NOT committed;
