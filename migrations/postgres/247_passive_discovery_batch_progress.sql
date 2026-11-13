-- One durable receipt per source batch. Source positions remain in
-- ingest_batches; no per-observation PostgreSQL receipt is added.
CREATE TABLE IF NOT EXISTS passive_discovery_batch_progress (
 batch_id text PRIMARY KEY REFERENCES ingest_batches(batch_id),
 selected_count integer NOT NULL CHECK(selected_count>=0),
 selection_sha256 text NOT NULL CHECK(length(selection_sha256)=64),
 processed_offset integer NOT NULL DEFAULT 0 CHECK(processed_offset>=0),
 first_ingested_at timestamptz,
 verified_at timestamptz,
 archive_verified_at timestamptz,
 completed_at timestamptz,
 lease_owner text NOT NULL DEFAULT '',
 lease_until timestamptz NOT NULL DEFAULT '-infinity',
 next_attempt_at timestamptz NOT NULL DEFAULT now(),
 attempts integer NOT NULL DEFAULT 0,
 last_error text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK(processed_offset<=selected_count)
);
CREATE INDEX IF NOT EXISTS passive_discovery_batch_ready
ON passive_discovery_batch_progress(next_attempt_at,created_at,batch_id)
WHERE completed_at IS NULL;
CREATE INDEX IF NOT EXISTS passive_discovery_batch_oldest
ON passive_discovery_batch_progress(first_ingested_at,batch_id)
WHERE completed_at IS NULL AND first_ingested_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS passive_discovery_batch_ingested
ON passive_discovery_batch_progress(first_ingested_at DESC)
WHERE first_ingested_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS passive_discovery_batch_processed
ON passive_discovery_batch_progress(completed_at DESC)
WHERE completed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS passive_discovery_batch_archived
ON passive_discovery_batch_progress(archive_verified_at DESC)
WHERE archive_verified_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS passive_discovery_batch_archive_gap
ON passive_discovery_batch_progress(first_ingested_at,batch_id)
WHERE archive_verified_at IS NULL AND first_ingested_at IS NOT NULL AND selected_count>0;
