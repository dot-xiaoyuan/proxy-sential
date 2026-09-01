ALTER TABLE identity_ingest_batches ADD COLUMN IF NOT EXISTS normalized_events JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE identity_ingest_batches ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE identity_ingest_batches ADD COLUMN IF NOT EXISTS last_retried_at TIMESTAMPTZ;
