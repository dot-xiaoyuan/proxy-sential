-- Optional scoped behavior clues. Only compact derived fields and references
-- are staged. Authoritative traffic remains in the standard-event store.
CREATE TABLE IF NOT EXISTS passive_behavior_batch_work (
 batch_id text NOT NULL,
 segment integer NOT NULL,
 sensor_id text NOT NULL,
 payload jsonb NOT NULL,
 byte_size integer NOT NULL CHECK (byte_size>0 AND byte_size<=2097152),
 payload_sha256 text NOT NULL,
 source_through timestamptz NOT NULL,
 enqueued_at timestamptz NOT NULL DEFAULT now(),
 next_attempt_at timestamptz NOT NULL DEFAULT now(),
 processed_at timestamptz,
 attempts integer NOT NULL DEFAULT 0,
 last_error text NOT NULL DEFAULT '',
 PRIMARY KEY(batch_id,segment)
);
CREATE INDEX IF NOT EXISTS passive_behavior_batch_ready
 ON passive_behavior_batch_work(sensor_id,next_attempt_at,enqueued_at,batch_id,segment) WHERE processed_at IS NULL;

CREATE TABLE IF NOT EXISTS passive_behavior_windows (
 owner_key text NOT NULL,
 sensor_id text NOT NULL,
 bucket_at timestamptz NOT NULL,
 kind text NOT NULL,
 value text NOT NULL,
 first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL,
 first_ingested_at timestamptz NOT NULL,
 event_id text NOT NULL,
 ip inet NOT NULL,
 batch_id text NOT NULL,
 PRIMARY KEY(owner_key,bucket_at,kind,value)
);
CREATE INDEX IF NOT EXISTS passive_behavior_windows_retention ON passive_behavior_windows(first_ingested_at);
