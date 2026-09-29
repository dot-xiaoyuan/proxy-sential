CREATE TABLE IF NOT EXISTS ingest_checkpoints (
  sensor_id TEXT NOT NULL,
  source_kind TEXT NOT NULL,
  source_path TEXT NOT NULL,
  file_id TEXT NOT NULL,
  committed_offset BIGINT NOT NULL DEFAULT 0,
  last_event_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(sensor_id, source_kind, source_path)
);

CREATE TABLE IF NOT EXISTS ingest_batches (
  batch_id TEXT PRIMARY KEY,
  sensor_id TEXT NOT NULL,
  source_kind TEXT NOT NULL,
  source_path TEXT NOT NULL,
  file_id TEXT NOT NULL,
  start_offset BIGINT NOT NULL,
  end_offset BIGINT NOT NULL,
  checksum TEXT NOT NULL,
  status TEXT NOT NULL,
  event_count BIGINT NOT NULL DEFAULT 0,
  malformed_count BIGINT NOT NULL DEFAULT 0,
  last_error TEXT,
  started_at TIMESTAMPTZ NOT NULL,
  committed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_ingest_batches_source_started
  ON ingest_batches(sensor_id, source_kind, source_path, started_at DESC);
