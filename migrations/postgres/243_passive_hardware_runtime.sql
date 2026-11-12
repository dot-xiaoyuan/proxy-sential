-- Optional bounded retained-evidence bootstrap has a fixed start and durable
-- cursor. Missing original references are counted as gaps, never manufactured.
CREATE TABLE IF NOT EXISTS passive_hardware_runtime (
 sensor_id text PRIMARY KEY,
 backfill_started_at timestamptz NOT NULL DEFAULT now(),
 backfill_cursor text NOT NULL DEFAULT '',
 backfill_complete boolean NOT NULL DEFAULT false,
 backfill_rows bigint NOT NULL DEFAULT 0,
 backfill_missing_refs bigint NOT NULL DEFAULT 0,
 available_from timestamptz,
 last_success_at timestamptz,
 last_error text NOT NULL DEFAULT '',
 updated_at timestamptz NOT NULL DEFAULT now()
);
