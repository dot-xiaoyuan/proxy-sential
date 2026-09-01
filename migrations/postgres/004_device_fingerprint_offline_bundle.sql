ALTER TABLE endpoint_device_profiles
  ADD COLUMN IF NOT EXISTS recognition_conflict BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS device_profile_backfill_jobs (
  version TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  processed INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
