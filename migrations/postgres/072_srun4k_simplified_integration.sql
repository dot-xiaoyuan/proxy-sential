CREATE TABLE IF NOT EXISTS srun4k_integrations (
  connector_id text PRIMARY KEY REFERENCES enforcement_connectors(connector_id) ON DELETE CASCADE,
  host text NOT NULL UNIQUE,
  source text NOT NULL UNIQUE,
  sensor_id text NOT NULL,
  reconcile_interval_hours integer NOT NULL DEFAULT 6 CHECK(reconcile_interval_hours BETWEEN 1 AND 168),
  event_channel_state text NOT NULL DEFAULT 'waiting' CHECK(event_channel_state IN ('waiting','healthy','interrupted')),
  connection_state text NOT NULL DEFAULT 'pending' CHECK(connection_state IN ('pending','healthy','failed')),
  last_error text NOT NULL DEFAULT '',
  last_tested_at timestamptz,
  last_synced_at timestamptz,
  identity_accounts integer NOT NULL DEFAULT 0 CHECK(identity_accounts>=0),
  identity_sessions integer NOT NULL DEFAULT 0 CHECK(identity_sessions>=0),
  products integer NOT NULL DEFAULT 0 CHECK(products>=0),
  groups_count integer NOT NULL DEFAULT 0 CHECK(groups_count>=0),
  controls integer NOT NULL DEFAULT 0 CHECK(controls>=0),
  updated_by text NOT NULL DEFAULT 'system',
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE identity_full_snapshots
  DROP CONSTRAINT IF EXISTS identity_full_snapshots_interval_seconds_check;
ALTER TABLE identity_full_snapshots
  ADD CONSTRAINT identity_full_snapshots_interval_seconds_check
  CHECK(interval_seconds BETWEEN 1 AND 604800);

CREATE TABLE IF NOT EXISTS srun4k_group_catalog (
  source text NOT NULL,
  group_id text NOT NULL,
  name text NOT NULL,
  parent_id text NOT NULL DEFAULT '',
  path text NOT NULL DEFAULT '',
  active boolean NOT NULL DEFAULT true,
  observed_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(source,group_id)
);

CREATE TABLE IF NOT EXISTS identity_snapshot_uploads (
  upload_id text PRIMARY KEY,
  source text NOT NULL,
  sensor_id text NOT NULL,
  campus_id text NOT NULL DEFAULT '',
  access_domain text NOT NULL DEFAULT '',
  observed_at timestamptz NOT NULL,
  interval_seconds integer NOT NULL CHECK(interval_seconds BETWEEN 1 AND 604800),
  expected_count integer NOT NULL CHECK(expected_count BETWEEN 0 AND 200000),
  expected_chunks integer NOT NULL CHECK(expected_chunks BETWEEN 1 AND 200),
  expected_sha256 text NOT NULL,
  status text NOT NULL DEFAULT 'uploading' CHECK(status IN ('uploading','completed','failed')),
  snapshot_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);

CREATE TABLE IF NOT EXISTS identity_snapshot_upload_chunks (
  upload_id text NOT NULL REFERENCES identity_snapshot_uploads(upload_id) ON DELETE CASCADE,
  chunk_index integer NOT NULL CHECK(chunk_index>=0),
  record_count integer NOT NULL CHECK(record_count BETWEEN 0 AND 2000),
  content_sha256 text NOT NULL,
  records jsonb NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(upload_id,chunk_index)
);

CREATE INDEX IF NOT EXISTS identity_snapshot_uploads_created
  ON identity_snapshot_uploads(status,created_at);

CREATE TABLE IF NOT EXISTS notification_outbox (
  notification_id text PRIMARY KEY,
  idempotency_key text NOT NULL UNIQUE,
  account_id text NOT NULL,
  template text NOT NULL,
  parameters jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','sent','failed','cancelled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
