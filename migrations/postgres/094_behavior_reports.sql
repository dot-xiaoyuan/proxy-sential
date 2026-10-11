-- Northbound security-behaviour reporting. Channels and the outbox are disabled
-- by default: the external platform contract and credentials are site facts.
CREATE TABLE IF NOT EXISTS behavior_report_channels (
  channel_id text PRIMARY KEY,
  name text NOT NULL,
  endpoint_url text NOT NULL DEFAULT '',
  token_endpoint text NOT NULL DEFAULT '',
  token_method text NOT NULL DEFAULT 'GET',
  token_scope text NOT NULL DEFAULT '',
  auth_type text NOT NULL DEFAULT 'none' CHECK(auth_type IN ('none','bearer','oauth2_client_credentials')),
  encrypted_secret text NOT NULL DEFAULT '',
  source_system_ip text NOT NULL DEFAULT '',
  source_system_name text NOT NULL DEFAULT '',
  batch_size integer NOT NULL DEFAULT 100 CHECK(batch_size BETWEEN 1 AND 500),
  flush_interval_seconds integer NOT NULL DEFAULT 1 CHECK(flush_interval_seconds BETWEEN 1 AND 300),
  timeout_seconds integer NOT NULL DEFAULT 10 CHECK(timeout_seconds BETWEEN 1 AND 120),
  tls_skip_verify boolean NOT NULL DEFAULT false,
  field_mapping jsonb NOT NULL DEFAULT '{}'::jsonb,
  success_status_codes integer[] NOT NULL DEFAULT '{200}',
  enabled boolean NOT NULL DEFAULT false,
  revision integer NOT NULL DEFAULT 1 CHECK(revision>=1),
  created_by text NOT NULL DEFAULT '',
  updated_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS behavior_report_outbox (
  report_id text PRIMARY KEY,
  idempotency_key text NOT NULL UNIQUE,
  channel_id text NOT NULL DEFAULT '',
  event_type text NOT NULL CHECK(event_type IN ('poison_behavior','proxy_behavior','ai_relay_audit')),
  subject_type text NOT NULL DEFAULT 'ip',
  subject_id text NOT NULL DEFAULT '',
  account_id text NOT NULL DEFAULT '',
  ip text NOT NULL DEFAULT '',
  target text NOT NULL DEFAULT '',
  target_type text NOT NULL DEFAULT '',
  occurred_at timestamptz NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','sending','sent','failed','cancelled')),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz,
  lease_until timestamptz,
  last_error text NOT NULL DEFAULT '',
  http_status integer NOT NULL DEFAULT 0,
  remote_id text NOT NULL DEFAULT '',
  sent_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS behavior_report_outbox_pending ON behavior_report_outbox(status,next_attempt_at);
CREATE INDEX IF NOT EXISTS behavior_report_outbox_channel ON behavior_report_outbox(channel_id,status,occurred_at DESC);

CREATE TABLE IF NOT EXISTS behavior_report_attempts (
  attempt_id text PRIMARY KEY,
  report_id text NOT NULL REFERENCES behavior_report_outbox(report_id) ON DELETE CASCADE,
  attempt integer NOT NULL,
  status text NOT NULL CHECK(status IN ('sent','failed')),
  http_status integer NOT NULL DEFAULT 0,
  remote_id text NOT NULL DEFAULT '',
  error text NOT NULL DEFAULT '',
  started_at timestamptz NOT NULL,
  finished_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS behavior_report_attempts_report ON behavior_report_attempts(report_id,attempt);
