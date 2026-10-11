-- Notification delivery: the outbox written by the native 4K path becomes
-- drainable. Templates and channels are configuration entities; delivery state
-- lives on the outbox row so "queued" is never presented as "delivered".
ALTER TABLE notification_outbox
  ADD COLUMN IF NOT EXISTS channel_id text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS attempts integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz,
  ADD COLUMN IF NOT EXISTS lease_until timestamptz,
  ADD COLUMN IF NOT EXISTS last_error text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS rendered_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS remote_id text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS sent_at timestamptz;

-- A worker leases a row while it is in flight; a crashed worker's lease expires
-- and the row becomes claimable again.
ALTER TABLE notification_outbox DROP CONSTRAINT IF EXISTS notification_outbox_status_check;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_status_check
  CHECK(status IN ('queued','sending','sent','failed','cancelled'));
CREATE INDEX IF NOT EXISTS notification_outbox_pending ON notification_outbox(status,next_attempt_at);

CREATE TABLE IF NOT EXISTS notification_templates (
  template_id text PRIMARY KEY,
  name text NOT NULL,
  channel_type text NOT NULL DEFAULT '',
  subject text NOT NULL DEFAULT '',
  body text NOT NULL,
  variables jsonb NOT NULL DEFAULT '[]'::jsonb,
  enabled boolean NOT NULL DEFAULT true,
  revision integer NOT NULL DEFAULT 1 CHECK(revision>=1),
  created_by text NOT NULL DEFAULT '',
  updated_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Secrets are sealed with the action master key and are never returned by the API.
CREATE TABLE IF NOT EXISTS notification_channels (
  channel_id text PRIMARY KEY,
  name text NOT NULL,
  channel_type text NOT NULL DEFAULT 'http' CHECK(channel_type IN ('http','srun_sms')),
  endpoint_url text NOT NULL DEFAULT '',
  token_endpoint text NOT NULL DEFAULT '',
  token_scope text NOT NULL DEFAULT '',
  auth_type text NOT NULL DEFAULT 'none' CHECK(auth_type IN ('none','bearer','basic','oauth2_client_credentials')),
  encrypted_secret text NOT NULL DEFAULT '',
  config jsonb NOT NULL DEFAULT '{}'::jsonb,
  is_default boolean NOT NULL DEFAULT false,
  enabled boolean NOT NULL DEFAULT false,
  revision integer NOT NULL DEFAULT 1 CHECK(revision>=1),
  created_by text NOT NULL DEFAULT '',
  updated_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS notification_channels_single_default ON notification_channels(is_default) WHERE is_default;

CREATE TABLE IF NOT EXISTS notification_delivery_attempts (
  attempt_id text PRIMARY KEY,
  notification_id text NOT NULL REFERENCES notification_outbox(notification_id) ON DELETE CASCADE,
  attempt integer NOT NULL,
  status text NOT NULL CHECK(status IN ('sent','failed')),
  http_status integer NOT NULL DEFAULT 0,
  remote_id text NOT NULL DEFAULT '',
  error text NOT NULL DEFAULT '',
  started_at timestamptz NOT NULL,
  finished_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS notification_attempts_notification ON notification_delivery_attempts(notification_id,attempt);
