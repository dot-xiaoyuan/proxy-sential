ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS policy_metadata jsonb NOT NULL DEFAULT '{}';
CREATE TABLE IF NOT EXISTS policy_identity_observations (
 event_id text PRIMARY KEY, observed_at timestamptz NOT NULL, account_id text NOT NULL,
 session_id text NOT NULL, session_data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS policy_identity_account_time ON policy_identity_observations(account_id,observed_at);
CREATE INDEX IF NOT EXISTS policy_identity_time ON policy_identity_observations(observed_at);
CREATE TABLE IF NOT EXISTS account_policy_definitions (id text PRIMARY KEY, document jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS account_policy_executions (id text PRIMARY KEY, document jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE enforcement_actions ADD COLUMN IF NOT EXISTS policy_parameters jsonb NOT NULL DEFAULT '{}';
