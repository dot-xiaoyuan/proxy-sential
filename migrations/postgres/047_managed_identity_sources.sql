CREATE TABLE enforcement_identity_sources (
 connector_id text PRIMARY KEY REFERENCES enforcement_connectors(connector_id),
 config_version bigint NOT NULL DEFAULT 1,
 public_config jsonb NOT NULL,
 encrypted_token bytea NOT NULL DEFAULT '',
 state text NOT NULL DEFAULT 'pending',
 blocker text NOT NULL DEFAULT 'identity_not_checked',
 last_attempt_at timestamptz,
 last_success_at timestamptz,
 observed_at timestamptz,
 record_count integer NOT NULL DEFAULT 0,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX enforcement_identity_sources_scope ON enforcement_identity_sources ((public_config->>'source'),(public_config->>'sensor_id'),(public_config->>'campus_id'),(public_config->>'access_domain'));
