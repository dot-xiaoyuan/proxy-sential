CREATE TABLE IF NOT EXISTS enforcement_4k_databases (
    connector_id text PRIMARY KEY REFERENCES enforcement_connectors(connector_id) ON DELETE CASCADE,
    public_config jsonb NOT NULL,
    encrypted_password bytea NOT NULL,
    updated_by text NOT NULL DEFAULT 'system',
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
