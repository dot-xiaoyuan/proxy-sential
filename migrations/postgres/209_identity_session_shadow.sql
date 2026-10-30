-- Kafka-driven identity session shadow. It stores every observed session state;
-- identity_session_open_shadow exposes only sessions without an end time.
CREATE TABLE IF NOT EXISTS identity_session_shadow (
    session_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL DEFAULT '',
    endpoint_id TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    mac TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    sensor_id TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    last_confirmed_at TIMESTAMPTZ,
    identity_confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    vlan TEXT NOT NULL DEFAULT '',
    nas_ip TEXT NOT NULL DEFAULT '',
    session_status TEXT NOT NULL DEFAULT '',
    policy_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_session_shadow_open_idx
    ON identity_session_shadow (updated_at DESC) WHERE ended_at IS NULL;
CREATE OR REPLACE VIEW identity_session_open_shadow AS
SELECT session_id,account_id,endpoint_id,ip,mac,source,sensor_id,started_at,ended_at,
       last_confirmed_at,identity_confidence,vlan,nas_ip,session_status,policy_metadata,updated_at
FROM identity_session_shadow WHERE ended_at IS NULL;
