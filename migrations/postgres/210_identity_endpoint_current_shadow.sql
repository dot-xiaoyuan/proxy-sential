-- Latest open identity session per endpoint, derived from identity_session_shadow.
CREATE TABLE IF NOT EXISTS identity_endpoint_current_shadow (
    endpoint_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    account_id TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    mac TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    vlan TEXT NOT NULL DEFAULT '',
    nas_ip TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ,
    last_confirmed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_endpoint_current_shadow_seen_idx
    ON identity_endpoint_current_shadow (updated_at DESC);
