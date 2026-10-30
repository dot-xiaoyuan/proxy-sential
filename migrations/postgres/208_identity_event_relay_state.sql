-- Cursor for the identity-session Kafka relay. It reads only updated rows from
-- account_sessions; it does not replay the historical table.
CREATE TABLE IF NOT EXISTS identity_event_relay_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    updated_at TIMESTAMPTZ NOT NULL,
    session_id TEXT NOT NULL DEFAULT ''
);
INSERT INTO identity_event_relay_state(singleton,updated_at,session_id)
VALUES (TRUE, now()-interval '1 minute', '')
ON CONFLICT (singleton) DO NOTHING;
