-- Phase 2d shadow device current state. Additive and not read by any query path.
-- facts is a compact fact map built from discovery_service_facts_shadow; the
-- final production projector may replace this with an incremental Redis/PG path.
CREATE TABLE IF NOT EXISTS discovery_device_current_shadow (
    device_key TEXT PRIMARY KEY,
    last_seen TIMESTAMPTZ NOT NULL,
    fact_count INTEGER NOT NULL,
    facts JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS discovery_device_current_shadow_seen_idx
    ON discovery_device_current_shadow (last_seen DESC);

CREATE TABLE IF NOT EXISTS discovery_device_current_shadow_state (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    last_updated_at TIMESTAMPTZ NOT NULL
);
INSERT INTO discovery_device_current_shadow_state(id,last_updated_at)
VALUES (TRUE, '1970-01-01T00:00:00Z')
ON CONFLICT (id) DO NOTHING;
