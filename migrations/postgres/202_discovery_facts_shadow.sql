-- Phase 2c shadow facts for the discovery event bus. Additive and not read by
-- any query path. The final device_current projection is still a separate step.
CREATE TABLE IF NOT EXISTS discovery_service_facts_shadow (
    device_key TEXT NOT NULL,
    fact_key TEXT NOT NULL,
    event_id TEXT NOT NULL,
    sensor_id TEXT NOT NULL DEFAULT '',
    source_id TEXT NOT NULL DEFAULT '',
    site TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    vlan TEXT NOT NULL DEFAULT '',
    interface_name TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT '',
    service_instance TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    mac TEXT NOT NULL DEFAULT '',
    observed_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    withdrawn BOOLEAN NOT NULL DEFAULT FALSE,
    content_hash TEXT NOT NULL DEFAULT '',
    version BIGINT NOT NULL,
    observation JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_key, fact_key)
);
CREATE INDEX IF NOT EXISTS discovery_service_facts_shadow_seen_idx
    ON discovery_service_facts_shadow (device_key, observed_at DESC);
