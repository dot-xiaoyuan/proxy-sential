-- Cursor pagination for the shadow current-state read API.
CREATE INDEX IF NOT EXISTS discovery_device_current_shadow_seen_idx
    ON discovery_device_current_shadow (last_seen DESC, device_key);
