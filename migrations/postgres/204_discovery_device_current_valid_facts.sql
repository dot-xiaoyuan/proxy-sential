-- Track expired/withdrawn facts separately without dropping the current-state
-- observations. The shadow reads `facts` as the currently valid fact map.
ALTER TABLE discovery_device_current_shadow
    ADD COLUMN IF NOT EXISTS expired_fact_count INTEGER NOT NULL DEFAULT 0;
