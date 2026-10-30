-- Store the presentation document on the event-bus current row so the read path
-- no longer has to join the legacy/fresh stream projection.
ALTER TABLE discovery_device_current_shadow
    ADD COLUMN IF NOT EXISTS document JSONB NOT NULL DEFAULT '{}'::jsonb;
