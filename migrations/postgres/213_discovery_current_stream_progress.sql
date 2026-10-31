-- Reconcile active stream device states into the event-bus current ledger in
-- bounded, restartable result-version order. A cursor belongs to an epoch so
-- activating a prepared epoch never inherits another epoch's progress.
CREATE TABLE IF NOT EXISTS discovery_current_stream_progress (
    epoch text PRIMARY KEY,
    last_result_version bigint NOT NULL DEFAULT 0 CHECK (last_result_version >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE discovery_device_current_shadow
    ADD COLUMN IF NOT EXISTS stream_result_version bigint NOT NULL DEFAULT 0;

-- Include presentation epochs that are already inactive at migration time so
-- bounded retirement can remove them without an all-table runtime sweep.
INSERT INTO discovery_current_stream_progress(epoch)
SELECT DISTINCT document->>'epoch' FROM discovery_device_current_shadow
WHERE document ? 'epoch' AND coalesce(document->>'epoch','')<>''
ON CONFLICT (epoch) DO NOTHING;

ALTER TABLE discovery_device_current_shadow_state
    ADD COLUMN IF NOT EXISTS last_fact_change_version bigint NOT NULL DEFAULT 0;
ALTER TABLE discovery_device_current_shadow_state
    ADD COLUMN IF NOT EXISTS last_fact_expiry_at timestamptz NOT NULL DEFAULT '1970-01-01T00:00:00Z';
ALTER TABLE discovery_device_current_shadow_state
    ADD COLUMN IF NOT EXISTS last_fact_expiry_device_key text NOT NULL DEFAULT '';

-- Read benefit: bounded next-state lookup across active epochs. Write cost:
-- one narrow btree entry per stream device state update. The index follows
-- the state table's lifecycle and needs no independent retention policy.
CREATE INDEX IF NOT EXISTS stream_discovery_state_result_version_cursor
    ON stream_discovery_device_state (result_version, epoch, device_key);

-- Versions are allocated under one transaction lock by a table trigger, so a
-- later version cannot commit before an earlier one even while an older fact
-- sink process is restarting after the migration. Seed existing facts once
-- for the new current cursor; this is an explicit migration backfill, not a
-- request-time rebuild. The narrow index adds one entry per changed fact and
-- leaves with the fact table's lifecycle.
CREATE SEQUENCE IF NOT EXISTS discovery_fact_shadow_change_version;
ALTER TABLE discovery_service_facts_shadow
    ADD COLUMN IF NOT EXISTS fact_change_version bigint NOT NULL DEFAULT 0;
UPDATE discovery_service_facts_shadow
SET fact_change_version=nextval('discovery_fact_shadow_change_version')
WHERE fact_change_version=0;
ALTER TABLE discovery_service_facts_shadow
    ALTER COLUMN fact_change_version SET DEFAULT 0;
CREATE OR REPLACE FUNCTION discovery_fact_shadow_stamp_change()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(9184,214);
    NEW.fact_change_version := nextval('discovery_fact_shadow_change_version');
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END $$;
CREATE TRIGGER discovery_fact_shadow_stamp_change
BEFORE INSERT OR UPDATE ON discovery_service_facts_shadow
FOR EACH ROW EXECUTE FUNCTION discovery_fact_shadow_stamp_change();
CREATE INDEX IF NOT EXISTS discovery_service_facts_shadow_change_cursor
    ON discovery_service_facts_shadow (fact_change_version, device_key);

-- Re-evaluate naturally expired facts once by their validity boundary.
CREATE INDEX IF NOT EXISTS discovery_service_facts_shadow_expiry_cursor
    ON discovery_service_facts_shadow (valid_until, device_key)
    WHERE NOT withdrawn AND valid_until IS NOT NULL;

-- A passive-signal page probes at most four recent DHCP facts per requested
-- MAC and active epoch. This adds one index entry per non-withdrawn DHCP fact;
-- old entries leave with the stream fact lifecycle.
CREATE INDEX IF NOT EXISTS stream_discovery_dhcp_mac_recent
    ON stream_discovery_facts (epoch, sensor_id, mac, observed_at DESC, visible_event_key DESC)
    WHERE protocol='dhcp' AND NOT withdrawn AND mac<>'';

-- A cutover clears old-epoch presentation documents in bounded key pages.
CREATE INDEX IF NOT EXISTS discovery_current_shadow_document_epoch
    ON discovery_device_current_shadow ((document->>'epoch'), device_key)
    WHERE document ? 'epoch';
