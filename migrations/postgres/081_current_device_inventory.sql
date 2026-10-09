-- Current inventory replaces repeated full history snapshots. Existing history
-- is intentionally left intact; operator-authorized cleanup is a separate action.
CREATE TABLE IF NOT EXISTS device_inventory_current (LIKE device_inventory_snapshots INCLUDING DEFAULTS);
CREATE UNIQUE INDEX IF NOT EXISTS device_inventory_current_key ON device_inventory_current(sensor_id,"window",ip);
CREATE INDEX IF NOT EXISTS device_inventory_current_updated ON device_inventory_current(sensor_id,"window",created_at DESC);
ALTER TABLE device_inventory_current SET (autovacuum_vacuum_scale_factor=0.02,toast.autovacuum_vacuum_scale_factor=0.02);
