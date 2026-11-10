-- Additive terminal-projection fields. The scoped identity and validity are
-- required for bounded reads; older projection rows remain visible as
-- incomplete until their affected identity is refreshed from source evidence.
ALTER TABLE passive_census_terminal_current
 ADD COLUMN IF NOT EXISTS sensor_id text NOT NULL DEFAULT '',
 ADD COLUMN IF NOT EXISTS campus_id text NOT NULL DEFAULT '',
 ADD COLUMN IF NOT EXISTS access_domain text NOT NULL DEFAULT '',
 ADD COLUMN IF NOT EXISTS vlan text NOT NULL DEFAULT '',
 ADD COLUMN IF NOT EXISTS vrf text NOT NULL DEFAULT '',
 ADD COLUMN IF NOT EXISTS effective_until timestamptz;
CREATE INDEX IF NOT EXISTS passive_census_terminal_sensor_recent
 ON passive_census_terminal_current(sensor_id,last_seen DESC,scope_key,identity_key);
