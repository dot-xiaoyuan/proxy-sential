-- The census summary and cursor list constrain sensor and time on every read.
-- One index serves both identifier kinds; the added write/index cost is one
-- entry per scoped identifier and is bounded by the current projection size.
CREATE INDEX IF NOT EXISTS passive_census_identifier_sensor_recent
 ON passive_census_identifier_current(sensor_id,last_seen DESC,kind,scope_key,value);
