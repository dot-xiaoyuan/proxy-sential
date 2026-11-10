-- Time-driven classification changes are refreshed in bounded key batches.
CREATE INDEX IF NOT EXISTS passive_census_terminal_due
 ON passive_census_terminal_current(sensor_id,effective_until,device_key)
 WHERE classification_status<>'expired' AND effective_until IS NOT NULL;
