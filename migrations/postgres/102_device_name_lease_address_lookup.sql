-- Name evidence resolves lease ownership by host(ip). The existing inet index
-- cannot serve that expression, causing repeated scans in recognition jobs.
CREATE INDEX IF NOT EXISTS device_address_leases_host_lookup
 ON device_address_leases(sensor_id,campus_id,host(ip),observed_at)
 INCLUDE(endpoint_id,action);
