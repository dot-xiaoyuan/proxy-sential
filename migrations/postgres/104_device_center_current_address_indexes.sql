-- Device-center address validity is evaluated before pagination. Time-leading
-- indexes keep it independent of the size of historical lease/session tables.
-- Only read acceleration: no identity, evidence or policy semantics change.
SET LOCAL lock_timeout = '10s';
CREATE INDEX IF NOT EXISTS device_center_live_lease_lookup
 ON device_address_leases(valid_until,observed_at)
 INCLUDE(sensor_id,campus_id,ip,endpoint_id,event_id,action)
 WHERE action='ack';
CREATE INDEX IF NOT EXISTS device_center_current_session_lookup
 ON account_sessions(updated_at)
 INCLUDE(endpoint_id,ip,started_at)
 WHERE ended_at IS NULL AND endpoint_id IS NOT NULL AND endpoint_id<>'' AND ip IS NOT NULL;
