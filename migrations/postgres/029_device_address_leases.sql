-- Passive DHCP ownership is separate from account identity and observation timestamps.
CREATE TABLE IF NOT EXISTS device_address_leases (
 sensor_id TEXT NOT NULL,
 campus_id TEXT NOT NULL DEFAULT '',
 event_id TEXT NOT NULL,
 ip INET NOT NULL,
 endpoint_id TEXT NOT NULL,
 observed_at TIMESTAMPTZ NOT NULL,
 valid_until TIMESTAMPTZ NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('ack','stop')),
 PRIMARY KEY(sensor_id,campus_id,event_id)
);
CREATE INDEX IF NOT EXISTS device_address_leases_lookup ON device_address_leases(sensor_id,campus_id,ip,observed_at DESC);
