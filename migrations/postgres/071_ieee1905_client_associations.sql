CREATE TABLE IF NOT EXISTS ieee1905_client_associations (
 sensor_id text NOT NULL,
 campus_id text NOT NULL DEFAULT '',
 access_domain text NOT NULL DEFAULT '',
 gateway_ip inet,
 gateway_mac text NOT NULL,
 bssid text NOT NULL,
 client_mac text NOT NULL,
 association_state text NOT NULL CHECK(association_state IN ('joined','left')),
 first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL,
 last_event_id text NOT NULL,
 source text NOT NULL DEFAULT 'packet-sidecar',
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(sensor_id,gateway_mac,client_mac)
);

CREATE INDEX IF NOT EXISTS ieee1905_client_associations_active_gateway
 ON ieee1905_client_associations(sensor_id,gateway_ip,last_seen DESC,client_mac)
 WHERE association_state='joined' AND gateway_ip IS NOT NULL;

CREATE INDEX IF NOT EXISTS ieee1905_client_associations_client
 ON ieee1905_client_associations(client_mac,last_seen DESC);
