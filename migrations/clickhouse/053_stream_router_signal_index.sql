-- An eight-day, body-free cursor for the dedicated router recognizer. Fresh
-- stream events enter through the confirmed narrow search insert; legacy
-- normalized_events retain their separate existing reader until retirement.
CREATE TABLE IF NOT EXISTS stream_router_signal_index (
 sensor_id String,
 indexed_at DateTime64(6,'UTC'),
 event_key String,
 scope_id String,
 content_sha256 FixedString(64),
 archive_month UInt32,
 retention_class LowCardinality(String),
 observed_at DateTime64(6,'UTC'),
 protocol LowCardinality(String),
 body_ref String
) ENGINE=MergeTree
PARTITION BY toYYYYMM(indexed_at)
ORDER BY (sensor_id,indexed_at,event_key)
TTL toDateTime(indexed_at)+INTERVAL 8 DAY DELETE
SETTINGS non_replicated_deduplication_window=1000;

CREATE MATERIALIZED VIEW IF NOT EXISTS stream_router_signal_index_mv
TO stream_router_signal_index AS
SELECT sensor_id,indexed_at,event_key,scope_id,content_sha256,
 archive_month,retention_class,observed_at,protocol,body_ref
FROM stream_event_search
WHERE event_type IN ('device','router')
 AND protocol IN ('dhcp','software','lldp','cdp','ssdp','snmp','handshake',
                  'http','ssl','tls','x509','quic','vrrp','hsrp','ttl');
