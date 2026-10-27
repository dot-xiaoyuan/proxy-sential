-- Preserve every authoritative event and search row. Router recognition has
-- already excluded pure packet TTL from scoring; avoid indexing new weak rows.
-- The default keeps rows written by the old application eligible during the
-- migration-to-release interval. Old index rows remain for durable replay.
ALTER TABLE stream_event_search
ADD COLUMN IF NOT EXISTS router_score_possible UInt8 DEFAULT 1;

-- Create the replacement before removing the old view: concurrent inserts
-- may duplicate a row briefly, which the cursor reader checks and deduplicates.
CREATE MATERIALIZED VIEW IF NOT EXISTS stream_router_signal_index_mv_v2
TO stream_router_signal_index AS
SELECT sensor_id,indexed_at,event_key,scope_id,content_sha256,
 archive_month,retention_class,observed_at,protocol,body_ref
FROM stream_event_search
WHERE router_score_possible=1 AND event_type IN ('device','router')
 AND protocol IN ('dhcp','software','lldp','cdp','ssdp','snmp','handshake',
                  'http','ssl','tls','x509','quic','vrrp','hsrp','ttl');

DROP VIEW IF EXISTS stream_router_signal_index_mv;
