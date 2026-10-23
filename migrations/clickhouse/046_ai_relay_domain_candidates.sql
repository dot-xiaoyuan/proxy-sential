-- Keep only fields needed for bounded seven-day domain reads. The indicator
-- library is applied at query time, so an asset update can match retained
-- observations without rewriting this table.
CREATE TABLE IF NOT EXISTS ai_relay_domain_candidates_v1 (
 timestamp DateTime64(6,'UTC'), event_id String, sensor_id LowCardinality(String),
 campus_id LowCardinality(String), subject_ip String, event_type LowCardinality(String),
 dns_query String, sni String, http_host String, snis Array(String), hosts Array(String)
) ENGINE=MergeTree
PARTITION BY toDate(timestamp)
ORDER BY (timestamp,sensor_id,subject_ip,event_id)
TTL toDateTime(timestamp)+INTERVAL 7 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS ai_relay_domain_candidates_v1_mv
TO ai_relay_domain_candidates_v1 AS
SELECT timestamp,event_id,sensor_id,campus_id,subject_ip,type AS event_type,
 if(type='dns',JSONExtractString(payload_json,'query'),'') AS dns_query,
 if(type IN ('tls','quic'),JSONExtractString(payload_json,'sni'),'') AS sni,
 if(type='http',JSONExtractString(payload_json,'host'),'') AS http_host,
 if(source='handshake-sidecar',JSONExtract(payload_json,'snis','Array(String)'),[]) AS snis,
 if(source='handshake-sidecar',JSONExtract(payload_json,'hosts','Array(String)'),[]) AS hosts
FROM normalized_events
WHERE subject_ip!='' AND (type IN ('dns','tls','http','quic') OR
 (source='handshake-sidecar' AND source_event_type='handshake'));
