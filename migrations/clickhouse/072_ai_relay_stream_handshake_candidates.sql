-- Stream handshakes are archived as canonical normalized-event bodies, while
-- the original candidate view only follows normalized_events. Project the
-- bounded domain fields from the authoritative body on future inserts. No
-- original body is copied into this seven-day read model.
CREATE MATERIALIZED VIEW IF NOT EXISTS ai_relay_domain_candidates_stream_v2_mv
TO ai_relay_domain_candidates_v1 AS
SELECT
 observed_at AS timestamp,
 JSONExtractString(body,'event_id') AS event_id,
 JSONExtractString(body,'observer','sensor_id') AS sensor_id,
 JSONExtractString(body,'subject','campus_id') AS campus_id,
 JSONExtractString(body,'subject','ip') AS subject_ip,
 'handshake' AS event_type,
 '' AS dns_query,
 '' AS sni,
 '' AS http_host,
 JSONExtract(body,'payload','snis','Array(String)') AS snis,
 JSONExtract(body,'payload','hosts','Array(String)') AS hosts
FROM stream_event_body_evidence_v2
WHERE JSONExtractString(body,'source')='handshake-sidecar'
 AND JSONExtractString(body,'source_event_type')='handshake'
 AND JSONExtractString(body,'event_id')!=''
 AND JSONExtractString(body,'subject','ip')!=''
 AND (notEmpty(JSONExtract(body,'payload','snis','Array(String)'))
   OR notEmpty(JSONExtract(body,'payload','hosts','Array(String)')));
