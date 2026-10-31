-- Fresh audited device-signal streams write their typed search rows to
-- stream_event_search. The 059 view remains for legacy normalized_events;
-- this separate view adds only the scoped payload-free initial SYN source.
-- It reuses the seven-day compact read model and adds no request-time scan.
CREATE MATERIALIZED VIEW IF NOT EXISTS discovery_observed_flow_ports_stream_mv
TO discovery_observed_flow_ports_10m AS
SELECT toStartOfInterval(observed_at, INTERVAL 10 MINUTE) AS window_start,
 sensor_id, src_ip, 'tcp' AS proto, dst_port,
 maxState(toTimeZone(observed_at, 'Asia/Shanghai')) AS last_seen,
 argMaxState(event_key, toTimeZone(observed_at, 'Asia/Shanghai')) AS evidence_id
FROM stream_event_search
WHERE event_type='flow' AND source='flow-syn-sidecar' AND protocol='syn_attempt'
 AND sensor_id<>'' AND src_ip<>'' AND dst_port>0
GROUP BY window_start, sensor_id, src_ip, proto, dst_port;
