-- A matched reverse SYN-ACK is a separate weak IP/port observation. The
-- existing seven-day compact table already separates rows by proto; this
-- view uses a distinct internal proto so the reader can prefer response
-- evidence without treating an unmatched packet as an open device port.
CREATE MATERIALIZED VIEW IF NOT EXISTS discovery_observed_flow_syn_ack_stream_mv
TO discovery_observed_flow_ports_10m AS
SELECT toStartOfInterval(observed_at, INTERVAL 10 MINUTE) AS window_start,
 sensor_id, src_ip, 'tcp_synack' AS proto, dst_port,
 maxState(toTimeZone(observed_at, 'Asia/Shanghai')) AS last_seen,
 argMaxState(event_key, toTimeZone(observed_at, 'Asia/Shanghai')) AS evidence_id
FROM stream_event_search
WHERE event_type='flow' AND source='flow-syn-sidecar' AND protocol='syn_ack_observed'
 AND sensor_id<>'' AND src_ip<>'' AND dst_port>0
GROUP BY window_start, sensor_id, src_ip, proto, dst_port;
