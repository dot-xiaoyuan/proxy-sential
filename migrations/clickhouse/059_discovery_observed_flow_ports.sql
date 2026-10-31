-- Mirror-observed destination ports are access clues, not evidence that a
-- service is listening on the device. This compact 10-minute read model
-- prevents a ledger page from aggregating the full flow window at request time.
-- One aggregate row per sensor/source IP/protocol/port/window adds write
-- amplification; seven-day TTL follows the source feature retention. The
-- view starts with new input only and does not claim historical coverage.
CREATE TABLE IF NOT EXISTS discovery_observed_flow_ports_10m (
 window_start DateTime('UTC'),
 sensor_id String,
 src_ip String,
 proto LowCardinality(String),
 dst_port UInt32,
 last_seen AggregateFunction(max, DateTime64(6,'Asia/Shanghai')),
 evidence_id AggregateFunction(argMax, String, DateTime64(6,'Asia/Shanghai'))
) ENGINE=AggregatingMergeTree
PARTITION BY toDate(window_start)
ORDER BY (sensor_id,src_ip,window_start,proto,dst_port)
TTL window_start + INTERVAL 7 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS discovery_observed_flow_ports_10m_mv
TO discovery_observed_flow_ports_10m AS
SELECT toStartOfInterval(timestamp,INTERVAL 10 MINUTE) AS window_start,
 sensor_id,src_ip,proto,dst_port,
 maxState(timestamp) AS last_seen,
 argMaxState(event_id,timestamp) AS evidence_id
FROM normalized_events
WHERE type='flow' AND sensor_id<>'' AND src_ip<>'' AND dst_port>0
GROUP BY window_start,sensor_id,src_ip,proto,dst_port;
