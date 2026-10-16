-- Bounded raw handshake summaries and measured coverage. Queries use exact scope,
-- IP and time; raw receipt IDs remain available for audit. No historical backfill.
-- Retain the only copy until verified archival is available (no destructive TTL).
CREATE TABLE shared_observation_events_v2 (
 sensor_id LowCardinality(String), campus_id LowCardinality(String), access_domain LowCardinality(String),
 subject_ip String, source LowCardinality(String), collector_instance_id String,
 timestamp DateTime64(6,'UTC'), event_id String, source_event_type LowCardinality(String),
 payload_json String, first_received_at DateTime64(6,'UTC') DEFAULT now64(6)
) ENGINE=MergeTree PARTITION BY toYYYYMM(first_received_at)
ORDER BY (sensor_id,campus_id,access_domain,subject_ip,timestamp,event_id);
CREATE MATERIALIZED VIEW shared_observation_events_v2_mv TO shared_observation_events_v2 AS
SELECT sensor_id,campus_id,JSONExtractString(payload_json,'access_domain') AS access_domain,
 subject_ip,source,JSONExtractString(observer_json,'collector_instance_id') AS collector_instance_id,
 timestamp,event_id,source_event_type,payload_json,now64(6) AS first_received_at
FROM normalized_events
WHERE source='handshake-sidecar' AND source_event_type IN ('handshake','capture_coverage');
-- Logical hot queries are limited to recent input; archive bundles retain the
-- decision, identity proof and original summaries together. No archive TTL is
-- allowed to erase case-referenced proof implicitly.
CREATE TABLE shared_observation_archive_v1 (
 observation_id String,decision_id String,first_received_at DateTime64(6,'UTC'),
 content_hash String,document String,archived_at DateTime64(6,'UTC') DEFAULT now64(6)
) ENGINE=MergeTree PARTITION BY toYYYYMM(first_received_at)
ORDER BY (observation_id,decision_id,content_hash);
-- MAC-addressed protocol facts stay separate from IP-addressed handshakes.
CREATE TABLE shared_association_events_v1 (
 sensor_id LowCardinality(String),campus_id LowCardinality(String),access_domain LowCardinality(String),
 subject_mac String,source LowCardinality(String),collector_instance_id String,
 timestamp DateTime64(6,'UTC'),event_id String,source_event_type LowCardinality(String),
 payload_json String,first_received_at DateTime64(6,'UTC') DEFAULT now64(6)
) ENGINE=MergeTree PARTITION BY toYYYYMM(first_received_at)
ORDER BY (sensor_id,campus_id,access_domain,subject_mac,timestamp,event_id);
CREATE MATERIALIZED VIEW shared_association_events_v1_mv TO shared_association_events_v1 AS
SELECT sensor_id,campus_id,JSONExtractString(payload_json,'access_domain') AS access_domain,
 subject_mac,source,JSONExtractString(observer_json,'collector_instance_id') AS collector_instance_id,
 timestamp,event_id,source_event_type,payload_json,now64(6) AS first_received_at FROM normalized_events
WHERE source='packet-sidecar' AND source_event_type IN ('ieee1905_client_association','ieee1905_client_snapshot','capture_coverage');
