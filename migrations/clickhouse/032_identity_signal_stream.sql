ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS subject_json String DEFAULT '';
CREATE TABLE IF NOT EXISTS identity_signal_events_v1 (
 received_at DateTime64(6,'UTC'),timestamp DateTime64(6,'UTC'),event_id String,
 schema_version String,source String,source_event_type String,type String,sensor_id String,
 subject_ip String,subject_mac String,account_id String,endpoint_id String,campus_id String,
 subject_json String,observer_json String,payload_json String,flow_json String,raw_ref_json String,confidence Float64
) ENGINE=MergeTree PARTITION BY toDate(received_at) ORDER BY(sensor_id,received_at,event_id)
TTL toDateTime(received_at)+INTERVAL 8 DAY DELETE;
CREATE MATERIALIZED VIEW IF NOT EXISTS identity_signal_events_v1_mv TO identity_signal_events_v1 AS
SELECT now64(6,'UTC') AS received_at,timestamp,event_id,schema_version,source,source_event_type,type,sensor_id,subject_ip,subject_mac,account_id,endpoint_id,campus_id,subject_json,observer_json,payload_json,flow_json,raw_ref_json,confidence FROM normalized_events WHERE type IN ('identity','device');
-- Backfill uses a separate receipt interval and worker cursor; live ingestion
-- has priority and late event timestamps cannot fall behind its receipt cursor.
INSERT INTO identity_signal_events_v1
SELECT timestamp AS received_at,timestamp,event_id,schema_version,source,source_event_type,type,sensor_id,subject_ip,subject_mac,account_id,endpoint_id,campus_id,subject_json,observer_json,payload_json,flow_json,raw_ref_json,confidence FROM normalized_events WHERE type IN ('identity','device') AND timestamp>=now()-INTERVAL 7 DAY;
