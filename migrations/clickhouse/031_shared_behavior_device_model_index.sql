CREATE TABLE IF NOT EXISTS shared_behavior_device_model_events_v1 (
 timestamp DateTime64(6,'UTC'),
 event_id String,
 sensor_id String,
 campus_id String,
 access_domain String,
 subject_ip String,
 source LowCardinality(String),
 collector_instance_id String,
 feature_value String
) ENGINE=MergeTree
PARTITION BY toDate(timestamp)
ORDER BY(sensor_id,subject_ip,timestamp,feature_value,event_id)
TTL toDateTime(timestamp)+INTERVAL 8 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS shared_behavior_device_model_index_v1_mv
TO shared_behavior_device_model_events_v1 AS
SELECT timestamp,event_id,sensor_id,campus_id,access_domain,subject_ip,source,collector_instance_id,feature_value
FROM shared_behavior_signal_events_v1
WHERE feature_family='device_model' AND subject_ip!='' AND feature_value!='';

INSERT INTO shared_behavior_device_model_events_v1
SELECT timestamp,event_id,sensor_id,campus_id,access_domain,subject_ip,source,collector_instance_id,feature_value
FROM shared_behavior_signal_events_v1
WHERE timestamp>=now()-INTERVAL 24 HOUR AND feature_family='device_model' AND subject_ip!='' AND feature_value!='';
