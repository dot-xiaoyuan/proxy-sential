-- Releases before 2026.09.04 formatted RFC3339 Zeek timestamps without first
-- converting the instant to the Asia/Shanghai DateTime64 column timezone.
-- timestamp belongs to the MergeTree sorting key and cannot be updated in
-- place, so mark legacy rows, copy them with the corrected instant, then
-- synchronously remove the marked originals. Fresh installs match no rows.
ALTER TABLE normalized_events
ADD COLUMN IF NOT EXISTS timezone_repair UInt8 DEFAULT 0;

ALTER TABLE normalized_events
UPDATE timezone_repair = 1
WHERE source = 'zeek' AND timezone_repair = 0
SETTINGS mutations_sync = 2;

INSERT INTO normalized_events
(timestamp,event_id,schema_version,source,source_event_type,type,sensor_id,subject_ip,src_ip,dst_ip,src_port,dst_port,proto,direction,observer_json,payload_json,flow_json,raw_ref_json,confidence,timezone_repair)
SELECT timestamp + INTERVAL 8 HOUR,event_id,schema_version,source,source_event_type,type,sensor_id,subject_ip,src_ip,dst_ip,src_port,dst_port,proto,direction,observer_json,payload_json,flow_json,raw_ref_json,confidence,2
FROM normalized_events
WHERE timezone_repair = 1;

ALTER TABLE normalized_events
DELETE WHERE timezone_repair = 1
SETTINGS mutations_sync = 2;
