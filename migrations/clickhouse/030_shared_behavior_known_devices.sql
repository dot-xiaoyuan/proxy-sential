CREATE MATERIALIZED VIEW IF NOT EXISTS shared_behavior_device_model_events_v1_mv
TO shared_behavior_signal_events_v1 AS
WITH
 JSONExtractString(payload_json,'user_agent') AS ua,
 multiIf(
  positionCaseInsensitiveUTF8(ua,'android')>0,
   extract(ua,'(?i)([A-Z0-9][A-Z0-9._-]{3,})[ ]+Build/'),
  match(ua,'iPhone[0-9]+,[0-9]+'),extract(ua,'(iPhone[0-9]+,[0-9]+)'),
  match(ua,'iPad[0-9]+,[0-9]+'),extract(ua,'(iPad[0-9]+,[0-9]+)'),
  '') AS hardware_model,
 multiIf(
  startsWith(hardware_model,'iPhone') OR startsWith(hardware_model,'iPad'),'Apple',
  positionCaseInsensitiveUTF8(ua,'honor')>0,'Honor',
  positionCaseInsensitiveUTF8(ua,'xiaomi')>0 OR positionCaseInsensitiveUTF8(ua,'redmi')>0,'Xiaomi',
  positionCaseInsensitiveUTF8(ua,'samsung')>0 OR startsWith(hardware_model,'GT-'),'Samsung',
  positionCaseInsensitiveUTF8(ua,'huawei')>0,'Huawei','') AS hardware_brand,
 if(startsWith(hardware_model,'iPhone') OR startsWith(hardware_model,'iPad'),'iOS','Android') AS os_family,
 if(startsWith(hardware_model,'iPad'),'tablet','mobile') AS device_type
SELECT timestamp,event_id,sensor_id,campus_id,
 JSONExtractString(payload_json,'access_domain') AS access_domain,
 subject_ip,source,
 JSONExtractString(observer_json,'collector_instance_id') AS collector_instance_id,
 'device_model' AS feature_family,
 concat(hardware_brand,'|',os_family,'|',device_type,'|',hardware_model) AS feature_value
FROM normalized_events
WHERE subject_ip!='' AND hardware_model!='';

INSERT INTO shared_behavior_signal_events_v1
WITH
 JSONExtractString(payload_json,'user_agent') AS ua,
 multiIf(
  positionCaseInsensitiveUTF8(ua,'android')>0,
   extract(ua,'(?i)([A-Z0-9][A-Z0-9._-]{3,})[ ]+Build/'),
  match(ua,'iPhone[0-9]+,[0-9]+'),extract(ua,'(iPhone[0-9]+,[0-9]+)'),
  match(ua,'iPad[0-9]+,[0-9]+'),extract(ua,'(iPad[0-9]+,[0-9]+)'),
  '') AS hardware_model,
 multiIf(
  startsWith(hardware_model,'iPhone') OR startsWith(hardware_model,'iPad'),'Apple',
  positionCaseInsensitiveUTF8(ua,'honor')>0,'Honor',
  positionCaseInsensitiveUTF8(ua,'xiaomi')>0 OR positionCaseInsensitiveUTF8(ua,'redmi')>0,'Xiaomi',
  positionCaseInsensitiveUTF8(ua,'samsung')>0 OR startsWith(hardware_model,'GT-'),'Samsung',
  positionCaseInsensitiveUTF8(ua,'huawei')>0,'Huawei','') AS hardware_brand,
 if(startsWith(hardware_model,'iPhone') OR startsWith(hardware_model,'iPad'),'iOS','Android') AS os_family,
 if(startsWith(hardware_model,'iPad'),'tablet','mobile') AS device_type
SELECT timestamp,event_id,sensor_id,campus_id,
 JSONExtractString(payload_json,'access_domain') AS access_domain,
 subject_ip,source,
 JSONExtractString(observer_json,'collector_instance_id') AS collector_instance_id,
 'device_model' AS feature_family,
 concat(hardware_brand,'|',os_family,'|',device_type,'|',hardware_model) AS feature_value
FROM normalized_events
WHERE timestamp>=now()-INTERVAL 24 HOUR AND subject_ip!='' AND hardware_model!='';
