-- The link trigger, name evidence, live PTR and the recognition summary all
-- update endpoint_recognition_jobs and shared_device_profile_jobs, in different
-- endpoint orders. A single transaction that enqueues profile jobs after
-- locking a recognition job can cross a link batch that does the opposite and
-- deadlock. Serialise only this job/profile section with one transaction-scoped
-- advisory lock; the discovery/link writes themselves stay concurrent.
CREATE OR REPLACE FUNCTION mark_endpoint_recognition_dirty(target_id text)
RETURNS void
LANGUAGE plpgsql
AS $function$
BEGIN
 IF target_id IS NULL OR target_id='' THEN RETURN; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('recognition-writer', 0));
 IF NOT EXISTS (SELECT 1 FROM endpoint_entities WHERE endpoint_id=target_id) THEN RETURN; END IF;
 IF EXISTS (
  SELECT 1 FROM endpoint_recognition_jobs
  WHERE endpoint_id=target_id AND processed_generation<dirty_generation
    AND lease_until<clock_timestamp() AND lane=0
 ) THEN
  RETURN;
 END IF;
 INSERT INTO endpoint_recognition_jobs(endpoint_id) VALUES(target_id)
 ON CONFLICT(endpoint_id) DO UPDATE SET
  dirty_generation=endpoint_recognition_jobs.dirty_generation+1,
  lane=0,
  not_before=LEAST(endpoint_recognition_jobs.not_before,now()),
  updated_at=CASE WHEN endpoint_recognition_jobs.processed_generation<endpoint_recognition_jobs.dirty_generation THEN endpoint_recognition_jobs.updated_at ELSE now() END
 WHERE endpoint_recognition_jobs.processed_generation>=endpoint_recognition_jobs.dirty_generation
    OR endpoint_recognition_jobs.lease_until>clock_timestamp() OR endpoint_recognition_jobs.lane=1;
END;
$function$;

CREATE OR REPLACE FUNCTION enqueue_shared_device_profile_job(p_sensor text, p_campus text, p_endpoint text, p_mac text, p_ip inet, p_vlan text, p_observed timestamp with time zone)
RETURNS void
LANGUAGE plpgsql
AS $function$
DECLARE normalized_mac text; identity text; target_sensor text;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('recognition-writer', 0));
 IF p_observed IS NULL OR p_observed<(SELECT cutover_at FROM shared_device_profile_runtime WHERE singleton) THEN RETURN; END IF;
 normalized_mac := regexp_replace(lower(coalesce(p_mac,'')),'[^0-9a-f]','','g');
 target_sensor := coalesce(p_sensor,'');
 IF coalesce(p_endpoint,'')<>'' THEN identity := 'endpoint:'||p_endpoint;
 ELSIF normalized_mac<>'' THEN identity := 'mac:'||normalized_mac;
 ELSIF p_ip IS NOT NULL THEN identity := 'address:'||coalesce(p_campus,'')||':'||coalesce(p_vlan,'')||':'||host(p_ip);
 ELSE RETURN;
 END IF;
 INSERT INTO shared_device_profile_jobs(subject_key,sensor_id,campus_id,endpoint_id,mac,ip,vlan,observed_at)
 VALUES(target_sensor||':'||identity,target_sensor,coalesce(p_campus,''),coalesce(p_endpoint,''),coalesce(p_mac,''),p_ip,coalesce(p_vlan,''),p_observed)
 ON CONFLICT(subject_key) DO UPDATE SET
  sensor_id=CASE WHEN EXCLUDED.sensor_id<>'' THEN EXCLUDED.sensor_id ELSE shared_device_profile_jobs.sensor_id END,
  campus_id=CASE WHEN EXCLUDED.campus_id<>'' THEN EXCLUDED.campus_id ELSE shared_device_profile_jobs.campus_id END,
  endpoint_id=CASE WHEN EXCLUDED.endpoint_id<>'' THEN EXCLUDED.endpoint_id ELSE shared_device_profile_jobs.endpoint_id END,
  mac=CASE WHEN EXCLUDED.mac<>'' THEN EXCLUDED.mac ELSE shared_device_profile_jobs.mac END,
  ip=coalesce(EXCLUDED.ip,shared_device_profile_jobs.ip),
  vlan=CASE WHEN EXCLUDED.vlan<>'' THEN EXCLUDED.vlan ELSE shared_device_profile_jobs.vlan END,
  observed_at=greatest(shared_device_profile_jobs.observed_at,EXCLUDED.observed_at),
  dirty_since=CASE WHEN shared_device_profile_jobs.processed_generation>=shared_device_profile_jobs.dirty_generation THEN now() ELSE shared_device_profile_jobs.dirty_since END,
  dirty_generation=shared_device_profile_jobs.dirty_generation+1,
  not_before=least(shared_device_profile_jobs.not_before,now()),updated_at=now();
END;
$function$;
