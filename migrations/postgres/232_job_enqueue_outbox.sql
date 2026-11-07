-- Triggers that mark recognition or shared-profile work used to upsert shared
-- job rows from many writers, which deadlocked whenever two transactions
-- touched the same jobs in different endpoint orders. Keep the triggers as
-- append-only logs instead; a single dispatcher per job table folds the log
-- into the job rows in one ordered statement, so writers never wait on shared
-- rows. The logs are drained and trimmed by the dispatcher.
CREATE TABLE IF NOT EXISTS endpoint_recognition_dirty_log (
 id bigserial PRIMARY KEY,
 endpoint_id text NOT NULL,
 created_at timestamp with time zone NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS endpoint_recognition_dirty_log_id ON endpoint_recognition_dirty_log (id);

CREATE TABLE IF NOT EXISTS shared_device_profile_dirty_log (
 id bigserial PRIMARY KEY,
 subject_key text NOT NULL,
 sensor_id text NOT NULL DEFAULT '',
 campus_id text NOT NULL DEFAULT '',
 endpoint_id text NOT NULL DEFAULT '',
 mac text NOT NULL DEFAULT '',
 ip inet,
 vlan text NOT NULL DEFAULT '',
 observed_at timestamp with time zone NOT NULL,
 created_at timestamp with time zone NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shared_device_profile_dirty_log_id ON shared_device_profile_dirty_log (id);

CREATE OR REPLACE FUNCTION mark_endpoint_recognition_dirty(target_id text)
RETURNS void
LANGUAGE plpgsql
AS $function$
BEGIN
 IF target_id IS NULL OR target_id='' THEN RETURN; END IF;
 IF NOT EXISTS (SELECT 1 FROM endpoint_entities WHERE endpoint_id=target_id) THEN RETURN; END IF;
 INSERT INTO endpoint_recognition_dirty_log(endpoint_id) VALUES(target_id);
END;
$function$;

CREATE OR REPLACE FUNCTION enqueue_shared_device_profile_job(p_sensor text, p_campus text, p_endpoint text, p_mac text, p_ip inet, p_vlan text, p_observed timestamp with time zone)
RETURNS void
LANGUAGE plpgsql
AS $function$
DECLARE normalized_mac text; identity text; target_sensor text;
BEGIN
 IF p_observed IS NULL OR p_observed<(SELECT cutover_at FROM shared_device_profile_runtime WHERE singleton) THEN RETURN; END IF;
 normalized_mac := regexp_replace(lower(coalesce(p_mac,'')),'[^0-9a-f]','','g');
 target_sensor := coalesce(p_sensor,'');
 IF coalesce(p_endpoint,'')<>'' THEN identity := 'endpoint:'||p_endpoint;
 ELSIF normalized_mac<>'' THEN identity := 'mac:'||normalized_mac;
 ELSIF p_ip IS NOT NULL THEN identity := 'address:'||coalesce(p_campus,'')||':'||coalesce(p_vlan,'')||':'||host(p_ip);
 ELSE RETURN;
 END IF;
 INSERT INTO shared_device_profile_dirty_log(subject_key,sensor_id,campus_id,endpoint_id,mac,ip,vlan,observed_at)
 VALUES(target_sensor||':'||identity,target_sensor,coalesce(p_campus,''),coalesce(p_endpoint,''),coalesce(p_mac,''),p_ip,coalesce(p_vlan,''),p_observed);
END;
$function$;
