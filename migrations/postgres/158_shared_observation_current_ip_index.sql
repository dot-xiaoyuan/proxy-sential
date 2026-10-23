-- Field installations precreate this index CONCURRENTLY before applying the
-- migration, so the large historical table keeps accepting writes. A fresh
-- installation builds it normally on an empty table.
SET LOCAL lock_timeout = '5s';
CREATE INDEX IF NOT EXISTS shared_behavior_current_scope_ip
 ON shared_behavior_observations(sensor_id,campus_id,access_domain,ip,observation_id)
 WHERE current;
