ALTER TABLE srun4k_integrations
  ADD COLUMN IF NOT EXISTS authorization_database_host text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS online_redis_host text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS catalog_redis_host text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS event_redis_host text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS northbound_api_host text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS northbound_app_id text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS encrypted_northbound_app_secret bytea NOT NULL DEFAULT ''::bytea,
  ADD COLUMN IF NOT EXISTS authorization_refreshed_at timestamptz,
  ADD COLUMN IF NOT EXISTS authorization_database_state text NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS online_redis_state text NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS catalog_redis_state text NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS event_redis_state text NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS northbound_api_state text NOT NULL DEFAULT 'pending';

UPDATE srun4k_integrations
SET authorization_database_host=host,
    online_redis_host=host,
    catalog_redis_host=host,
    northbound_api_host=host
WHERE authorization_database_host='' OR online_redis_host='' OR catalog_redis_host='' OR northbound_api_host='';

UPDATE srun4k_integrations
SET authorization_database_state=CASE WHEN connection_state='healthy' THEN 'healthy' ELSE 'pending' END,
    online_redis_state=CASE WHEN connection_state='healthy' THEN 'healthy' ELSE 'pending' END,
    catalog_redis_state=CASE WHEN connection_state='healthy' THEN 'healthy' ELSE 'pending' END,
    event_redis_state='pending',
    northbound_api_state=CASE WHEN connection_state='healthy' THEN 'healthy' ELSE 'pending' END;

ALTER TABLE identity_bridge_configs
  ADD COLUMN IF NOT EXISTS desired_event_redis_addr text NOT NULL DEFAULT '';
