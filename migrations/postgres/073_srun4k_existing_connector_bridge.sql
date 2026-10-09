-- Turn an existing encrypted 4K connector into the simplified managed
-- integration without copying credentials or exposing them to the UI.
INSERT INTO srun4k_integrations(
  connector_id,
  host,
  source,
  sensor_id,
  reconcile_interval_hours,
  event_channel_state,
  connection_state,
  updated_by
)
SELECT
  connector.connector_id,
  database_config.public_config->>'host',
  'srun4k:' || connector.connector_id,
  'srun4k-direct:' || connector.connector_id,
  6,
  'waiting',
  'pending',
  'migration'
FROM enforcement_4k_databases AS database_config
JOIN enforcement_connectors AS connector
  ON connector.connector_id = database_config.connector_id
WHERE connector.connector_type = 'srun4k'
  AND length(trim(database_config.public_config->>'host')) > 0
ON CONFLICT DO NOTHING;
