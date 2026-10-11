CREATE INDEX IF NOT EXISTS discovery_observation_latest_read
ON discovery_observations(
  device_key,
  source_id,
  origin,
  (coalesce(data->>'ip','')),
  (coalesce(data->'evidence'->'payload'->>'service_type','')),
  (coalesce(data->>'port','')),
  observed_at DESC,
  id DESC
);
