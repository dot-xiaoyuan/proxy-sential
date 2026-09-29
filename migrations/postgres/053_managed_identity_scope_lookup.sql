CREATE INDEX IF NOT EXISTS enforcement_identity_sources_campus_domain ON enforcement_identity_sources ((public_config->>'campus_id'),(public_config->>'access_domain'),connector_id);
CREATE INDEX IF NOT EXISTS policy_identity_scope_time ON policy_identity_observations ((session_data->>'campus_id'),(session_data->>'access_domain'),observed_at,event_id);
CREATE INDEX IF NOT EXISTS identity_full_snapshots_campus_domain_observed ON identity_full_snapshots (campus_id,access_domain,observed_at DESC,source,sensor_id);
