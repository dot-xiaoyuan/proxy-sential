CREATE INDEX IF NOT EXISTS idx_endpoint_page_order ON endpoint_entities(last_seen DESC NULLS LAST,registration_updated_at DESC NULLS LAST,endpoint_id) WHERE entity_role='endpoint';
CREATE INDEX IF NOT EXISTS idx_sessions_endpoint_started ON account_sessions(endpoint_id,started_at DESC,session_id);
CREATE INDEX IF NOT EXISTS idx_ip_history_endpoint_observed ON identity_ip_mac_history(endpoint_id,last_seen DESC,first_seen DESC,ip,event_id);
CREATE INDEX IF NOT EXISTS idx_access_history_endpoint_observed ON identity_access_history(endpoint_id,last_seen DESC,event_id);
CREATE INDEX IF NOT EXISTS idx_action_page_order ON enforcement_actions(created_at DESC,action_id DESC);
