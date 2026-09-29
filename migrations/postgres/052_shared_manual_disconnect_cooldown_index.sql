-- Bound account/scope cooldown lookups to recent grants on the selected connector.
CREATE INDEX shared_manual_disconnect_grants_connector_recent
 ON shared_manual_disconnect_grants(connector_id, created_at DESC);
