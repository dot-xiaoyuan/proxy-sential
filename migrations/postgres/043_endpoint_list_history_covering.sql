-- List inventories use account/IP/access summaries, not raw history payloads.
-- Preserve textual IP tie breaking and cover all projected summary columns.
CREATE INDEX IF NOT EXISTS idx_ip_history_endpoint_list_cover
ON identity_ip_mac_history(endpoint_id,last_seen DESC,first_seen DESC,(host(ip)),event_id)
INCLUDE(account_id,ip);
CREATE INDEX IF NOT EXISTS idx_access_history_endpoint_list_cover
ON identity_access_history(endpoint_id,last_seen DESC,event_id)
INCLUDE(account_id,access_id,first_seen);
CREATE INDEX IF NOT EXISTS idx_sessions_endpoint_list_cover
ON account_sessions(endpoint_id,started_at DESC,session_id)
INCLUDE(account_id,ended_at);
