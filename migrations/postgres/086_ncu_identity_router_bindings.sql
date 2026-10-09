CREATE INDEX IF NOT EXISTS account_sessions_current_mac_lookup
ON account_sessions ((regexp_replace(lower(COALESCE(mac,'')),'[^0-9a-f]','','g')), updated_at DESC)
WHERE ended_at IS NULL AND mac IS NOT NULL AND mac <> '';

CREATE INDEX IF NOT EXISTS account_sessions_current_endpoint_lookup
ON account_sessions (endpoint_id, updated_at DESC)
WHERE ended_at IS NULL AND endpoint_id IS NOT NULL AND endpoint_id <> '';

CREATE INDEX IF NOT EXISTS account_identity_projection_current_mac_lookup
ON account_identity_session_projection ((regexp_replace(lower(COALESCE(document->>'mac','')),'[^0-9a-f]','','g')), confirmed_at DESC)
WHERE COALESCE(document->>'ended_at','')='' AND COALESCE(document->>'mac','')<>'';

CREATE INDEX IF NOT EXISTS account_identity_projection_current_endpoint_lookup
ON account_identity_session_projection ((document->>'endpoint_id'), confirmed_at DESC)
WHERE COALESCE(document->>'ended_at','')='' AND COALESCE(document->>'endpoint_id','')<>'';
