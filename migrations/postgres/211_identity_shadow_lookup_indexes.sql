-- The direct shadow readers look sessions up by account/endpoint, not only by
-- session_id. Keep the shadow path off sequential scans.
CREATE INDEX IF NOT EXISTS identity_session_shadow_account_idx
    ON identity_session_shadow (account_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS identity_session_shadow_endpoint_idx
    ON identity_session_shadow (endpoint_id, updated_at DESC);
