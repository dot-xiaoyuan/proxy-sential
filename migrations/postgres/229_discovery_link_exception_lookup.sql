-- Ordinary discovery links repeat their frame-verified MAC. Keep only links
-- without that proof or with a different endpoint in the hot read index.
-- The full discovery_identity_links table remains the authoritative history.
CREATE INDEX IF NOT EXISTS discovery_identity_link_exceptions
 ON discovery_identity_links(observation_id) INCLUDE(endpoint_id)
 WHERE coalesce(basis->>'mac','')=''
    OR lower(endpoint_id)<>'mac:'||lower(basis->>'mac');
