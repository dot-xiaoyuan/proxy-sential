CREATE TABLE shared_manual_disconnect_grants (
 grant_id text PRIMARY KEY,
 review_id text NOT NULL REFERENCES shared_access_reviews(review_id),
 actor_id text NOT NULL,
 connector_id text NOT NULL REFERENCES enforcement_connectors(connector_id),
 identity_version bigint NOT NULL,
 evidence_version bigint NOT NULL,
 shared_config_version text NOT NULL,
 fingerprint text NOT NULL,
 approved_plan jsonb NOT NULL,
 expires_at timestamptz NOT NULL,
 revoked boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX shared_manual_disconnect_grants_review ON shared_manual_disconnect_grants(review_id,created_at DESC);
