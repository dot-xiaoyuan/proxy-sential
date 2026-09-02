CREATE TABLE IF NOT EXISTS endpoint_domain_evidence (
  endpoint_id TEXT NOT NULL REFERENCES endpoint_entities(endpoint_id) ON DELETE CASCADE,
  domain TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  event_source TEXT NOT NULL,
  attribution_method TEXT NOT NULL,
  auth_session_id TEXT,
  rule_source TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  category TEXT NOT NULL,
  confidence DOUBLE PRECISION NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  hit_count BIGINT NOT NULL DEFAULT 0,
  event_ids_sample JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(endpoint_id, domain, ecosystem, event_source, rule_version)
);

CREATE TABLE IF NOT EXISTS endpoint_domain_evidence_events (
  rule_version TEXT NOT NULL,
  event_id TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(rule_version, event_id, ecosystem)
);

CREATE TABLE IF NOT EXISTS domain_evidence_backfill_jobs (
  version TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  cursor_timestamp TIMESTAMPTZ,
  cursor_event_id TEXT NOT NULL DEFAULT '',
  processed BIGINT NOT NULL DEFAULT 0,
  attributed BIGINT NOT NULL DEFAULT 0,
  matched BIGINT NOT NULL DEFAULT 0,
  last_error TEXT,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE endpoint_device_profiles ADD COLUMN IF NOT EXISTS ecosystem_hint TEXT;
ALTER TABLE endpoint_device_profiles ADD COLUMN IF NOT EXISTS ecosystem_confidence DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE endpoint_device_profiles ADD COLUMN IF NOT EXISTS ecosystem_conflict BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE endpoint_device_profiles ADD COLUMN IF NOT EXISTS ecosystem_evidence_count BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_endpoint_domain_evidence_endpoint_seen
  ON endpoint_domain_evidence(endpoint_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_endpoint_domain_evidence_ecosystem
  ON endpoint_domain_evidence(ecosystem, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_domain_evidence_events_observed
  ON endpoint_domain_evidence_events(observed_at, event_id);
