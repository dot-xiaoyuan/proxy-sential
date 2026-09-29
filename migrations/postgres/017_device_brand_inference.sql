ALTER TABLE endpoint_domain_evidence_events ADD COLUMN IF NOT EXISTS observation JSONB;
ALTER TABLE endpoint_domain_evidence_events ADD COLUMN IF NOT EXISTS rule_match JSONB;
CREATE INDEX IF NOT EXISTS idx_brand_window_events ON endpoint_domain_evidence_events(rule_version,endpoint_id,observed_at) WHERE rule_match IS NOT NULL;

CREATE TABLE IF NOT EXISTS domain_rule_versions (
 version TEXT PRIMARY KEY,
 rules JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS domain_recognition_state (
 singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK(singleton),
 active_version TEXT NOT NULL DEFAULT '',
 pending_version TEXT NOT NULL DEFAULT '',
 enabled BOOLEAN NOT NULL DEFAULT true,
 last_error TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS endpoint_brand_inferences (
 endpoint_id TEXT NOT NULL REFERENCES endpoint_entities(endpoint_id) ON DELETE CASCADE,
 rule_version TEXT NOT NULL,
 result JSONB NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(endpoint_id,rule_version)
);

CREATE TABLE IF NOT EXISTS domain_reconcile_cursors (
 sensor_id TEXT NOT NULL,
 rule_version TEXT NOT NULL,
 kind TEXT NOT NULL,
 cursor_timestamp TIMESTAMPTZ NOT NULL,
 cursor_event_id TEXT NOT NULL DEFAULT '',
 completed_at TIMESTAMPTZ,
 PRIMARY KEY(sensor_id,rule_version,kind)
);
