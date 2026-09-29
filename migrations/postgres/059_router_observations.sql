-- Passive router observations are deliberately isolated from proxy risk and enforcement state.
CREATE TABLE IF NOT EXISTS router_rule_versions (
 version text PRIMARY KEY,
 installed_at timestamptz NOT NULL DEFAULT now(),
 active boolean NOT NULL DEFAULT true,
 config jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS router_evidence_facts (
 evidence_id text PRIMARY KEY,
 assessment_id text NOT NULL,
 endpoint_id text NOT NULL DEFAULT '',
 ip inet,
 mac text NOT NULL DEFAULT '',
 vlan text NOT NULL DEFAULT '',
 source text NOT NULL,
 source_family text NOT NULL,
 kind text NOT NULL,
 rule_id text NOT NULL,
 rule_version text NOT NULL,
 score integer NOT NULL,
 conflict boolean NOT NULL DEFAULT false,
 exclusion boolean NOT NULL DEFAULT false,
 first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS router_evidence_assessment_time ON router_evidence_facts(assessment_id,last_seen DESC);
CREATE INDEX IF NOT EXISTS router_evidence_source ON router_evidence_facts(source_family,last_seen DESC);
CREATE INDEX IF NOT EXISTS router_evidence_expiry ON router_evidence_facts(expires_at);

CREATE TABLE IF NOT EXISTS router_assessments (
 assessment_id text PRIMARY KEY,
 endpoint_id text NOT NULL DEFAULT '',
 ip inet,
 mac text NOT NULL DEFAULT '',
 vlans text[] NOT NULL DEFAULT '{}',
 brand text NOT NULL DEFAULT '',
 series text NOT NULL DEFAULT '',
 model text NOT NULL DEFAULT '',
 role text NOT NULL,
 status text NOT NULL CHECK(status IN ('candidate','likely','confirmed')),
 confidence integer NOT NULL CHECK(confidence BETWEEN 0 AND 100),
 sources text[] NOT NULL DEFAULT '{}',
 infrastructure boolean NOT NULL DEFAULT false,
 brand_reference_only boolean NOT NULL DEFAULT false,
 ambiguous boolean NOT NULL DEFAULT false,
 rule_version text NOT NULL,
 first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 assessment jsonb NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS router_assessment_status_score ON router_assessments(status,confidence DESC,last_seen DESC);
CREATE INDEX IF NOT EXISTS router_assessment_identity ON router_assessments(endpoint_id,mac,ip);
CREATE INDEX IF NOT EXISTS router_assessment_classification ON router_assessments(brand,model,role,infrastructure);
CREATE INDEX IF NOT EXISTS router_assessment_times ON router_assessments(first_seen,last_seen DESC);
CREATE INDEX IF NOT EXISTS router_assessment_sources ON router_assessments USING gin(sources);
CREATE INDEX IF NOT EXISTS router_assessment_vlans ON router_assessments USING gin(vlans);

CREATE TABLE IF NOT EXISTS router_assessment_history (
 history_id bigserial PRIMARY KEY,
 assessment_id text NOT NULL REFERENCES router_assessments(assessment_id) ON DELETE CASCADE,
 status text NOT NULL,
 confidence integer NOT NULL,
 rule_version text NOT NULL,
 changed_at timestamptz NOT NULL DEFAULT now(),
 conflicts jsonb NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS router_assessment_history_timeline ON router_assessment_history(assessment_id,changed_at DESC);
