CREATE TABLE IF NOT EXISTS local_users (
  user_id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('viewer','reviewer','operator','admin')),
  password_hash TEXT NOT NULL,
  disabled BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS campuses (
  campus_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  code TEXT NOT NULL UNIQUE,
  enabled BOOLEAN NOT NULL DEFAULT true,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS buildings (
  building_id TEXT PRIMARY KEY,
  campus_id TEXT NOT NULL REFERENCES campuses(campus_id),
  name TEXT NOT NULL,
  code TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(campus_id, code)
);

CREATE TABLE IF NOT EXISTS network_zones (
  network_zone_id TEXT PRIMARY KEY,
  campus_id TEXT NOT NULL REFERENCES campuses(campus_id),
  building_id TEXT REFERENCES buildings(building_id),
  name TEXT NOT NULL,
  cidrs JSONB NOT NULL DEFAULT '[]'::jsonb,
  ssids JSONB NOT NULL DEFAULT '[]'::jsonb,
  vlans JSONB NOT NULL DEFAULT '[]'::jsonb,
  enabled BOOLEAN NOT NULL DEFAULT true,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS access_points (
  access_point_id TEXT PRIMARY KEY,
  campus_id TEXT NOT NULL REFERENCES campuses(campus_id),
  building_id TEXT REFERENCES buildings(building_id),
  network_zone_id TEXT REFERENCES network_zones(network_zone_id),
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  management_ip INET,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  enabled BOOLEAN NOT NULL DEFAULT true,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS person_type TEXT;
ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS department TEXT;
ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS campus_id TEXT;
ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS building_id TEXT;
ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS network_zone_id TEXT;
ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS ssid TEXT;
ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS vlan TEXT;
ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS ap TEXT;
ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS nas_ip INET;
ALTER TABLE account_sessions ADD COLUMN IF NOT EXISTS session_status TEXT;

ALTER TABLE identity_access_history ADD COLUMN IF NOT EXISTS campus_id TEXT;
ALTER TABLE identity_access_history ADD COLUMN IF NOT EXISTS building_id TEXT;
ALTER TABLE identity_access_history ADD COLUMN IF NOT EXISTS network_zone_id TEXT;
ALTER TABLE identity_access_history ADD COLUMN IF NOT EXISTS ssid TEXT;
ALTER TABLE identity_access_history ADD COLUMN IF NOT EXISTS nas_ip INET;

ALTER TABLE risk_snapshots ADD COLUMN IF NOT EXISTS assessment_level TEXT;
ALTER TABLE risk_snapshots ADD COLUMN IF NOT EXISTS review_disposition TEXT;
ALTER TABLE risk_snapshots ADD COLUMN IF NOT EXISTS automation_eligible BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE risk_snapshots ADD COLUMN IF NOT EXISTS automation_blockers JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE subject_risk_snapshots ADD COLUMN IF NOT EXISTS assessment_level TEXT;
ALTER TABLE subject_risk_snapshots ADD COLUMN IF NOT EXISTS review_disposition TEXT;
ALTER TABLE subject_risk_snapshots ADD COLUMN IF NOT EXISTS automation_eligible BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE subject_risk_snapshots ADD COLUMN IF NOT EXISTS automation_blockers JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE TABLE IF NOT EXISTS campus_exceptions (
  exception_id TEXT PRIMARY KEY,
  scope_type TEXT NOT NULL,
  scope_value TEXT NOT NULL,
  campus_id TEXT,
  reason TEXT NOT NULL,
  ruleset_version TEXT NOT NULL,
  valid_from TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS risk_cases (
  case_id TEXT PRIMARY KEY,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  ip INET,
  account_id TEXT,
  endpoint_id TEXT,
  campus_id TEXT,
  department TEXT,
  status TEXT NOT NULL,
  disposition TEXT,
  priority TEXT NOT NULL,
  assignee_id TEXT,
  risk_score INTEGER NOT NULL,
  risk_confidence DOUBLE PRECISION NOT NULL,
  assessment_level TEXT NOT NULL,
  ruleset_version TEXT,
  due_at TIMESTAMPTZ,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  resolved_at TIMESTAMPTZ,
  closed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_cases_open_subject
ON risk_cases(subject_type, subject_id)
WHERE status NOT IN ('closed');

CREATE TABLE IF NOT EXISTS risk_case_comments (
  comment_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES risk_cases(case_id),
  author_id TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS risk_case_timeline (
  timeline_id BIGSERIAL PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES risk_cases(case_id),
  actor_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  before_value JSONB,
  after_value JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS risk_case_evidence_snapshots (
  snapshot_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES risk_cases(case_id),
  ruleset_version TEXT,
  evidence JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sla_policies (
  policy_id TEXT PRIMARY KEY,
  assessment_level TEXT NOT NULL UNIQUE,
  response_minutes INTEGER NOT NULL,
  resolution_minutes INTEGER NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO sla_policies(policy_id, assessment_level, response_minutes, resolution_minutes)
VALUES ('sla-high','high',60,240), ('sla-suspicious','suspicious',240,1440)
ON CONFLICT (assessment_level) DO NOTHING;

CREATE TABLE IF NOT EXISTS enforcement_connectors (
  connector_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  endpoint_url TEXT NOT NULL,
  action_mapping JSONB NOT NULL DEFAULT '{}'::jsonb,
  encrypted_secret BYTEA NOT NULL,
  mode TEXT NOT NULL DEFAULT 'shadow',
  enabled BOOLEAN NOT NULL DEFAULT false,
  shadow_ready BOOLEAN NOT NULL DEFAULT false,
  updated_by TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS enforcement_actions (
  action_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  case_id TEXT REFERENCES risk_cases(case_id),
  connector_id TEXT REFERENCES enforcement_connectors(connector_id),
  action_type TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  account_id TEXT,
  endpoint_id TEXT,
  ip INET,
  session_id TEXT,
  campus_id TEXT,
  status TEXT NOT NULL,
  mode TEXT NOT NULL,
  duration_seconds INTEGER,
  evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  ruleset_version TEXT,
  request_body JSONB,
  response_body JSONB,
  remote_action_id TEXT,
  retry_count INTEGER NOT NULL DEFAULT 0,
  cooldown_until TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  last_error TEXT,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cases_queue ON risk_cases(status, priority, due_at, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_campus ON risk_cases(campus_id, department, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_actions_subject ON enforcement_actions(subject_type, subject_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_actions_circuit ON enforcement_actions(campus_id, status, created_at DESC);
