CREATE TABLE IF NOT EXISTS endpoint_entities (
  endpoint_id TEXT PRIMARY KEY,
  primary_mac TEXT,
  entity_role TEXT NOT NULL DEFAULT 'endpoint',
  first_seen TIMESTAMPTZ,
  last_seen TIMESTAMPTZ,
  identity_confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  registration_status TEXT NOT NULL DEFAULT 'unregistered',
  owner_account TEXT,
  owner_name TEXT,
  owner_department TEXT,
  asset_tag TEXT,
  registered_by TEXT,
  registered_at TIMESTAMPTZ,
  registration_note TEXT,
  merge_status TEXT NOT NULL DEFAULT 'active',
  merged_into_endpoint_id TEXT,
  split_from_endpoint_id TEXT,
  registration_updated_by TEXT,
  registration_updated_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE endpoint_entities ADD COLUMN IF NOT EXISTS registration_status TEXT NOT NULL DEFAULT 'unregistered';
ALTER TABLE endpoint_entities ADD COLUMN IF NOT EXISTS owner_account TEXT;
ALTER TABLE endpoint_entities ADD COLUMN IF NOT EXISTS owner_name TEXT;
ALTER TABLE endpoint_entities ADD COLUMN IF NOT EXISTS owner_department TEXT;
ALTER TABLE endpoint_entities ADD COLUMN IF NOT EXISTS asset_tag TEXT;
ALTER TABLE endpoint_entities ADD COLUMN IF NOT EXISTS registered_by TEXT;
ALTER TABLE endpoint_entities ADD COLUMN IF NOT EXISTS registered_at TIMESTAMPTZ;
ALTER TABLE endpoint_entities ADD COLUMN IF NOT EXISTS registration_note TEXT;
ALTER TABLE endpoint_entities ADD COLUMN IF NOT EXISTS merge_status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE endpoint_entities ADD COLUMN IF NOT EXISTS merged_into_endpoint_id TEXT;
ALTER TABLE endpoint_entities ADD COLUMN IF NOT EXISTS split_from_endpoint_id TEXT;
ALTER TABLE endpoint_entities ADD COLUMN IF NOT EXISTS registration_updated_by TEXT;
ALTER TABLE endpoint_entities ADD COLUMN IF NOT EXISTS registration_updated_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS infrastructure_entities (
  entity_id TEXT PRIMARY KEY,
  ip INET,
  mac TEXT,
  entity_role TEXT NOT NULL,
  name TEXT,
  source TEXT NOT NULL DEFAULT 'config',
  first_seen TIMESTAMPTZ,
  last_seen TIMESTAMPTZ,
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS account_sessions (
  session_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  endpoint_id TEXT,
  ip INET,
  mac TEXT,
  access_id TEXT,
  source TEXT NOT NULL,
  started_at TIMESTAMPTZ NOT NULL,
  ended_at TIMESTAMPTZ,
  identity_confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
  raw_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS identity_ip_mac_history (
  event_id TEXT NOT NULL UNIQUE,
  history_id BIGSERIAL PRIMARY KEY,
  endpoint_id TEXT,
  account_id TEXT,
  entity_role TEXT NOT NULL DEFAULT 'unknown',
  ip INET,
  mac TEXT,
  source TEXT NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  identity_confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
  event_ids_sample JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE TABLE IF NOT EXISTS identity_access_history (
  event_id TEXT NOT NULL UNIQUE,
  history_id BIGSERIAL PRIMARY KEY,
  endpoint_id TEXT,
  account_id TEXT,
  entity_role TEXT NOT NULL DEFAULT 'unknown',
  access_id TEXT NOT NULL,
  access_type TEXT,
  ap TEXT,
  switch_id TEXT,
  switch_port TEXT,
  vlan TEXT,
  source TEXT NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  identity_confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
  event_ids_sample JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE TABLE IF NOT EXISTS subject_evidence (
  evidence_id TEXT PRIMARY KEY,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  account_id TEXT,
  endpoint_id TEXT,
  ip INET,
  type TEXT NOT NULL,
  "window" TEXT NOT NULL,
  score INTEGER NOT NULL,
  confidence DOUBLE PRECISION NOT NULL,
  severity TEXT NOT NULL,
  reason TEXT NOT NULL,
  samples JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS subject_risk_snapshots (
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  account_id TEXT,
  endpoint_id TEXT,
  ip INET,
  score INTEGER NOT NULL,
  level TEXT NOT NULL,
  confidence DOUBLE PRECISION NOT NULL,
  "window" TEXT NOT NULL,
  evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  summary TEXT NOT NULL,
  recommended_action TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY(subject_type, subject_id)
);

CREATE TABLE IF NOT EXISTS subject_risk_snapshot_history (
  history_id BIGSERIAL PRIMARY KEY,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  snapshot JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_endpoint_entities_mac ON endpoint_entities(primary_mac);
CREATE INDEX IF NOT EXISTS idx_infrastructure_entities_ip ON infrastructure_entities(ip);
CREATE INDEX IF NOT EXISTS idx_account_sessions_account ON account_sessions(account_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_ip_mac_history_lookup ON identity_ip_mac_history(account_id, ip, mac, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_identity_access_history_lookup ON identity_access_history(account_id, access_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_subject_evidence_subject ON subject_evidence(subject_type, subject_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_subject_risk_level_score ON subject_risk_snapshots(level, score DESC);
