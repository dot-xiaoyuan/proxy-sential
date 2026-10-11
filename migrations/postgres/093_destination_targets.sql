-- Internal destination access detection replaces the legacy "poison behaviour"
-- check. Rules ship disabled: the sensitive ranges and thresholds are site
-- facts, not defaults, and the evaluator must be previewed before it is enabled.
CREATE TABLE IF NOT EXISTS destination_target_rules (
  rule_id text PRIMARY KEY,
  name text NOT NULL,
  enabled boolean NOT NULL DEFAULT false,
  behavior_type text NOT NULL DEFAULT 'configured_ip_range' CHECK(behavior_type IN ('configured_ip_range','high_frequency_internal')),
  target_type text NOT NULL DEFAULT 'cidr' CHECK(target_type IN ('ip','cidr','domain')),
  targets text[] NOT NULL DEFAULT '{}',
  window_seconds integer NOT NULL DEFAULT 3600 CHECK(window_seconds BETWEEN 60 AND 86400),
  threshold integer NOT NULL DEFAULT 1 CHECK(threshold>=1),
  direction text NOT NULL DEFAULT 'any' CHECK(direction IN ('any','up','down')),
  push_enabled boolean NOT NULL DEFAULT false,
  push_without_account boolean NOT NULL DEFAULT false,
  created_by text NOT NULL DEFAULT '',
  updated_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS destination_target_findings (
  finding_id text PRIMARY KEY,
  rule_id text NOT NULL,
  subject_ip text NOT NULL,
  account_id text NOT NULL DEFAULT '',
  behavior_type text NOT NULL,
  matched_targets jsonb NOT NULL DEFAULT '[]'::jsonb,
  unique_destinations integer NOT NULL DEFAULT 0,
  hit_count integer NOT NULL DEFAULT 0,
  direction text NOT NULL DEFAULT '',
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  pushed boolean NOT NULL DEFAULT false,
  push_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS destination_target_findings_created ON destination_target_findings(created_at DESC);
CREATE INDEX IF NOT EXISTS destination_target_findings_subject ON destination_target_findings(subject_ip,window_start DESC);
