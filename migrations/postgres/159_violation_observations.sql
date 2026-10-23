-- All prospective external actions remain local observations.
CREATE TABLE IF NOT EXISTS violation_observations (
 observation_key text PRIMARY KEY,
 kind text NOT NULL,
 target text NOT NULL DEFAULT '',
 case_id text NOT NULL DEFAULT '',
 facts jsonb NOT NULL DEFAULT '{}'::jsonb,
 observed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS violation_observations_recent ON violation_observations(observed_at DESC,observation_key DESC);
CREATE INDEX IF NOT EXISTS violation_observations_target_recent ON violation_observations(target,observed_at DESC);
CREATE INDEX IF NOT EXISTS violation_observations_target_key ON violation_observations(target,observation_key DESC);
CREATE INDEX IF NOT EXISTS violation_observations_case_recent ON violation_observations(case_id,observed_at DESC,observation_key DESC) WHERE case_id<>'';

CREATE TABLE IF NOT EXISTS violation_cases (
 case_id text PRIMARY KEY,
 account_id text NOT NULL,
 assessment_id text NOT NULL,
 status text NOT NULL CHECK(status IN ('open','closed')),
 first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL,
 simulated_notice_times jsonb NOT NULL DEFAULT '[]'::jsonb,
 prior_sanctions integer NOT NULL DEFAULT 0,
 last_violation timestamptz,
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(account_id,assessment_id)
);
CREATE INDEX IF NOT EXISTS violation_cases_account ON violation_cases(account_id,updated_at DESC);
CREATE INDEX IF NOT EXISTS violation_cases_account_key ON violation_cases(account_id,case_id DESC);
CREATE INDEX IF NOT EXISTS violation_cases_open ON violation_cases(updated_at DESC) WHERE status='open';

CREATE TABLE IF NOT EXISTS violation_worker_state (
 worker_key text PRIMARY KEY,
 cursor_value text NOT NULL DEFAULT '',
 updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS violation_scan_evaluations (
 evaluation_id text PRIMARY KEY,
 source_id text NOT NULL,
 observed_at timestamptz NOT NULL DEFAULT now(),
 assessment jsonb NOT NULL,
 created_by text NOT NULL DEFAULT '',
 reviewer_label text NOT NULL DEFAULT '' CHECK(reviewer_label IN ('','true_positive','false_positive','uncertain')),
 reviewed_by text NOT NULL DEFAULT '',
 reviewed_at timestamptz
);
CREATE INDEX IF NOT EXISTS violation_scan_evaluations_recent ON violation_scan_evaluations(observed_at DESC,evaluation_id DESC);
