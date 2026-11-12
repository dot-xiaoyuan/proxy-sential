-- A record-only action belongs to a continuous strong-evidence episode, not
-- to each revision of the same observation. Keep the lookup separate so this
-- migration never rebuilds an index over millions of historical executions.
CREATE TABLE shared_observation_episode_index (
 episode_scope_key text NOT NULL,
 execution_id text PRIMARY KEY REFERENCES shared_observation_executions(execution_id) ON DELETE CASCADE
);
CREATE INDEX shared_observation_episode_scope
 ON shared_observation_episode_index(episode_scope_key,execution_id);

-- Historical decisions are reviewed from their saved evidence in bounded
-- evaluation-time order with an immutable first-received cutoff. A correction never rewrites or deletes the decision,
-- action, report or original evidence.
CREATE TABLE shared_observation_correction_runs (
 run_id text PRIMARY KEY,
 bad_rule_before timestamptz NOT NULL,
 received_before timestamptz NOT NULL,
 cursor_evaluated_at timestamptz NOT NULL DEFAULT 'epoch',
 cursor_decision_id text NOT NULL DEFAULT '',
 inspected bigint NOT NULL DEFAULT 0,
 insufficient bigint NOT NULL DEFAULT 0,
 unverified bigint NOT NULL DEFAULT 0,
 status text NOT NULL DEFAULT 'running' CHECK(status IN ('running','completed')),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE shared_observation_decision_corrections (
 decision_id text PRIMARY KEY,
 run_id text NOT NULL REFERENCES shared_observation_correction_runs(run_id),
 evidence_version text NOT NULL,
 source_sha256 char(64) NOT NULL,
 classification text NOT NULL CHECK(classification IN ('insufficient_evidence','unverified')),
 reason text NOT NULL,
 reviewed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX shared_observation_corrections_run
 ON shared_observation_decision_corrections(run_id,decision_id);
