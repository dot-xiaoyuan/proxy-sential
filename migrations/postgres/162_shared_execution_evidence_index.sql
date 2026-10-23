-- Existing installations prebuild this index CONCURRENTLY and verify its
-- definition/validity before running the transactional migration.
SET LOCAL lock_timeout = '5s';
CREATE INDEX IF NOT EXISTS shared_observation_execution_evidence_active
 ON shared_observation_executions(evidence_version) WHERE state<>'expired';
