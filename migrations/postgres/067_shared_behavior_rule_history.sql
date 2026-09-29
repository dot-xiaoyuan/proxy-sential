ALTER TABLE shared_behavior_observation_history
 ADD COLUMN IF NOT EXISTS rule_version text NOT NULL DEFAULT '';

UPDATE shared_behavior_observation_history
SET rule_version=COALESCE(NULLIF(observation->>'rule_version',''),'shared-behavior/v1')
WHERE rule_version='';
