CREATE TABLE IF NOT EXISTS shared_behavior_generations (
 generation_id text PRIMARY KEY,
 sensor_id text NOT NULL,
 window_start timestamptz NOT NULL,
 window_end timestamptz NOT NULL,
 coverage_state text NOT NULL CHECK(coverage_state IN ('verified','incomplete','failed')),
 coverage_blockers text[] NOT NULL DEFAULT '{}',
 observation_count integer NOT NULL DEFAULT 0,
 confirmed_count integer NOT NULL DEFAULT 0,
 active boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS shared_behavior_generation_active_sensor
 ON shared_behavior_generations(sensor_id) WHERE active;
CREATE INDEX IF NOT EXISTS shared_behavior_generation_latest
 ON shared_behavior_generations(sensor_id,window_end DESC,created_at DESC);

ALTER TABLE shared_behavior_observations
 ADD COLUMN IF NOT EXISTS generation_id text NOT NULL DEFAULT '';
ALTER TABLE shared_behavior_observations
 ADD COLUMN IF NOT EXISTS current boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS shared_behavior_observations_current_page
 ON shared_behavior_observations(confidence DESC,last_seen DESC,observation_id DESC)
 WHERE current;

ALTER TABLE shared_behavior_observation_history
 ADD COLUMN IF NOT EXISTS generation_id text NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS shared_behavior_history_generation
 ON shared_behavior_observation_history(observation_id,generation_id)
 WHERE generation_id<>'';

ALTER TABLE risk_snapshots
 ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}';
