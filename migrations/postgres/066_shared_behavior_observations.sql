CREATE TABLE IF NOT EXISTS shared_behavior_observations (
 observation_id text PRIMARY KEY,
 sensor_id text NOT NULL,
 campus_id text NOT NULL DEFAULT '',
 access_domain text NOT NULL DEFAULT '',
 ip inet NOT NULL,
 endpoint_id text NOT NULL DEFAULT '',
 router_assessment_id text NOT NULL DEFAULT '',
 status text NOT NULL CHECK(status IN ('candidate','likely','confirmed')),
 confidence integer NOT NULL CHECK(confidence BETWEEN 0 AND 100),
 signal_groups text[] NOT NULL DEFAULT '{}',
 rule_version text NOT NULL,
 coverage_state text NOT NULL CHECK(coverage_state IN ('verified','partial','unknown')),
 first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL,
 window_start timestamptz NOT NULL,
 window_end timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 observation jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS shared_behavior_observations_page
 ON shared_behavior_observations(last_seen DESC,observation_id DESC);
CREATE INDEX IF NOT EXISTS shared_behavior_observations_status
 ON shared_behavior_observations(status,confidence DESC,last_seen DESC);
CREATE INDEX IF NOT EXISTS shared_behavior_observations_ip
 ON shared_behavior_observations(ip,last_seen DESC);
CREATE INDEX IF NOT EXISTS shared_behavior_observations_endpoint
 ON shared_behavior_observations(endpoint_id,last_seen DESC)
 WHERE endpoint_id<>'';

CREATE TABLE IF NOT EXISTS shared_behavior_observation_history (
 history_id bigserial PRIMARY KEY,
 observation_id text NOT NULL REFERENCES shared_behavior_observations(observation_id) ON DELETE CASCADE,
 status text NOT NULL,
 confidence integer NOT NULL,
 signal_groups text[] NOT NULL DEFAULT '{}',
 coverage_state text NOT NULL,
 observation jsonb NOT NULL,
 observed_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS shared_behavior_observation_history_item
 ON shared_behavior_observation_history(observation_id,observed_at DESC,history_id DESC);
