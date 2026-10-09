-- Current discovery is a complete-window projection. Historical evidence and
-- review records remain intact; a non-matching window must not revive old hits.
ALTER TABLE shared_behavior_observations ADD COLUMN IF NOT EXISTS current boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS shared_behavior_current_discovery
 ON shared_behavior_observations(sensor_id,last_seen DESC,observation_id DESC) WHERE current;
