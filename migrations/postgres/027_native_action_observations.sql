CREATE TABLE IF NOT EXISTS native_action_observations (
    observation_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    idempotency_key text NOT NULL REFERENCES native_action_dispatch(idempotency_key),
    result jsonb NOT NULL,
    step_failed boolean NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS native_action_observations_key_idx
    ON native_action_observations(idempotency_key, observation_id DESC);
COMMENT ON TABLE native_action_observations IS 'Append-only native transport and reconciliation observations; not proof of action completion';
