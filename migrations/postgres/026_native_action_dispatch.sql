CREATE TABLE IF NOT EXISTS native_action_dispatch (
    idempotency_key text PRIMARY KEY,
    intent jsonb NOT NULL,
    reserved_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
COMMENT ON TABLE native_action_dispatch IS 'Immutable native action send reservations; absence of a receipt never permits automatic resend';
