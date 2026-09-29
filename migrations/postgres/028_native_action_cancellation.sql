ALTER TABLE native_action_dispatch ADD COLUMN IF NOT EXISTS cancelled_at timestamptz;
COMMENT ON COLUMN native_action_dispatch.cancelled_at IS 'Stops future sends; does not reverse already submitted native commands';
