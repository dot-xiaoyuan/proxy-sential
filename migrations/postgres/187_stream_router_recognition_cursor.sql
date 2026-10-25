-- The new body-free router index advances by insertion time, independently
-- of the legacy event-time cursor. Late source events therefore remain visible.
CREATE TABLE stream_router_recognition_state (
 sensor_id text PRIMARY KEY,
 fresh_cutoff_at timestamptz,
 cancel_id text NOT NULL DEFAULT '',
 cursor_indexed_at timestamptz,
 cursor_event_key text NOT NULL DEFAULT '',
 lease_owner text NOT NULL DEFAULT '',
 lease_until timestamptz NOT NULL DEFAULT '-infinity',
 processed_events bigint NOT NULL DEFAULT 0,
 rule_version text NOT NULL DEFAULT '',
 last_success_at timestamptz,
 last_error text NOT NULL DEFAULT '',
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE stream_router_fresh_cutovers (
 sensor_id text PRIMARY KEY,
 cancel_id text NOT NULL UNIQUE,
 indexed_after timestamptz NOT NULL,
 canceled_index_rows bigint NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION prevent_stream_router_cutover_change() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 RAISE EXCEPTION 'stream router cutover audit is immutable';
END $$;
CREATE TRIGGER stream_router_cutover_immutable BEFORE UPDATE OR DELETE ON stream_router_fresh_cutovers
 FOR EACH ROW EXECUTE FUNCTION prevent_stream_router_cutover_change();
