-- A test-data reset can clear the mutable cursor while preserving the last
-- immutable router fresh cutover. Record the deleted interval as unprocessed;
-- its row count is unknown after the authorized ClickHouse truncate.
CREATE TABLE stream_router_reset_recoveries (
 sensor_id text NOT NULL,
 reset_id text NOT NULL,
 fixed_cutover_at timestamptz NOT NULL,
 fixed_cancel_id text NOT NULL,
 reset_started_at timestamptz NOT NULL,
 first_indexed_at timestamptz NOT NULL,
 first_event_key text NOT NULL,
 first_content_sha256 text NOT NULL CHECK (first_content_sha256 ~ '^[0-9a-f]{64}$'),
 retained_before_reset_rows bigint NOT NULL CHECK (retained_before_reset_rows=0),
 retained_reset_to_first_rows bigint NOT NULL CHECK (retained_reset_to_first_rows=0),
 deleted_unprocessed_rows bigint,
 disposition text NOT NULL DEFAULT 'authorized_reset_unprocessed'
   CHECK (disposition='authorized_reset_unprocessed'),
 authorization_ref text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(sensor_id,reset_id),
 FOREIGN KEY(sensor_id,fixed_cutover_at)
   REFERENCES stream_router_fresh_cutovers(sensor_id,indexed_after),
 CHECK (fixed_cutover_at<reset_started_at AND reset_started_at<=first_indexed_at),
 CHECK (deleted_unprocessed_rows IS NULL OR deleted_unprocessed_rows>=0)
);

CREATE FUNCTION prevent_stream_router_reset_recovery_change() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 RAISE EXCEPTION 'stream router reset recovery audit is immutable';
END $$;
CREATE TRIGGER stream_router_reset_recovery_immutable
BEFORE UPDATE OR DELETE ON stream_router_reset_recoveries
FOR EACH ROW EXECUTE FUNCTION prevent_stream_router_reset_recovery_change();
-- A broad test reset may use TRUNCATE ... CASCADE, which bypasses row triggers.
-- This statement trigger also rejects truncation reached through CASCADE.
CREATE TRIGGER stream_router_reset_recovery_no_truncate
BEFORE TRUNCATE ON stream_router_reset_recoveries
FOR EACH STATEMENT EXECUTE FUNCTION prevent_stream_router_reset_recovery_change();
