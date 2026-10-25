-- A risk materializer may defer router observation writes only to the
-- incremental owner of the same sensor. Empty value is compatible until the
-- owner claims the row after this additive migration.
ALTER TABLE router_recognition_state ADD COLUMN sensor_id text NOT NULL DEFAULT '';
