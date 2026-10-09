-- Retain all legacy results; zero is the baseline preceding ordered operations.
SET LOCAL lock_timeout = '250ms';
SET LOCAL statement_timeout = '5s';
ALTER TABLE srun4k_integrations
    ADD COLUMN last_test_result_order bigint NOT NULL DEFAULT 0 CHECK (last_test_result_order >= 0),
    ADD COLUMN last_sync_result_order bigint NOT NULL DEFAULT 0 CHECK (last_sync_result_order >= 0),
    ADD COLUMN last_health_result_order bigint NOT NULL DEFAULT 0 CHECK (last_health_result_order >= 0);
-- Cached blocks could issue an older ordinal from another pooled connection.
CREATE SEQUENCE srun4k_operation_sequence AS bigint CACHE 1 NO CYCLE;
