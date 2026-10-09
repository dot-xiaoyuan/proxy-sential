ALTER TABLE enforcement_actions
    ADD COLUMN IF NOT EXISTS precheck_retry_count integer NOT NULL DEFAULT 0
        CHECK (precheck_retry_count BETWEEN 0 AND 5),
    ADD COLUMN IF NOT EXISTS precheck_retryable boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN enforcement_actions.precheck_retry_count IS
    'Bounded pre-dispatch validation failure count, independent of transport attempts; explicit recovery retry resets this budget';
COMMENT ON COLUMN enforcement_actions.precheck_retryable IS
    'Latest validation failure was a typed unavailable read or context interruption; never authorizes dispatch';
