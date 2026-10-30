-- Incremental recognition coverage shadow. One row per minute/protocol; the
-- 24h API can merge these rows instead of scanning the receipt window.
CREATE TABLE IF NOT EXISTS recognition_coverage_minute_shadow (
    minute TIMESTAMPTZ NOT NULL,
    protocol TEXT NOT NULL,
    inputs BIGINT NOT NULL,
    parsed BIGINT NOT NULL,
    attributed BIGINT NOT NULL,
    features BIGINT NOT NULL,
    candidates BIGINT NOT NULL,
    conclusions BIGINT NOT NULL,
    conflict BIGINT NOT NULL,
    processing BIGINT NOT NULL,
    unattributed BIGINT NOT NULL,
    insufficient BIGINT NOT NULL,
    errors BIGINT NOT NULL,
    overdue BIGINT NOT NULL,
    timed BIGINT NOT NULL,
    read_ms DOUBLE PRECISION NOT NULL,
    lookup_ms DOUBLE PRECISION NOT NULL,
    rules_ms DOUBLE PRECISION NOT NULL,
    write_ms DOUBLE PRECISION NOT NULL,
    p95_ms DOUBLE PRECISION NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (minute, protocol)
);
