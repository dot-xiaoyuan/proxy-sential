SET LOCAL lock_timeout='5s';
-- Actual source timestamps and conservative bounds for already received
-- inventories remain distinguishable in the audit trail.
ALTER TABLE identity_delta_runs ADD COLUMN capture_origin text NOT NULL DEFAULT '';
