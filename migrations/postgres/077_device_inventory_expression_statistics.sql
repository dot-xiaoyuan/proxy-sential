-- ANALYZE copies every sampled expression result before the wide-value guard.
-- The devices array contains large raw signals; its distribution is not a
-- useful device-ID selectivity estimate. Keep the GIN index and row content,
-- but skip only this expression's sample evaluation in subsequent ANALYZE runs.
SET LOCAL lock_timeout = '250ms';
SET LOCAL statement_timeout = '5s';
ALTER INDEX idx_device_inventory_candidate_ids ALTER COLUMN 1 SET STATISTICS 0;
