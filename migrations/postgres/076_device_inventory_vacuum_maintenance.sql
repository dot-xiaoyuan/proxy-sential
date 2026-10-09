-- Large JSON inventories live mostly in TOAST. Waiting for the global 20%
-- dead-row threshold leaves deleted snapshots unavailable for timely reuse.
-- This changes maintenance metadata only; evidence and rows remain intact.
SET LOCAL lock_timeout = '250ms';
SET LOCAL statement_timeout = '5s';
ALTER TABLE device_inventory_snapshots SET (
  autovacuum_vacuum_scale_factor = 0.02,
  autovacuum_vacuum_threshold = 2000,
  toast.autovacuum_vacuum_scale_factor = 0.02,
  toast.autovacuum_vacuum_threshold = 2000
);
