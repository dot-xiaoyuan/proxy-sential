-- Traversing a mutable latest projection is not a full historical snapshot.
-- Record rows replaced after the fixed bootstrap start as a separate gap.
ALTER TABLE passive_hardware_runtime
 ADD COLUMN IF NOT EXISTS backfill_changed_rows bigint NOT NULL DEFAULT 0;
