ALTER TABLE enforcement_connectors
  ADD COLUMN IF NOT EXISTS shadow_validation_since TIMESTAMPTZ;
