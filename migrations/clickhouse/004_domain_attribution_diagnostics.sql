ALTER TABLE domain_ecosystem_observations ADD COLUMN IF NOT EXISTS subject_ip String DEFAULT '';
ALTER TABLE domain_ecosystem_observations ADD COLUMN IF NOT EXISTS attribution_method String DEFAULT '';
ALTER TABLE domain_ecosystem_observations ADD COLUMN IF NOT EXISTS attribution_reason String DEFAULT '';
