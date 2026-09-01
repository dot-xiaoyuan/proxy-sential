ALTER TABLE risk_cases ADD COLUMN IF NOT EXISTS dedupe_key TEXT;
UPDATE risk_cases SET dedupe_key = md5(subject_type || ':' || subject_id) WHERE dedupe_key IS NULL;
ALTER TABLE risk_cases ALTER COLUMN dedupe_key SET NOT NULL;
DROP INDEX IF EXISTS idx_risk_cases_open_subject;
CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_cases_open_dedupe
ON risk_cases(dedupe_key)
WHERE status <> 'closed';

ALTER TABLE endpoint_entities ADD COLUMN IF NOT EXISTS ownership_class TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE endpoint_device_profiles ADD COLUMN IF NOT EXISTS vendor_confidence DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE endpoint_device_profiles ADD COLUMN IF NOT EXISTS brand_confidence DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE endpoint_device_profiles ADD COLUMN IF NOT EXISTS model_confidence DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE endpoint_device_profiles ADD COLUMN IF NOT EXISTS device_type_confidence DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE endpoint_device_profiles ADD COLUMN IF NOT EXISTS os_family_confidence DOUBLE PRECISION NOT NULL DEFAULT 0;
