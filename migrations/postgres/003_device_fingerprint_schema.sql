CREATE TABLE IF NOT EXISTS endpoint_device_profiles (
  endpoint_id TEXT PRIMARY KEY REFERENCES endpoint_entities(endpoint_id) ON DELETE CASCADE,
  vendor TEXT,
  brand TEXT,
  model TEXT,
  device_type TEXT,
  os_family TEXT,
  recognition_confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
  recognition_source TEXT,
  fingerprint_version TEXT NOT NULL,
  randomized_mac BOOLEAN NOT NULL DEFAULT false,
  evidence_summary JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS device_fingerprint_versions (
  version TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  checksum TEXT NOT NULL,
  status TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  activated_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_endpoint_device_profiles_brand
  ON endpoint_device_profiles(brand, device_type, updated_at DESC);
