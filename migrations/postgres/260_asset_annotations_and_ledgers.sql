-- L3 资产运营层受审计轻量写入：人工核验纠偏/资产备注 与 校方资产台账持久化对账。
-- 绝不修改底层被动发现原始观测与证据，仅以独立业务层表承载并全部写入 audit_logs。

CREATE TABLE IF NOT EXISTS asset_manual_annotations (
  target_key text PRIMARY KEY,
  sensor_id text NOT NULL DEFAULT '',
  verification_status text NOT NULL DEFAULT 'verified',
  override_device_type text NOT NULL DEFAULT '',
  override_brand text NOT NULL DEFAULT '',
  override_model text NOT NULL DEFAULT '',
  department text NOT NULL DEFAULT '',
  owner_name text NOT NULL DEFAULT '',
  asset_tag text NOT NULL DEFAULT '',
  note text NOT NULL DEFAULT '',
  updated_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT asset_manual_annotations_status_check
    CHECK (verification_status IN ('verified', 'corrected', 'ignored', 'unverified'))
);

CREATE INDEX IF NOT EXISTS idx_asset_manual_annotations_sensor_updated
  ON asset_manual_annotations (sensor_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS asset_ledger_snapshots (
  ledger_id text PRIMARY KEY,
  sensor_id text NOT NULL DEFAULT '',
  name text NOT NULL,
  source_kind text NOT NULL DEFAULT 'general',
  entry_count integer NOT NULL DEFAULT 0,
  imported_by text NOT NULL DEFAULT '',
  imported_at timestamptz NOT NULL DEFAULT now(),
  note text NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_asset_ledger_snapshots_imported
  ON asset_ledger_snapshots (imported_at DESC);

CREATE TABLE IF NOT EXISTS asset_ledger_entries (
  id bigserial PRIMARY KEY,
  ledger_id text NOT NULL REFERENCES asset_ledger_snapshots(ledger_id) ON DELETE CASCADE,
  mac text NOT NULL DEFAULT '',
  ip text NOT NULL DEFAULT '',
  asset_name text NOT NULL DEFAULT '',
  expected_type text NOT NULL DEFAULT '',
  expected_vendor text NOT NULL DEFAULT '',
  expected_model text NOT NULL DEFAULT '',
  department text NOT NULL DEFAULT '',
  location text NOT NULL DEFAULT '',
  asset_tag text NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_asset_ledger_entries_ledger
  ON asset_ledger_entries (ledger_id);
CREATE INDEX IF NOT EXISTS idx_asset_ledger_entries_mac
  ON asset_ledger_entries (ledger_id, lower(mac)) WHERE mac <> '';
CREATE INDEX IF NOT EXISTS idx_asset_ledger_entries_ip
  ON asset_ledger_entries (ledger_id, ip) WHERE ip <> '';
