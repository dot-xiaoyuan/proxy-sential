-- Internal scan clues are disabled until campus zones and traffic coverage are reviewed.
CREATE TABLE IF NOT EXISTS internal_scan_rules (
  campus_id text PRIMARY KEY,
  enabled boolean NOT NULL DEFAULT false,
  excluded_source_cidrs jsonb NOT NULL DEFAULT '[]'::jsonb,
  dense_hosts integer NOT NULL DEFAULT 32 CHECK (dense_hosts > 0),
  dense_attempts integer NOT NULL DEFAULT 50 CHECK (dense_attempts > 0),
  dense_consecutive integer NOT NULL DEFAULT 16 CHECK (dense_consecutive > 0),
  dense_failure_ratio double precision NOT NULL DEFAULT 0.6 CHECK (dense_failure_ratio > 0 AND dense_failure_ratio <= 1),
  sparse_zones integer NOT NULL DEFAULT 50 CHECK (sparse_zones > 0),
  sparse_ports integer NOT NULL DEFAULT 3 CHECK (sparse_ports > 0),
  sparse_thin_ratio double precision NOT NULL DEFAULT 0.8 CHECK (sparse_thin_ratio > 0 AND sparse_thin_ratio <= 1),
  sparse_failure_ratio double precision NOT NULL DEFAULT 0.5 CHECK (sparse_failure_ratio > 0 AND sparse_failure_ratio <= 1),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS internal_scan_findings (
  finding_id text PRIMARY KEY,
  campus_id text NOT NULL,
  sensor_id text NOT NULL,
  source_ip inet NOT NULL,
  mode text NOT NULL CHECK (mode IN ('dense_internal_scan','sparse_cross_subnet_scan')),
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  zone_count integer NOT NULL,
  destination_count integer NOT NULL,
  longest_consecutive integer NOT NULL,
  attempt_count integer NOT NULL,
  failed_count integer NOT NULL,
  succeeded_count integer NOT NULL,
  unknown_count integer NOT NULL,
  details jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS internal_scan_findings_source_time ON internal_scan_findings(campus_id,source_ip,window_end DESC);
CREATE INDEX IF NOT EXISTS internal_scan_findings_created ON internal_scan_findings(created_at);

CREATE TABLE IF NOT EXISTS internal_scan_runs (
  run_at timestamptz PRIMARY KEY,
  status text NOT NULL CHECK (status IN ('complete','incomplete')),
  reason text NOT NULL DEFAULT '',
  flow_count integer NOT NULL DEFAULT 0,
  finding_count integer NOT NULL DEFAULT 0
);
