CREATE TABLE IF NOT EXISTS product_policy_snapshots (
 snapshot_id text PRIMARY KEY,
 source text NOT NULL,
 instance_id text NOT NULL,
 observed_at timestamptz NOT NULL,
 content_hash text NOT NULL,
 document jsonb NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(source, content_hash),
 UNIQUE(source, observed_at)
);
CREATE INDEX IF NOT EXISTS product_policy_snapshots_source_time ON product_policy_snapshots(source, observed_at DESC);

CREATE TABLE IF NOT EXISTS product_catalog (
 source text NOT NULL,
 product_id text NOT NULL,
 name text NOT NULL,
 snapshot_id text NOT NULL REFERENCES product_policy_snapshots(snapshot_id),
 document jsonb NOT NULL,
 active boolean NOT NULL DEFAULT true,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(source, product_id)
);

CREATE TABLE IF NOT EXISTS product_control_catalog (
 source text NOT NULL,
 control_id text NOT NULL,
 name text NOT NULL,
 snapshot_id text NOT NULL REFERENCES product_policy_snapshots(snapshot_id),
 document jsonb NOT NULL,
 active boolean NOT NULL DEFAULT true,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(source, control_id)
);

CREATE TABLE IF NOT EXISTS policy_import_batches (
 batch_id text PRIMARY KEY,
 source text NOT NULL,
 snapshot_id text NOT NULL REFERENCES product_policy_snapshots(snapshot_id),
 status text NOT NULL CHECK(status IN ('previewed','published')),
 preview jsonb NOT NULL,
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 published_at timestamptz
);
CREATE INDEX IF NOT EXISTS policy_import_batches_source_time ON policy_import_batches(source, created_at DESC);

CREATE TABLE IF NOT EXISTS policy_decision_records (
 decision_id text PRIMARY KEY,
 execution_id text NOT NULL,
 policy_id text NOT NULL,
 policy_revision integer NOT NULL,
 account_id text NOT NULL,
 known boolean NOT NULL,
 violated boolean NOT NULL,
 evaluated_at timestamptz NOT NULL,
 document jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS policy_decision_records_time ON policy_decision_records(evaluated_at DESC, decision_id);
CREATE INDEX IF NOT EXISTS policy_decision_records_account_time ON policy_decision_records(account_id, evaluated_at DESC);
