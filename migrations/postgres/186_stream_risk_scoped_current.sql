-- New risk decisions are owned by the sensor that produced their confirmed
-- feature lane. Legacy global snapshots remain readable until a scoped read
-- cutover; no migration rewrites or silently adopts old conclusions.
CREATE TABLE stream_risk_current (
 sensor_id text NOT NULL,
 subject_type text NOT NULL CHECK(subject_type IN ('ip','account')),
 subject_id text NOT NULL,
 ip inet,
 score integer NOT NULL,
 level text NOT NULL,
 observed_at timestamptz NOT NULL,
 evaluated_at timestamptz NOT NULL,
 content_sha256 text NOT NULL CHECK(length(content_sha256)=64),
 snapshot jsonb NOT NULL,
 PRIMARY KEY(sensor_id,subject_type,subject_id)
);
CREATE INDEX stream_risk_current_list_idx
 ON stream_risk_current(sensor_id,level,score DESC,subject_id);
CREATE INDEX stream_risk_current_expiry_idx
 ON stream_risk_current(sensor_id,observed_at,subject_type,subject_id);
CREATE TABLE stream_risk_evidence (
 sensor_id text NOT NULL,
 evidence_id text NOT NULL,
 subject_type text NOT NULL,
 subject_id text NOT NULL,
 content_sha256 text NOT NULL CHECK(length(content_sha256)=64),
 evidence jsonb NOT NULL,
 created_at timestamptz NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(sensor_id,evidence_id)
);
CREATE INDEX stream_risk_evidence_subject_idx
 ON stream_risk_evidence(sensor_id,subject_type,subject_id,created_at DESC);
-- Compact changes contain hashes and evidence references, never another full
-- result or event body. A repeated interpretation has no change row.
CREATE TABLE stream_risk_changes (
 change_id bigserial PRIMARY KEY,
 sensor_id text NOT NULL,
 subject_type text NOT NULL,
 subject_id text NOT NULL,
 previous_sha256 text NOT NULL DEFAULT '',
 current_sha256 text NOT NULL DEFAULT '',
 reason text NOT NULL CHECK(reason IN ('created','corrected','expired')),
 evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
 observed_at timestamptz,
 changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX stream_risk_changes_subject_idx
 ON stream_risk_changes(sensor_id,subject_type,subject_id,change_id DESC);
