-- An operator starts a new risk generation only after the prior source is
-- stopped and its fixed segments are reconciled. The old dirty set is audited
-- as canceled work, never acknowledged as evaluated.
CREATE TABLE stream_risk_fresh_cutovers (
 sensor_id text PRIMARY KEY,
 cancel_id text NOT NULL UNIQUE,
 accepted_after timestamptz NOT NULL,
 canceled_subjects bigint NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE stream_risk_canceled_subjects (
 cancel_id text NOT NULL REFERENCES stream_risk_fresh_cutovers(cancel_id),
 sensor_id text NOT NULL,
 subject_type text NOT NULL,
 subject_id text NOT NULL,
 generation bigint NOT NULL,
 first_dirty_at timestamptz NOT NULL,
 last_dirty_at timestamptz NOT NULL,
 last_observed_at timestamptz NOT NULL,
 canceled_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(cancel_id,sensor_id,subject_type,subject_id)
);
-- Existing interpretations remain stored for audit but do not become current
-- until this generation has evaluated their subject from fresh input.
ALTER TABLE stream_risk_evidence ADD COLUMN evaluated_at timestamptz;

CREATE FUNCTION prevent_stream_risk_cancel_audit_change() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
 RAISE EXCEPTION 'stream risk cancellation audit is immutable';
END $$;
CREATE TRIGGER stream_risk_cutover_immutable BEFORE UPDATE OR DELETE ON stream_risk_fresh_cutovers
 FOR EACH ROW EXECUTE FUNCTION prevent_stream_risk_cancel_audit_change();
CREATE TRIGGER stream_risk_canceled_subject_immutable BEFORE UPDATE OR DELETE ON stream_risk_canceled_subjects
 FOR EACH ROW EXECUTE FUNCTION prevent_stream_risk_cancel_audit_change();
