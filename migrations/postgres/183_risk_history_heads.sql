-- Track the last committed risk interpretation per subject. Identical
-- observations do not need another full JSON history row; a later correction,
-- reversal or out-of-order result remains an independent transition.
CREATE TABLE risk_snapshot_history_heads (
 subject_type text NOT NULL,
 subject_id text NOT NULL,
 snapshot_hash text NOT NULL CHECK (length(snapshot_hash)=32),
 changed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(subject_type,subject_id)
);
