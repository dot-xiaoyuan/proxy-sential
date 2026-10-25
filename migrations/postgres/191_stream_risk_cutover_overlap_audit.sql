-- A subject may receive fresh input before a new risk cutover is committed.
-- Its old unprocessed work is canceled, while its current dirty generation
-- stays queued. Record this distinction in the immutable cancellation ledger.
ALTER TABLE stream_risk_canceled_subjects
 ADD COLUMN fresh_generation_retained boolean NOT NULL DEFAULT false;
