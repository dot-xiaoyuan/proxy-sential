-- A record-only policy hit is a terminal reporting record, never a delivery job.
ALTER TABLE behavior_report_outbox DROP CONSTRAINT IF EXISTS behavior_report_outbox_status_check;
ALTER TABLE behavior_report_outbox ADD CONSTRAINT behavior_report_outbox_status_check
  CHECK (status IN ('queued','sending','sent','failed','cancelled','recorded'));

-- Historical reconciliation runs separately in bounded batches after release.
