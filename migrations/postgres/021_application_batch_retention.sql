-- Bounded retention cleanup must not rescan all recent batch metadata per page.
CREATE INDEX IF NOT EXISTS application_batches_retention
ON application_processing_batches(created_at) WHERE committed;
