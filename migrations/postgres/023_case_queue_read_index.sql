-- The queue is paged independently of evidence/history and operations mutations.
CREATE INDEX IF NOT EXISTS idx_risk_cases_queue_page
ON risk_cases(priority, updated_at DESC, case_id);
