CREATE INDEX IF NOT EXISTS risk_case_snapshots_page_idx ON risk_case_evidence_snapshots(case_id,created_at DESC,snapshot_id DESC);
CREATE INDEX IF NOT EXISTS risk_case_comments_page_idx ON risk_case_comments(case_id,created_at DESC,comment_id DESC);
CREATE INDEX IF NOT EXISTS risk_case_timeline_page_idx ON risk_case_timeline(case_id,created_at DESC,event_id DESC);
CREATE INDEX IF NOT EXISTS enforcement_actions_page_idx ON enforcement_actions(created_at DESC,action_id DESC);
