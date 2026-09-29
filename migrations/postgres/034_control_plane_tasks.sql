CREATE TABLE IF NOT EXISTS control_plane_tasks (
 task_id TEXT PRIMARY KEY,
 kind TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','cancelled')),
 created_by TEXT NOT NULL,
 idempotency_key TEXT,
 request_hash TEXT NOT NULL,
 actor JSONB NOT NULL,
 method TEXT NOT NULL,
 request_path TEXT NOT NULL,
 content_type TEXT NOT NULL,
 input_path TEXT NOT NULL,
 result JSONB,
 error TEXT,
 response_status INTEGER,
 attempts INTEGER NOT NULL DEFAULT 0,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 started_at TIMESTAMPTZ,
 completed_at TIMESTAMPTZ,
 lease_until TIMESTAMPTZ,
 worker_id TEXT,
 UNIQUE(created_by,idempotency_key)
);
CREATE INDEX IF NOT EXISTS control_plane_tasks_queue ON control_plane_tasks(status,created_at,task_id);
