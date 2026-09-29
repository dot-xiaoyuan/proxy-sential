UPDATE read_model_jobs
SET dirty_generation=processed_generation+1,
    status='pending',
    lease_owner='',
    lease_until='-infinity',
    not_before=LEAST(not_before,now()),
    updated_at=now()
WHERE model IN ('activity-5m-v3','activity-hour-v3','activity-day-v3')
  AND processed_generation<dirty_generation;

CREATE TABLE IF NOT EXISTS router_recognition_state (
 singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK(singleton),
 cursor_timestamp TIMESTAMPTZ,
 cursor_event_id TEXT NOT NULL DEFAULT '',
 lease_owner TEXT NOT NULL DEFAULT '',
 lease_until TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
 processed_events BIGINT NOT NULL DEFAULT 0,
 last_success_at TIMESTAMPTZ,
 last_error TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO router_recognition_state(singleton)
VALUES(true)
ON CONFLICT(singleton) DO NOTHING;

CREATE INDEX IF NOT EXISTS router_assessments_expiry_status
ON router_assessments(expires_at,status,confidence DESC,last_seen DESC);
