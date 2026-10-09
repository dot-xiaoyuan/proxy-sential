-- Repair display timestamps emitted by the initial projection implementation.
-- Immutable snapshots, accounting authority and policy state are untouched.
UPDATE account_identity_session_projection
SET document=jsonb_set(document,'{ended_at}',to_jsonb(to_char(confirmed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')))
WHERE document->>'ended_at' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}';
