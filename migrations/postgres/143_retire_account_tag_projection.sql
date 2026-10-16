-- Retire the account tag projection without deleting historical review data.
-- Account identity sessions remain available to shared-access attribution.
DROP TRIGGER IF EXISTS account_tag_session_queue ON account_sessions;
DROP TRIGGER IF EXISTS account_tag_endpoint_queue ON endpoint_device_profiles;
DROP TRIGGER IF EXISTS account_tag_risk_queue ON subject_risk_snapshots;
DROP TRIGGER IF EXISTS account_tag_router_queue ON router_assessments;
DROP FUNCTION IF EXISTS queue_account_tag_from_session();
DROP FUNCTION IF EXISTS queue_account_tag_from_endpoint();
DROP FUNCTION IF EXISTS queue_account_tag_from_risk();
DROP FUNCTION IF EXISTS queue_account_tag_from_router();
DROP FUNCTION IF EXISTS enqueue_account_tag_projection(TEXT);
