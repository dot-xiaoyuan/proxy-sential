-- Remove the fixed identifiers used by the original domain evidence integration test.
-- These values are reserved test fixtures and are not valid production observations.
DELETE FROM endpoint_domain_evidence_events
WHERE endpoint_id = 'mac:02:00:00:00:09:12'
  AND rule_version = 'domain-integration-v1';

DELETE FROM endpoint_domain_evidence
WHERE endpoint_id = 'mac:02:00:00:00:09:12'
  AND rule_version = 'domain-integration-v1';

DELETE FROM account_sessions
WHERE session_id = 'domain-integration-session';

DELETE FROM endpoint_entities
WHERE endpoint_id = 'mac:02:00:00:00:09:12'
  AND NOT EXISTS (
    SELECT 1 FROM endpoint_domain_evidence evidence
    WHERE evidence.endpoint_id = endpoint_entities.endpoint_id
  );
