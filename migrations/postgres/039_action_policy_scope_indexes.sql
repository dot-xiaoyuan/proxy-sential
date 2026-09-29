CREATE INDEX IF NOT EXISTS idx_policy_execution_account_page
 ON account_policy_executions((document->>'account_id'),id);
CREATE INDEX IF NOT EXISTS idx_action_policy_execution
 ON enforcement_actions((policy_parameters->>'execution_id'),action_id);
CREATE INDEX IF NOT EXISTS idx_action_connector_shadow
 ON enforcement_actions(connector_id,created_at)
 WHERE mode='shadow' AND status='shadow';
CREATE INDEX IF NOT EXISTS idx_action_account_cooldown
 ON enforcement_actions(account_id,cooldown_until)
 WHERE account_id IS NOT NULL AND status IN('succeeded','revoked','expired');
CREATE INDEX IF NOT EXISTS idx_action_endpoint_cooldown
 ON enforcement_actions(endpoint_id,cooldown_until)
 WHERE endpoint_id IS NOT NULL AND status IN('succeeded','revoked','expired');
