-- Protocol withdrawals target a claim, including older content variants, while
-- contradictory product contents remain distinct facts until explicitly revoked.
ALTER TABLE passive_hardware_facts ADD COLUMN IF NOT EXISTS claim_key text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS passive_hardware_facts_claim ON passive_hardware_facts(identity_key,claim_key,observed_at);
CREATE INDEX IF NOT EXISTS passive_hardware_current_rule_version ON passive_hardware_current(rule_version,identity_key);
