ALTER TABLE router_recognition_state
ADD COLUMN IF NOT EXISTS rule_version text NOT NULL DEFAULT '';
