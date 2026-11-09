-- Passive discovery writes DNS-SD service_instance as a plain column so dedup
-- and retention joins do not extract JSON for every observation. The column was
-- added by hand on the 204 test host; codify it so fresh installs match the code.
ALTER TABLE discovery_observations ADD COLUMN IF NOT EXISTS service_instance text;

UPDATE discovery_observations
   SET service_instance = coalesce(data->'evidence'->'payload'->>'service_instance','')
 WHERE service_instance IS NULL;
