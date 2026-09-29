-- Coordinate reference creation with retention without locking entire case tables.
-- Retention takes the same global shared guard and nonblocking per-IP locks.
-- Unknown references take the exclusive global guard and protect all snapshots.
SET LOCAL lock_timeout = '2s';
CREATE OR REPLACE FUNCTION sentinel_guard_inventory_reference() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  reference_ip text;
BEGIN
  IF TG_TABLE_NAME = 'risk_cases' THEN
    reference_ip := NEW.ip::text;
  ELSE
    reference_ip := NULLIF(NEW.evidence->>'ip','');
  END IF;
  BEGIN
    reference_ip := host(reference_ip::inet);
  EXCEPTION WHEN invalid_text_representation THEN
    reference_ip := NULL;
  END;
  IF reference_ip IS NULL THEN
    PERFORM pg_advisory_xact_lock(hashtextextended('sentinel:inventory-reference:global',0));
  ELSE
    PERFORM pg_advisory_xact_lock_shared(hashtextextended('sentinel:inventory-reference:global',0));
    PERFORM pg_advisory_xact_lock(hashtextextended('sentinel:inventory-reference:ip:' || reference_ip,0));
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS inventory_reference_guard ON risk_cases;
CREATE TRIGGER inventory_reference_guard BEFORE INSERT OR UPDATE ON risk_cases
FOR EACH ROW EXECUTE FUNCTION sentinel_guard_inventory_reference();
DROP TRIGGER IF EXISTS inventory_reference_guard ON risk_case_evidence_snapshots;
CREATE TRIGGER inventory_reference_guard BEFORE INSERT OR UPDATE ON risk_case_evidence_snapshots
FOR EACH ROW EXECUTE FUNCTION sentinel_guard_inventory_reference();
