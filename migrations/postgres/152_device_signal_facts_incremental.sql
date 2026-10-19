-- The current device inventory is refreshed incrementally: each round reads the IPs whose facts changed
-- (updated_at) and rebuilds only those, by IP. Without these indexes both reads scanned the whole table
-- (643 MB on 184) every round.
--
-- Write cost: about 11 fact writes per second on 184; updated_at changes on each, so that index is
-- updated on every write. Read benefit: the refresh no longer loads every fact of 24 hours (about 96k
-- rows, ~360 MB in memory) every 30 seconds.
--
-- device_signal_facts is written continuously; on an existing installation build both indexes first with
-- CREATE INDEX CONCURRENTLY. CREATE INDEX IF NOT EXISTS still takes the table lock before checking the
-- name (it timed out on 184), so each index is created only when absent and no lock is taken otherwise.
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
 IF to_regclass('public.device_signal_facts_changed') IS NULL THEN
  CREATE INDEX device_signal_facts_changed ON device_signal_facts (sensor_id, updated_at);
 END IF;
 IF to_regclass('public.device_signal_facts_ip_window') IS NULL THEN
  CREATE INDEX device_signal_facts_ip_window ON device_signal_facts (sensor_id, ip, last_seen);
 END IF;
END $$;
