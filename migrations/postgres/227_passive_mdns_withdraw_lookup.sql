-- mDNS TTL=0 withdrawals need to expire every still-active observation for
-- the same source and service instance or address. Without these lookups each
-- withdrawal scans most of a multi-gigabyte discovery history.
--
-- Existing installations build both indexes with CREATE INDEX CONCURRENTLY
-- before running this transactional migration. The conditional DDL below then
-- records the migration without taking a table-wide index-build lock.
-- Each positive DNS-SD observation adds two narrow index entries; both are
-- removed from the active subset on withdrawal and retired with the history.
SET LOCAL lock_timeout = '5s';
DO $$
BEGIN
 IF to_regclass('public.discovery_dns_sd_withdraw_instance') IS NULL THEN
  CREATE INDEX discovery_dns_sd_withdraw_instance
   ON discovery_observations(source_id, ((data->'evidence'->'payload'->>'service_instance')), observed_at)
   WHERE origin='dns_sd' AND NOT withdrawn;
 END IF;
 IF to_regclass('public.discovery_dns_sd_withdraw_ip') IS NULL THEN
  CREATE INDEX discovery_dns_sd_withdraw_ip
   ON discovery_observations(source_id, ((data->>'ip')), observed_at)
   WHERE origin='dns_sd' AND NOT withdrawn;
 END IF;
END $$;
