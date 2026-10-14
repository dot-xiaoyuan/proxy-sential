-- The device center count and facet queries only need last_seen, endpoint_id and the two
-- filter columns, but `endpoint_recognition_summary` carries the wide `list_item` jsonb
-- (~149MB heap for 72k rows). Every count therefore read ~275MB and blew the 10s request
-- budget whenever the working set was not cached; `/device-inventory/metadata` returned 500
-- (`timeout: context deadline exceeded`) on the field.
--
-- This covering index is ~4.7MB and lets the count and facet scans stay index-only, which
-- measured 4.58s -> 0.31s for the 24h window and >30s -> 1.8s for the 有效地址 count.
--
-- As with 105, application-only upgrades run migrations inside a transaction, so the index
-- is built concurrently ahead of the upgrade on an existing installation and this statement
-- records the migration as a no-op there; a fresh install builds it here.
CREATE INDEX IF NOT EXISTS endpoint_recognition_summary_center_scan
 ON endpoint_recognition_summary(last_seen, endpoint_id) INCLUDE (filter_brand, filter_os_family);

ANALYZE endpoint_recognition_summary;
