-- The authoritative stream state replaces the duplicate shadow current table.
-- Only current rows enter this paging index: expired states otherwise force a
-- scan of every inactive row in an epoch before returning the first page.
-- It shares current-state lifetime and is maintained by the existing state
-- transaction; no additional event copy, worker or result version is created.
CREATE INDEX stream_discovery_state_current_page
ON stream_discovery_device_state(epoch,last_seen DESC,device_key)
WHERE document->>'current'='true';
