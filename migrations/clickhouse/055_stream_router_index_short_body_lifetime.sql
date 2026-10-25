-- A short-body router reference must expire before its seven-day body.
-- Evidence references keep the existing eight-day hot lookup window.
ALTER TABLE stream_router_signal_index
MODIFY TTL if(retention_class = 'evidence',
              toDateTime(indexed_at) + INTERVAL 8 DAY,
              toDateTime(indexed_at) + INTERVAL 6 DAY) DELETE;
