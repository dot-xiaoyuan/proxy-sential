-- Time-ordered pages must not sort every retained payload row. The projection
-- preserves the original rows (including duplicate ingestion semantics).
ALTER TABLE normalized_events ADD PROJECTION IF NOT EXISTS event_time_page
 (SELECT * ORDER BY (timestamp,event_id,sensor_id));
ALTER TABLE normalized_events MATERIALIZE PROJECTION event_time_page
 SETTINGS mutations_sync=2;

-- Detail lookup receives an event ID, rather than a sensor/IP/time range.
ALTER TABLE normalized_events ADD INDEX IF NOT EXISTS event_id_lookup
 event_id TYPE bloom_filter(0.001) GRANULARITY 1;
ALTER TABLE normalized_events MATERIALIZE INDEX event_id_lookup
 SETTINGS mutations_sync=2;
