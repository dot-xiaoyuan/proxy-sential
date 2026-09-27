ALTER TABLE normalized_events ADD COLUMN IF NOT EXISTS dedupe_key String DEFAULT if(match(event_id,'^suricata-[0-9]+-[0-9a-f]{16}$'),concat('suricata-',arrayElement(splitByChar('-',event_id),3)),event_id);
ALTER TABLE normalized_events MODIFY COLUMN dedupe_key String DEFAULT if(match(event_id,'^suricata-[0-9]+-[0-9a-f]{16}$'),concat('suricata-',arrayElement(splitByChar('-',event_id),3)),event_id);

CREATE TABLE IF NOT EXISTS normalized_events_canonical AS normalized_events
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (sensor_id, dedupe_key)
TTL toDateTime(timestamp) + INTERVAL 7 DAY
SETTINGS deduplicate_merge_projection_mode='drop';

ALTER TABLE normalized_events_canonical MODIFY COLUMN dedupe_key String DEFAULT if(match(event_id,'^suricata-[0-9]+-[0-9a-f]{16}$'),concat('suricata-',arrayElement(splitByChar('-',event_id),3)),event_id);

CREATE MATERIALIZED VIEW IF NOT EXISTS normalized_events_canonical_mv TO normalized_events_canonical AS
SELECT * FROM normalized_events;

INSERT INTO normalized_events_canonical SELECT * FROM normalized_events WHERE timestamp >= now() - INTERVAL 7 DAY;
