-- Most mirrored connection IDs occur only once and never match an application.
-- Keep domain/unknown counts in the observation model, while restricting the
-- expensive per-connection summaries to positively identified applications.
CREATE TABLE IF NOT EXISTS application_recognized_connection_dirty_log (
 written_at DateTime64(9,'UTC'),sensor_id String,campus_id String,connection_id String
) ENGINE = MergeTree
PARTITION BY toDate(written_at)
ORDER BY (written_at,sensor_id,campus_id,connection_id)
TTL toDateTime(written_at) + INTERVAL 8 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS application_recognized_connection_dirty_log_mv
TO application_recognized_connection_dirty_log AS
SELECT now64(9) AS written_at,sensor_id,campus_id,connection_id
FROM application_observations
WHERE target_type='application' AND target_id!='' AND connection_id!=''
GROUP BY sensor_id,campus_id,connection_id;

INSERT INTO application_recognized_connection_dirty_log
SELECT timestamp AS written_at,sensor_id,campus_id,connection_id
FROM application_observations
WHERE target_type='application' AND target_id!='' AND connection_id!=''
GROUP BY written_at,sensor_id,campus_id,connection_id
SETTINGS max_threads=2,max_memory_usage=536870912,max_execution_time=120,async_insert=0;
