package store

import (
	"context"
	"fmt"
	"time"
)

func (s *DBStore) rebuildActivityCoarseBuckets(ctx context.Context, rows []activityChartCursor, revision uint64) error {
	for _, model := range []struct {
		table, source, truncate string
		width                   time.Duration
	}{
		{"activity_chart_hour_facts", "activity_chart_bucket_facts_v2", "toStartOfHour", time.Hour},
		{"activity_chart_day_facts", "activity_chart_hour_facts", "toStartOfDay", 24 * time.Hour},
	} {
		keys := []string{}
		seen := map[string]bool{}
		var first, last time.Time
		for _, row := range rows {
			stamp, err := time.Parse(time.RFC3339Nano, row.WindowStart)
			if err != nil {
				return err
			}
			stamp = stamp.Truncate(model.width)
			if first.IsZero() || stamp.Before(first) {
				first = stamp
			}
			if last.IsZero() || stamp.After(last) {
				last = stamp
			}
			key := "(parseDateTimeBestEffort(" + chQuote(stamp.Format(time.RFC3339Nano)) + ")," + chQuote(row.SensorID) + "," + chQuote(row.CampusID) + ")"
			if !seen[key] {
				seen[key] = true
				keys = append(keys, key)
			}
		}
		if len(keys) == 0 {
			continue
		}
		// Rebuild one immutable bucket/scope at a time. A historical batch
		// can span seven days; aggregating all its coarse keys in one query
		// shares FINAL and aggregation memory and can exceed the fixed cap.
		for _, key := range keys {
			query := fmt.Sprintf(`INSERT INTO %s
	 SELECT window_start,sensor_id,campus_id,dimension,value,toUInt64(0),first_seen,last_seen,toUInt64(%d) FROM %s FINAL PREWHERE (window_start,sensor_id,campus_id) IN(%s)
	 UNION ALL
	 SELECT %s(window_start) AS bucket,sensor_id,campus_id,dimension,value,sum(event_count),min(first_seen),max(last_seen),toUInt64(%d) FROM %s FINAL PREWHERE (window_start>=parseDateTimeBestEffort(%s) AND window_start<parseDateTimeBestEffort(%s) AND (%s(window_start),sensor_id,campus_id) IN(%s)) WHERE event_count>0 GROUP BY bucket,sensor_id,campus_id,dimension,value
	 SETTINGS max_threads=1,max_block_size=2048,min_insert_block_size_rows=65536,min_insert_block_size_bytes=8388608,max_memory_usage=268435456,max_bytes_before_external_group_by=67108864,max_execution_time=20,async_insert=0`, model.table, revision*2, model.table, key, model.truncate, revision*2+1, model.source, chQuote(first.Format(time.RFC3339Nano)), chQuote(last.Add(model.width).Format(time.RFC3339Nano)), model.truncate, key)
			if err := s.ch.exec(ctx, query); err != nil {
				return fmt.Errorf("rebuild activity coarse table %s bucket %s: %w", model.table, key, err)
			}
		}
	}
	return nil
}
