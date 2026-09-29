package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Existing ingestion maintains ten-minute counters. Complete buckets can use
// those exact counters; only the two partial boundary buckets require raw rows.
// Unsupported dimensions retain the scoped raw count instead of dropping a
// filter or returning an approximate total.
func (s *ClickHouseStore) eventPageCount(ctx context.Context, q Query, where string) (int, error) {
	rest := q
	rest.Level, rest.SensorID, rest.From, rest.To, rest.Window = "", "", "", "", ""
	rest.Limit, rest.Cursor = 0, 0
	if rest != (Query{}) || (q.From == "" && q.To == "" && q.Window == "") {
		return s.eventCount(ctx, where)
	}
	lower := ""
	if q.From != "" {
		if stamp, err := time.Parse(time.RFC3339Nano, q.From); err == nil && stamp.Before(time.Now().Add(-7*24*time.Hour)) {
			return s.eventCount(ctx, where)
		}
		lower = "parseDateTime64BestEffort(" + chQuote(q.From) + ")"
	} else if q.To == "" && q.Window != "" {
		_, duration, err := NormalizeActivityWindow(q.Window)
		if err != nil {
			return 0, err
		}
		value, unit := clickHouseInterval(duration)
		lower = fmt.Sprintf("now()-INTERVAL %d %s", value, unit)
	}
	// An unbounded lower range can include counter buckets already expired in
	// raw storage. Never substitute those lifetime counters for retained rows.
	if lower == "" {
		return s.eventCount(ctx, where)
	}
	definitions := lower + " AS lower,toStartOfInterval(lower,INTERVAL 10 MINUTE)+INTERVAL 10 MINUTE AS first_full"
	full := "window_start>=first_full"
	partial := "timestamp>=lower AND timestamp<first_full"
	if q.To != "" {
		definitions += ",parseDateTime64BestEffort(" + chQuote(q.To) + ") AS upper,toStartOfInterval(upper,INTERVAL 10 MINUTE) AS last_full"
		full += " AND window_start<last_full"
		partial = "timestamp>=lower AND timestamp<=upper AND (timestamp<first_full OR timestamp>=last_full)"
	}
	var scope []string
	if q.SensorID != "" {
		scope = append(scope, "sensor_id="+chQuote(q.SensorID))
	}
	if q.Level != "" {
		scope = append(scope, "type="+chQuote(q.Level))
	}
	if len(scope) > 0 {
		scopeSQL := " AND " + strings.Join(scope, " AND ")
		full += scopeSQL
		partial += scopeSQL
	}
	data, err := s.query(ctx, "WITH "+definitions+" SELECT (SELECT coalesce(sum(events),0) FROM collector_event_counts_10m WHERE "+full+")+(SELECT count() FROM normalized_events WHERE "+partial+") AS count SETTINGS max_threads=1,max_block_size=8192,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow")
	if err != nil {
		return 0, err
	}
	return decodeSingleCount(data)
}
