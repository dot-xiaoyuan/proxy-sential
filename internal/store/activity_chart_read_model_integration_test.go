package store

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

func TestActivityChartBucketReplay(t *testing.T) {
	d := appIntegrationDB(t)
	s := d.store
	ctx := context.Background()
	sensor := fmt.Sprintf("chart-replay-%d", time.Now().UnixNano())
	base := time.Now().UTC().Truncate(24 * time.Hour).Add(-3*24*time.Hour + time.Hour)
	t.Cleanup(func() {
		for _, table := range []string{"normalized_events", "normalized_event_features", "activity_chart_bucket_facts_v2", "activity_chart_hour_facts", "activity_chart_day_facts", "activity_chart_dirty_log"} {
			if err := s.ch.exec(ctx, "ALTER TABLE "+table+" DELETE WHERE sensor_id="+chQuote(sensor)+" SETTINGS mutations_sync=2"); err != nil {
				t.Error(err)
			}
		}
	})
	var events []normalized.Event
	for i, typ := range []string{"dns", "http", "tls", "quic", "http", "tls", "dns", "http"} {
		events = append(events, normalized.Event{EventID: fmt.Sprintf("%s-%d", sensor, i), SchemaVersion: "1", Source: "test", Type: typ, Timestamp: base.Add(time.Duration(i)*2*time.Minute + time.Duration(i)*time.Microsecond).Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor}, Subject: map[string]any{"ip": fmt.Sprintf("10.20.0.%d", i%3), "campus_id": fmt.Sprintf("campus-%d", i%2)}, Flow: map[string]any{"proto": "tcp", "dst_ip": "1.1.1.1", "dst_port": 443}, Payload: map[string]any{"query": "dns.test", "host": "http.test", "sni": "tls.test", "user_agent": "replay-agent", "ja3": "fingerprint", "ja4": "fingerprint4"}})
	}
	for i := 0; i < 3; i++ {
		event := events[i]
		event.EventID = fmt.Sprintf("%s-later-day-%d", sensor, i)
		event.Timestamp = base.Add(24*time.Hour + time.Duration(i)*time.Hour + time.Minute).Format(time.RFC3339Nano)
		events = append(events, event)
	}
	if err := s.ch.WriteNormalizedEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	// Replayed canonical features generate dirty notifications twice. Counts must
	// stay canonical even before replacing merges happen.
	if err := s.ch.exec(ctx, "INSERT INTO normalized_event_features SELECT * FROM normalized_event_features WHERE sensor_id="+chQuote(sensor)); err != nil {
		t.Fatal(err)
	}
	if err := s.DrainActivityChartReadModel(ctx); err != nil {
		t.Fatal(err)
	}
	compare := func(q ActivityQuery, w time.Duration) {
		t.Helper()
		risks := map[string]risk.Snapshot{"10.20.0.0": {IP: "10.20.0.0", Level: "high", Score: 95}, "10.20.0.1": {IP: "10.20.0.1", Level: "suspicious", Score: 70}}
		old, err := s.ch.getActivityOverview(ctx, q, w, risks, false)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.ch.getActivityOverview(ctx, q, w, risks, true)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(old, got) {
			t.Fatalf("bucket result differs query=%+v window=%s\nold=%+v\nnew=%+v", q, w, old, got)
		}
		// DPI supports named windows; compare both paths with the same exact
		// as_of and network scope independently from the activity duration.
		oldDPI, err := s.ch.QueryDPIOverview(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		newDPI, err := s.ch.queryDPICoarseOverview(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(oldDPI, newDPI) {
			t.Fatalf("DPI tier result differs: query=%+v old=%+v new=%+v", q, oldDPI, newDPI)
		}
	}
	for _, window := range []string{"24h", "7d"} {
		_, duration, _ := NormalizeActivityWindow(window)
		for _, campus := range []string{"", "campus-0", "campus-1", "missing"} {
			compare(ActivityQuery{SensorID: sensor, CampusID: campus, AsOf: base.Add(48*time.Hour + 15*time.Minute + time.Microsecond).Format(time.RFC3339Nano), Window: window}, duration)
		}
	}
	for _, offset := range []time.Duration{4 * time.Minute, 10 * time.Minute, 15*time.Minute + time.Microsecond} {
		for _, window := range []time.Duration{3 * time.Minute, 10 * time.Minute, time.Hour} {
			for _, campus := range []string{"", "campus-0", "campus-1", "missing"} {
				compare(ActivityQuery{SensorID: sensor, CampusID: campus, AsOf: base.Add(offset).Format(time.RFC3339Nano), Window: "1h"}, window)
			}
		}
	}
	// A late event changes an already summarized bucket.
	late := events[0]
	late.EventID = sensor + "-late"
	late.Timestamp = base.Add(time.Minute).Format(time.RFC3339Nano)
	if err := s.ch.WriteNormalizedEvents(ctx, []normalized.Event{late}); err != nil {
		t.Fatal(err)
	}
	if err := s.DrainActivityChartReadModel(ctx); err != nil {
		t.Fatal(err)
	}
	compare(ActivityQuery{SensorID: sensor, AsOf: base.Add(15 * time.Minute).Format(time.RFC3339Nano), Window: "1h"}, time.Hour)
}
