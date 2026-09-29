package store

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

type coarseFailureTransport struct {
	next   http.RoundTripper
	sensor string
	days   int
}

func (t *coarseFailureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if strings.Contains(string(body), "INSERT INTO activity_chart_day_facts") && strings.Contains(string(body), t.sensor) {
		t.days++
		if t.days == 2 {
			return &http.Response{StatusCode: 500, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("Code: 241. MEMORY_LIMIT_EXCEEDED")), Request: r}, nil
		}
	}
	return t.next.RoundTrip(r)
}

// A partial historical batch may have committed one day and both hours when
// another day fails. Its receipt must remain unacknowledged; retry must produce
// exactly the same counts rather than losing or doubling either day.
func TestActivityCoarseBackfillResumesAfterPartialFailure(t *testing.T) {
	d := appIntegrationDB(t)
	s := d.store
	ctx := context.Background()
	if err := s.DrainActivityChartReadModel(ctx); err != nil {
		t.Fatal(err)
	}
	sensor := fmt.Sprintf("coarse-recovery-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		for _, table := range []string{"normalized_events", "normalized_event_features", "activity_chart_bucket_facts_v2", "activity_chart_hour_facts", "activity_chart_day_facts", "activity_chart_dirty_log"} {
			if err := s.ch.exec(ctx, "ALTER TABLE "+table+" DELETE WHERE sensor_id="+chQuote(sensor)+" SETTINGS mutations_sync=2"); err != nil {
				t.Error(err)
			}
		}
	})
	var before, after []byte
	if err := s.pg.db.QueryRowContext(ctx, `SELECT cursor_document FROM activity_chart_read_model_cursor_v2 WHERE id=1`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(24 * time.Hour).Add(-3*24*time.Hour + time.Hour)
	events := []normalized.Event{}
	for i := 0; i < 2; i++ {
		events = append(events, normalized.Event{EventID: fmt.Sprintf("%s-%d", sensor, i), SchemaVersion: "1", Source: "test", Type: "dns", Timestamp: base.Add(time.Duration(i) * 24 * time.Hour).Format(time.RFC3339Nano), Observer: map[string]any{"sensor_id": sensor}, Subject: map[string]any{"ip": "192.0.2.1"}, Payload: map[string]any{"query": "recovery.test"}})
	}
	if err := s.ch.WriteNormalizedEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	original := s.ch.client
	defer func() { s.ch.client = original }()
	client := *original
	next := client.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	fault := &coarseFailureTransport{next: next, sensor: sensor}
	client.Transport = fault
	s.ch.client = &client
	if err := s.DrainActivityChartReadModel(ctx); err == nil || !strings.Contains(err.Error(), "activity_chart_day_facts") {
		t.Fatalf("missing contextual failure: %v", err)
	}
	if err := s.pg.db.QueryRowContext(ctx, `SELECT cursor_document FROM activity_chart_read_model_cursor_v2 WHERE id=1`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("partial failure acknowledged receipt: before=%s after=%s", before, after)
	}
	s.ch.client = original
	if err := s.DrainActivityChartReadModel(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := s.ch.query(ctx, "SELECT sum(event_count) AS count FROM activity_chart_day_facts FINAL WHERE sensor_id="+chQuote(sensor)+" AND dimension='type' FORMAT JSONEachRow")
	if err != nil {
		t.Fatal(err)
	}
	count, err := decodeSingleCount(raw)
	if err != nil || count != 2 {
		t.Fatalf("restart lost/doubled counts: count=%d err=%v", count, err)
	}
}
