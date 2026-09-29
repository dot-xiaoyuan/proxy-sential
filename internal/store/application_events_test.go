package store

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/appdomain"
	"proxy-sentinel/internal/normalized"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestApplicationSourceParity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	e := normalized.Event{SchemaVersion: "v1", EventID: "app-1", Timestamp: now.Add(-time.Hour).Format(time.RFC3339Nano), Type: "tls", Observer: map[string]any{"sensor_id": "s"}, Subject: map[string]any{"ip": "10.0.0.1", "campus_id": "campus"}, Payload: map[string]any{"sni": "weixin.qq.com"}, Flow: map[string]any{"connection_id": "conn1", "bytes_toserver": float64(30)}}
	dir := t.TempDir()
	run := filepath.Join(dir, "runs", "run1")
	if err := os.MkdirAll(run, 0700); err != nil {
		t.Fatal(err)
	}
	summary, _ := json.Marshal(map[string]any{"started_at": e.Timestamp, "finished_at": e.Timestamp})
	if err := os.WriteFile(filepath.Join(run, "run-summary.json"), summary, 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(e)
	if err := os.WriteFile(filepath.Join(run, "normalized.jsonl"), append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if q == "" {
			b, _ := io.ReadAll(r.Body)
			q = string(b)
		}
		if !strings.Contains(q, "ORDER BY timestamp,sensor_id,event_id") || strings.Contains(q, "OFFSET") {
			t.Error("unstable scan", q)
		}
		observer, _ := json.Marshal(e.Observer)
		payload, _ := json.Marshal(e.Payload)
		flow, _ := json.Marshal(e.Flow)
		_ = json.NewEncoder(w).Encode(map[string]any{"timestamp": e.Timestamp, "event_id": e.EventID, "type": e.Type, "sensor_id": "s", "campus_id": "campus", "subject_ip": "10.0.0.1", "observer_json": string(observer), "payload_json": string(payload), "flow_json": string(flow)})
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	f := NewFileStore(FileOptions{ShadowDir: dir, SensorID: "s"})
	query := appdomain.Scan{From: now.Add(-24 * time.Hour), To: now, Limit: 10}
	a, err := f.ScanApplicationEvents(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ch.ScanApplicationEvents(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("%d %d", len(a), len(b))
	}
	if !reflect.DeepEqual(appdomain.Observe(a[0], nil), appdomain.Observe(b[0], nil)) {
		t.Fatalf("source mismatch: %+v %+v", a, b)
	}
	query.After = appdomain.EventCursor(a[0])
	a, err = f.ScanApplicationEvents(context.Background(), query)
	if err != nil || len(a) != 0 {
		t.Fatal("cursor did not advance", err)
	}
}
