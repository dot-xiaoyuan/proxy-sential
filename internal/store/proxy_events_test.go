package store

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/proxyprotocol"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProxySourceSignatureParity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	e := normalized.Event{SchemaVersion: "v1", EventID: "app-1", Timestamp: now.Add(-time.Hour).Format(time.RFC3339Nano), Type: "proxy_transaction", Source: "zeek", Observer: map[string]any{"sensor_id": "s", "collector_instance_id": "boot"}, Subject: map[string]any{"ip": "10.0.0.1", "campus_id": "campus"}, Payload: map[string]any{"protocol": "http_connect", "transaction_id": "1", "method": "CONNECT", "status": 200}, Flow: map[string]any{"connection_id": "conn1", "bytes_toserver": float64(30)}}
	producer := proxyprotocol.Producer{SensorID: "s", Source: "zeek", InstanceID: "boot", ParserID: "parser", ParserVersion: "1", CampusID: "campus", AccessDomain: "nas", Key: "01234567890123456789012345678901"}
	proxyprotocol.Sign(&e, producer)
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
		_ = json.NewEncoder(w).Encode(map[string]any{"source": e.Source, "raw_ref_json": "null", "timestamp": e.Timestamp, "event_id": e.EventID, "type": e.Type, "sensor_id": "s", "campus_id": "campus", "subject_ip": "10.0.0.1", "observer_json": string(observer), "payload_json": string(payload), "flow_json": string(flow)})
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	f := NewFileStore(FileOptions{ShadowDir: dir, SensorID: "s"})
	query := proxyprotocol.Scan{From: now.Add(-24 * time.Hour), To: now, Limit: 10}
	a, err := f.ScanProxyEvents(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ch.ScanProxyEvents(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("%d %d", len(a), len(b))
	}
	a[0].RawRef = nil
	b[0].RawRef = nil
	if !proxyprotocol.Evaluate(b[0], proxyprotocol.Config{Producers: []proxyprotocol.Producer{producer}}).Trusted {
		t.Fatal("database lost signed provenance")
	}
	if !reflect.DeepEqual(proxyprotocol.Evaluate(a[0], proxyprotocol.Config{Producers: []proxyprotocol.Producer{producer}}), proxyprotocol.Evaluate(b[0], proxyprotocol.Config{Producers: []proxyprotocol.Producer{producer}})) {
		t.Fatalf("source mismatch: %+v %+v", a, b)
	}
	query.After = proxyprotocol.EventCursor(a[0])
	a, err = f.ScanProxyEvents(context.Background(), query)
	if err != nil || len(a) != 0 {
		t.Fatal("cursor did not advance", err)
	}
}

func TestProxySignatureSurvivesStorageTimestampPrecision(t *testing.T) {
	e := normalized.Event{EventID: "p", Type: "proxy_transaction", Source: "test", Timestamp: "2026-09-11T09:00:00.123456789+08:00", Subject: map[string]any{"ip": "192.0.2.1"}, Observer: map[string]any{"sensor_id": "s", "collector_instance_id": "boot"}, Flow: map[string]any{"connection_id": "c"}, Payload: map[string]any{"protocol": "http_connect", "transaction_id": "1", "method": "CONNECT", "status": 200}}
	p := proxyprotocol.Producer{SensorID: "s", Source: "test", InstanceID: "boot", ParserID: "p", ParserVersion: "1", Key: "01234567890123456789012345678901"}
	proxyprotocol.Sign(&e, p)
	e.Timestamp = "2026-09-11T01:00:00.123456Z"
	if !proxyprotocol.Evaluate(e, proxyprotocol.Config{Producers: []proxyprotocol.Producer{p}}).Trusted {
		t.Fatal("database timezone/precision broke signature")
	}
}
