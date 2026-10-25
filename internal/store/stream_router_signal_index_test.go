package store

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRouterStreamIndexUsesInsertionCursorAndValidatesBodyRef(t *testing.T) {
	after := time.Date(2026, 10, 25, 8, 30, 0, 0, time.UTC)
	ref := StreamBodyRef{Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:event-2", SHA256: strings.Repeat("a", 64)}
	encoded, _ := json.Marshal(ref)
	row := map[string]any{"indexed_at": "2026-10-25T08:30:01.000000Z", "event_key": ref.Key, "scope_id": ref.Scope,
		"content_sha256": ref.SHA256, "archive_month": 202610, "retention_class": ref.Class,
		"observed_at": "2026-10-25T07:00:00.000000Z", "protocol": "ssdp", "body_ref": string(encoded)}
	query := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query = string(body)
		_ = json.NewEncoder(w).Encode(row)
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	items, err := ch.ListStreamRouterSignalRefs(context.Background(), "sensor-a", after, "fresh:event-1", 50)
	if err != nil || len(items) != 1 || items[0].Body != ref || !items[0].ObservedAt.Before(items[0].IndexedAt) {
		t.Fatalf("index item mismatch: %+v %v", items, err)
	}
	if !strings.Contains(query, "sensor_id='sensor-a'") || !strings.Contains(query, "indexed_at>") || !strings.Contains(query, "ORDER BY indexed_at,event_key LIMIT 50") || strings.Contains(query, "stream_event_body") {
		t.Fatalf("router index query is unbounded: %s", query)
	}
	items, err = ch.ListStreamRouterSignalRefs(context.Background(), "sensor-a", after, "", 50)
	if err != nil || len(items) != 1 || !strings.Contains(query, "event_key>''") {
		t.Fatalf("fresh cutoff without a prior event key could not start: items=%v err=%v query=%s", items, err, query)
	}
	row["content_sha256"] = strings.Repeat("b", 64)
	if _, err := ch.ListStreamRouterSignalRefs(context.Background(), "sensor-a", after, "fresh:event-1", 50); err == nil {
		t.Fatal("index reference conflict was accepted")
	}
}
