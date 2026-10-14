package store

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func probeEvent(id string) normalized.Event {
	return normalized.Event{
		SchemaVersion: "v1", EventID: id, Source: "device-signals", SourceEventType: "ttl", Type: "device",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Observer:  map[string]any{"sensor_id": "sensor-a", "interface": "bond0"},
		Subject:   map[string]any{"ip": "192.0.2.10"},
	}
}

// 现场实测逐 id 存在性扫描是 ingest 的吞吐上限，因此提供显式开关把它交给
// ClickHouse 的插入级去重；默认行为必须保持不变。
func TestEventIDIdempotencyModeSelectsTheScan(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(data))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	scanned := func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, body := range bodies {
			if strings.Contains(body, "FROM normalized_events WHERE event_id IN") {
				return true
			}
		}
		return false
	}
	inserted := func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, body := range bodies {
			if strings.Contains(body, "INSERT INTO normalized_events") {
				return true
			}
		}
		return false
	}

	t.Setenv("PROXY_SENTINEL_EVENT_ID_IDEMPOTENCY", "")
	if err := ch.WriteNormalizedEvents(context.Background(), []normalized.Event{probeEvent("probe-scan")}); err != nil {
		t.Fatal(err)
	}
	if !scanned() {
		t.Fatal("default mode must still check existing event ids before inserting")
	}

	mu.Lock()
	bodies = nil
	mu.Unlock()
	t.Setenv("PROXY_SENTINEL_EVENT_ID_IDEMPOTENCY", "clickhouse")
	if err := ch.WriteNormalizedEvents(context.Background(), []normalized.Event{probeEvent("probe-dedup")}); err != nil {
		t.Fatal(err)
	}
	if scanned() {
		t.Fatal("clickhouse dedup mode must not scan normalized_events for every event id")
	}
	if !inserted() {
		t.Fatal("clickhouse dedup mode must still insert the batch")
	}
}
