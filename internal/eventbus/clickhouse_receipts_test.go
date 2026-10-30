package eventbus

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

func TestClickHouseReceiptSinkWritesJSONEachRow(t *testing.T) {
	var gotQuery string
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink, err := NewClickHouseReceiptSink(server.URL + "/?database=proxy_sentinel")
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{
		EventID:     "evt-1",
		DeviceKey:   "device-1",
		ObservedAt:  time.Date(2026, 10, 30, 5, 0, 0, 123456000, time.UTC),
		AcceptedAt:  time.Date(2026, 10, 30, 5, 0, 1, 0, time.UTC),
		SegmentID:   "seg-1",
		ContentHash: "sha256:abc",
		SensorID:    "sensor-1",
		ScopeID:     "scope-1",
		Source:      "passive-discovery",
		SourcePath:  "packet://bond0",
		Partition:   2,
		Offset:      42,
		Envelope:    []byte(`{"schema_version":1}`),
		ConsumedAt:  time.Date(2026, 10, 30, 5, 0, 2, 0, time.UTC),
	}
	if err := sink.WriteReceipts(context.Background(), []Receipt{receipt}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, discoveryReceiptsTable) || !strings.Contains(gotQuery, "FORMAT JSONEachRow") {
		t.Fatalf("query missing table/format: %q", gotQuery)
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(gotBody)), &row); err != nil {
		t.Fatalf("body is not one JSON row: %v body=%q", err, gotBody)
	}
	if row["event_id"] != "evt-1" || row["device_key"] != "device-1" {
		t.Fatalf("unexpected row: %#v", row)
	}
	if row["observed_at"] != "2026-10-30 05:00:00.123456" {
		t.Fatalf("unexpected observed_at: %#v", row["observed_at"])
	}
}

func TestClickHouseReceiptSinkRejectsIncompleteReceipt(t *testing.T) {
	sink, err := NewClickHouseReceiptSink("http://127.0.0.1:1/")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteReceipts(context.Background(), []Receipt{{EventID: "evt"}}); err == nil {
		t.Fatal("expected incomplete receipt error")
	}
}

func TestClickHouseReceiptSinkReportsHTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad insert", http.StatusInternalServerError)
	}))
	defer server.Close()
	sink, err := NewClickHouseReceiptSink(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	err = sink.WriteReceipts(context.Background(), []Receipt{{
		EventID: "evt", DeviceKey: "dev", ObservedAt: time.Now().UTC(),
	}})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected HTTP failure, got %v", err)
	}
}
