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

func TestClickHouseFactSinkWritesRows(t *testing.T) {
	var query, body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query().Get("query")
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	sink, err := NewClickHouseFactSink(server.URL + "/?database=proxy_sentinel")
	if err != nil {
		t.Fatal(err)
	}
	fact := Fact{
		DeviceKey: "device-1", FactKey: "fact-1", EventID: "evt-1",
		SensorID: "sensor-1", Protocol: "dns_sd", IP: "10.0.0.1",
		ObservedAt: time.Date(2026, 10, 30, 5, 0, 0, 0, time.UTC),
		ValidUntil: time.Date(2026, 10, 30, 5, 2, 0, 0, time.UTC),
		Version:    1, Observation: []byte(`{"id":"evt-1"}`),
		ConsumedAt: time.Date(2026, 10, 30, 5, 0, 1, 0, time.UTC),
	}
	if err := sink.WriteFacts(context.Background(), []Fact{fact}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query, discoveryFactsShadowTable) || !strings.Contains(query, "FORMAT JSONEachRow") {
		t.Fatalf("unexpected query: %q", query)
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &row); err != nil {
		t.Fatalf("body is not JSONEachRow: %v body=%q", err, body)
	}
	if row["device_key"] != "device-1" || row["fact_key"] != "fact-1" || row["protocol"] != "dns_sd" {
		t.Fatalf("unexpected row: %#v", row)
	}
}

func TestClickHouseDiscoverySinkWritesReceiptAndFact(t *testing.T) {
	queries := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query().Get("query"))
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	sink, err := NewClickHouseDiscoverySink(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	envelope := discoveryFactEnvelope(t)
	raw, err := envelope.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{
		EventID: envelope.EventID, DeviceKey: envelope.PartitionKey,
		ObservedAt: envelope.ObservedAt, SegmentID: "seg-1", Envelope: raw,
		ConsumedAt: time.Now().UTC(),
	}
	if err := sink.WriteReceipts(context.Background(), []Receipt{receipt}); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 {
		t.Fatalf("expected receipt and fact writes, got %d: %v", len(queries), queries)
	}
	if !strings.Contains(queries[0], discoveryReceiptsTable) || !strings.Contains(queries[1], discoveryFactsShadowTable) {
		t.Fatalf("unexpected queries: %v", queries)
	}
}
