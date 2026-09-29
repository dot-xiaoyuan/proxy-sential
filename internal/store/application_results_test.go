package store

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"proxy-sentinel/internal/appdomain"
)

func TestApplicationExistingLookupChunksLargeBatches(t *testing.T) {
	var mu sync.Mutex
	querySizes := []int{}
	queryLimits := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		querySizes = append(querySizes, len(body))
		queryLimits = append(queryLimits, r.URL.Query().Get("max_query_size"))
		mu.Unlock()
	}))
	defer server.Close()
	clickhouse, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	database := &applicationDB{store: &DBStore{ch: clickhouse}}
	rows := make([]appdomain.Observation, 5000)
	for index := range rows {
		rows[index] = appdomain.Observation{
			SensorID: "sensor-campus",
			CampusID: "main-campus",
			EventID:  fmt.Sprintf("event-%08d-with-a-production-sized-identifier", index),
			Timestamp: time.Date(2026, time.September, 28, 8, 0, index%60, index, time.UTC).
				Format(time.RFC3339Nano),
		}
	}
	if _, err = database.existing(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	if len(querySizes) != 1 {
		t.Fatalf("expected one bounded lookup, got %d", len(querySizes))
	}
	for index, size := range querySizes {
		if size >= 1024*1024 {
			t.Fatalf("lookup exceeded bounded ClickHouse max_query_size: %d", size)
		}
		if queryLimits[index] != "1048576" {
			t.Fatalf("lookup did not declare its parser bound: %q", queryLimits[index])
		}
	}
}
