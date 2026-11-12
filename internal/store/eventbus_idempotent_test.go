package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func eventBusTestRow(t *testing.T, event normalized.Event) string {
	t.Helper()
	at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	row := eventBusNormalizedRow{
		EventID: event.EventID, Schema: event.SchemaVersion, Source: event.Source,
		SourceType: event.SourceEventType, Type: event.Type,
		Timestamp: at.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z"),
		Observer:  jsonString(event.Observer), Subject: jsonString(event.Subject),
		Payload: jsonString(event.Payload), Flow: jsonString(event.Flow), RawRef: jsonString(event.RawRef),
		Confidence: event.Confidence,
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestEventBusNormalizedWriterChecksImmediateEventIDDespiteBlockMode(t *testing.T) {
	var mu sync.Mutex
	inserted := 0
	insertSynchronous := true
	queries := []string{}
	event := probeEvent("bus-retry")
	storedRow := eventBusTestRow(t, event)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sql := string(body)
		mu.Lock()
		defer mu.Unlock()
		queries = append(queries, sql)
		if strings.HasPrefix(sql, "INSERT INTO normalized_events") {
			inserted++
			insertSynchronous = insertSynchronous && r.URL.Query().Get("async_insert") == "0"
			return
		}
		if inserted > 0 {
			fmt.Fprintln(w, storedRow)
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROXY_SENTINEL_EVENT_ID_IDEMPOTENCY", "clickhouse")
	for range 2 {
		if err := ch.WriteEventBusNormalizedEvents(context.Background(), []normalized.Event{event}); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if inserted != 1 {
		t.Fatalf("retry inserted %d copies", inserted)
	}
	if !insertSynchronous {
		t.Fatal("event bus insert did not force synchronous visibility")
	}
	if len(queries) != 3 || !strings.Contains(queries[0], "FROM normalized_events") || !strings.Contains(queries[2], "FROM normalized_events") ||
		strings.Contains(queries[0], "normalized_event_ids_v2") || strings.Contains(queries[0], "normalized_event_ids_v1") {
		t.Fatalf("did not query authoritative current body before both attempts: %v", queries)
	}
}

func TestEventBusNormalizedWriterRejectsRetainedBodyConflict(t *testing.T) {
	event := probeEvent("bus-conflict")
	stored := event
	stored.Payload = map[string]any{"device_type": "router"}
	// A reused ID can cross an observation-day boundary; the lookup must not
	// restrict itself to the new event's day.
	stored.Timestamp = time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339Nano)
	row := eventBusTestRow(t, stored)
	inserted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sql := string(body)
		if strings.HasPrefix(sql, "INSERT INTO normalized_events") {
			inserted = true
			return
		}
		bounds := regexp.MustCompile(`parseDateTime64BestEffort\('([^']+)',6\)`).FindAllStringSubmatch(sql, -1)
		if len(bounds) != 2 {
			t.Errorf("ID lookup did not bind a retained time range: %s", sql)
			return
		}
		lower, err := time.Parse(time.RFC3339Nano, bounds[0][1])
		if err != nil {
			t.Error(err)
			return
		}
		upper, err := time.Parse(time.RFC3339Nano, bounds[1][1])
		if err != nil {
			t.Error(err)
			return
		}
		at, _ := time.Parse(time.RFC3339Nano, stored.Timestamp)
		if !at.Before(lower) && at.Before(upper) {
			fmt.Fprintln(w, row)
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteEventBusNormalizedEvents(context.Background(), []normalized.Event{event}); err == nil || !strings.Contains(err.Error(), "conflicts with retained normalized body") {
		t.Fatalf("same ID with different retained content must fail: %v", err)
	}
	if inserted {
		t.Fatal("conflict was inserted")
	}
}

func TestEventBusNormalizedWriterRejectsUnverifiableRetainedBody(t *testing.T) {
	event := probeEvent("bus-missing-fields")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"event_id":"bus-missing-fields"}`)
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteEventBusNormalizedEvents(context.Background(), []normalized.Event{event}); err == nil || !strings.Contains(err.Error(), "cannot be compared") {
		t.Fatalf("missing authoritative fields must block offset acknowledgement: %v", err)
	}
}

func TestEventBusNormalizedWriterRejectsEventsOutsideProofWindow(t *testing.T) {
	event := probeEvent("bus-too-old")
	event.Timestamp = time.Now().UTC().Add(-8 * 24 * time.Hour).Format(time.RFC3339Nano)
	queried := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queried = true
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteEventBusNormalizedEvents(context.Background(), []normalized.Event{event}); err == nil || !strings.Contains(err.Error(), "outside the retained normalized event ID proof window") {
		t.Fatalf("old event without authoritative ID index must fail: %v", err)
	}
	if queried {
		t.Fatal("old event reached an unprovable hot-table lookup")
	}
}
