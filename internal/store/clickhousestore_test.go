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

	"proxy-sentinel/internal/normalized"
)

func TestClickHouseTimestampConvertsRFC3339InstantToShanghai(t *testing.T) {
	if got := clickHouseTimestamp("2026-09-04T07:30:01.123456Z"); got != "2026-09-04 15:30:01.123456" {
		t.Fatalf("unexpected UTC conversion: %s", got)
	}
	if got := clickHouseTimestamp("2026-09-04T15:30:01.123456+08:00"); got != "2026-09-04 15:30:01.123456" {
		t.Fatalf("unexpected Shanghai conversion: %s", got)
	}
}

func TestClickHouseRequestTimeoutDefaultsAndOverrides(t *testing.T) {
	defaultStore, err := NewClickHouseStore(ClickHouseOptions{DSN: "http://127.0.0.1:8123"})
	if err != nil {
		t.Fatal(err)
	}
	if defaultStore.client.Timeout != 2*time.Minute {
		t.Fatalf("unexpected default timeout: %s", defaultStore.client.Timeout)
	}

	explicitStore, err := NewClickHouseStore(ClickHouseOptions{DSN: "http://127.0.0.1:8123", RequestTimeout: 7 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if explicitStore.client.Timeout != 7*time.Minute {
		t.Fatalf("unexpected explicit timeout: %s", explicitStore.client.Timeout)
	}
}

func TestWriteNormalizedEventsSkipsIDsAlreadyInClickHouse(t *testing.T) {
	var inserted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		text := string(body)
		if strings.HasPrefix(text, "SELECT event_id") {
			_, _ = io.WriteString(w, `{"event_id":"event-existing"}`+"\n")
			return
		}
		if strings.HasPrefix(text, "INSERT INTO normalized_events") {
			for _, line := range strings.Split(text, "\n")[1:] {
				if strings.TrimSpace(line) == "" {
					continue
				}
				var row map[string]any
				if err := json.Unmarshal([]byte(line), &row); err != nil {
					t.Fatal(err)
				}
				inserted = append(inserted, row["event_id"].(string))
			}
			return
		}
		t.Fatalf("unexpected query: %s", text)
	}))
	defer server.Close()
	store, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	events := []normalized.Event{{EventID: "event-existing", Timestamp: time.Now().Format(time.RFC3339Nano)}, {EventID: "event-new", Timestamp: time.Now().Format(time.RFC3339Nano)}}
	if err := store.WriteNormalizedEvents(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if len(inserted) != 1 || inserted[0] != "event-new" {
		t.Fatalf("unexpected inserted ids: %#v", inserted)
	}
}

func TestWriteNormalizedEventsUsesNarrowIndexAfterCutover(t *testing.T) {
	cutover := time.Date(2026, 9, 28, 4, 0, 0, 0, time.UTC)
	queries := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		text := string(body)
		queries = append(queries, text)
		if strings.HasPrefix(text, "SELECT event_id FROM normalized_event_ids_v1") {
			_, _ = io.WriteString(w, `{"event_id":"event-existing"}`+"\n")
		}
	}))
	defer server.Close()
	store, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL, EventIDIndexCutover: cutover})
	if err != nil {
		t.Fatal(err)
	}
	events := []normalized.Event{
		{EventID: "event-existing", Timestamp: cutover.Add(time.Minute).Format(time.RFC3339Nano)},
		{EventID: "event-new", Timestamp: cutover.Add(time.Minute).Format(time.RFC3339Nano)},
	}
	if err := store.WriteNormalizedEvents(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 || !strings.Contains(queries[0], "normalized_event_ids_v1") || strings.Contains(queries[0], "normalized_events WHERE") {
		t.Fatalf("unexpected post-cutover queries: %#v", queries)
	}
	if !strings.Contains(queries[1], `"event_id":"event-new"`) || strings.Contains(queries[1], `"event_id":"event-existing"`) {
		t.Fatalf("unexpected insert body: %s", queries[1])
	}
}

func TestWriteNormalizedEventsBoundsLegacyLookupByTimestamp(t *testing.T) {
	cutover := time.Date(2026, 9, 28, 4, 0, 0, 0, time.UTC)
	var lookup string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		text := string(body)
		if strings.HasPrefix(text, "SELECT event_id FROM normalized_events") {
			lookup = text
		}
	}))
	defer server.Close()
	store, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL, EventIDIndexCutover: cutover})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteNormalizedEvents(context.Background(), []normalized.Event{{EventID: "legacy-event", Timestamp: cutover.Add(-time.Minute).Format(time.RFC3339Nano)}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lookup, "timestamp>=") || !strings.Contains(lookup, "timestamp<=") {
		t.Fatalf("legacy lookup is not time bounded: %s", lookup)
	}
}

func TestWriteNormalizedEventsUsesFineHashIndexAfterV2Cutover(t *testing.T) {
	v1Cutover := time.Date(2026, 9, 28, 4, 0, 0, 0, time.UTC)
	v2Cutover := v1Cutover.Add(time.Hour)
	queries := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		text := string(body)
		queries = append(queries, text)
		if strings.HasPrefix(text, "SELECT event_id FROM normalized_event_ids_v2") {
			_, _ = io.WriteString(w, `{"event_id":"event-v2-existing"}`+"\n")
		}
	}))
	defer server.Close()
	store, err := NewClickHouseStore(ClickHouseOptions{
		DSN: server.URL, EventIDIndexCutover: v1Cutover, EventIDIndexV2Cutover: v2Cutover,
	})
	if err != nil {
		t.Fatal(err)
	}
	events := []normalized.Event{
		{EventID: "event-v2-existing", Timestamp: v2Cutover.Add(time.Minute).Format(time.RFC3339Nano)},
		{EventID: "event-v2-new", Timestamp: v2Cutover.Add(time.Minute).Format(time.RFC3339Nano)},
	}
	if err = store.WriteNormalizedEvents(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 || !strings.Contains(queries[0], "normalized_event_ids_v2") || !strings.Contains(queries[0], "(event_id_hash,event_id) IN") || !strings.Contains(queries[0], "sipHash64") {
		t.Fatalf("unexpected v2 lookup: %#v", queries)
	}
	if strings.Contains(queries[1], `"event_id":"event-v2-existing"`) || !strings.Contains(queries[1], `"event_id":"event-v2-new"`) {
		t.Fatalf("unexpected v2 insert body: %s", queries[1])
	}
}

func TestEventIDV2CutoverCannotPrecedeV1(t *testing.T) {
	_, err := NewClickHouseStore(ClickHouseOptions{
		DSN:                   "http://127.0.0.1:8123",
		EventIDIndexCutover:   time.Date(2026, 9, 28, 5, 0, 0, 0, time.UTC),
		EventIDIndexV2Cutover: time.Date(2026, 9, 28, 4, 0, 0, 0, time.UTC),
	})
	if err == nil || !strings.Contains(err.Error(), "must not precede") {
		t.Fatalf("expected ordered cutover validation, got %v", err)
	}
}
