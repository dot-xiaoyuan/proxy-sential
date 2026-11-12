package store

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEventListCursorFreezesWindowAndRejectsChangedFilters(t *testing.T) {
	now := time.Date(2026, 11, 12, 3, 0, 0, 0, time.UTC)
	query := Query{SensorID: "sensor-a", Window: "1h", Limit: 20}
	effective, cursor, err := prepareEventListQuery(query, now)
	if err != nil {
		t.Fatal(err)
	}
	if effective.From != now.Add(-time.Hour).Format(time.RFC3339Nano) || effective.To != now.Format(time.RFC3339Nano) || effective.Window != "" {
		t.Fatalf("window was not frozen: %#v", effective)
	}
	query.EventCursor = *encodeEventListCursor(cursor, eventKey{Timestamp: now.Add(-time.Minute).Format(time.RFC3339Nano), EventID: "event-a", SensorID: "sensor-a"})
	effective, _, err = prepareEventListQuery(query, now.Add(time.Hour))
	if err != nil || effective.To != now.Format(time.RFC3339Nano) {
		t.Fatalf("cursor did not preserve the first page bound: query=%#v err=%v", effective, err)
	}
	query.SensorID = "sensor-b"
	if _, _, err = prepareEventListQuery(query, now.Add(time.Hour)); err == nil {
		t.Fatal("cursor must reject changed filters")
	}
}

func TestNormalizeEventKeyTimestampAcceptsClickHouseJSON(t *testing.T) {
	got, err := normalizeEventKeyTimestamp("2026-11-12 11:04:05.123456")
	if err != nil || got != "2026-11-12T03:04:05.123456Z" {
		t.Fatalf("ClickHouse DateTime64 timestamp was not cursor-safe: %q %v", got, err)
	}
	if _, err := normalizeEventKeyTimestamp("bad"); err == nil {
		t.Fatal("invalid event timestamp accepted")
	}
}

func TestClickHouseEventListUsesPageKeysWithoutCountOrOffset(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	keys := []eventKey{
		{Timestamp: now.Add(-time.Second).Format(time.RFC3339Nano), EventID: "event-3", SensorID: "sensor-a"},
		{Timestamp: now.Add(-2 * time.Second).Format(time.RFC3339Nano), EventID: "event-2", SensorID: "sensor-a"},
		{Timestamp: now.Add(-3 * time.Second).Format(time.RFC3339Nano), EventID: "event-1", SensorID: "sensor-a"},
	}
	queries := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sql := string(body)
		queries = append(queries, sql)
		switch {
		case strings.HasPrefix(sql, "SELECT timestamp,event_id,sensor_id"):
			for _, key := range keys {
				fmt.Fprintf(w, "{\"timestamp\":%q,\"event_id\":%q,\"sensor_id\":%q}\n", key.Timestamp, key.EventID, key.SensorID)
			}
		case strings.HasPrefix(sql, "SELECT timestamp,event_id,schema_version"):
			for _, key := range keys[:2] {
				fmt.Fprintf(w, "{\"timestamp\":%q,\"event_id\":%q,\"schema_version\":\"v1\",\"source\":\"test\",\"type\":\"dns\",\"observer_json\":\"{}\",\"payload_json\":\"{}\",\"flow_json\":\"{}\",\"raw_ref_json\":\"{}\"}\n", key.Timestamp, key.EventID)
			}
		case strings.Contains(sql, "count()"):
			fmt.Fprintln(w, `{"count":3}`)
		default:
			t.Errorf("unexpected SQL: %s", sql)
		}
	}))
	defer server.Close()
	store, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.ListEvents(context.Background(), Query{SensorID: "sensor-a", Window: "1h", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || !page.Page.HasMore || page.Page.NextCursor == nil {
		t.Fatalf("unexpected bounded page: %#v", page)
	}
	if len(queries) != 2 {
		t.Fatalf("list made %d queries, want key and body queries", len(queries))
	}
	for _, sql := range queries {
		if strings.Contains(sql, "count()") || strings.Contains(sql, " OFFSET ") {
			t.Fatalf("list performed full count or offset: %s", sql)
		}
	}
	count, err := store.CountEvents(context.Background(), Query{SensorID: "sensor-a", Window: "1h"})
	if err != nil || count != 3 {
		t.Fatalf("explicit count=%d err=%v", count, err)
	}
	if len(queries) != 3 || !strings.Contains(queries[2], "count()") {
		t.Fatalf("count was not isolated: %#v", queries)
	}
}

func TestClickHouseEventListResetsKeysWhenExpandingSparseWindow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	keys := []eventKey{
		{Timestamp: now.Add(-6 * time.Minute).Format(time.RFC3339Nano), EventID: "event-3", SensorID: "sensor-a"},
		{Timestamp: now.Add(-7 * time.Minute).Format(time.RFC3339Nano), EventID: "event-2", SensorID: "sensor-a"},
		{Timestamp: now.Add(-8 * time.Minute).Format(time.RFC3339Nano), EventID: "event-1", SensorID: "sensor-a"},
	}
	keyQueries := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sql := string(body)
		switch {
		case strings.HasPrefix(sql, "SELECT timestamp,event_id,sensor_id"):
			keyQueries++
			if keyQueries == 1 {
				fmt.Fprintf(w, "{\"timestamp\":%q,\"event_id\":%q,\"sensor_id\":%q}\n", keys[2].Timestamp, keys[2].EventID, keys[2].SensorID)
				return
			}
			for _, key := range keys {
				fmt.Fprintf(w, "{\"timestamp\":%q,\"event_id\":%q,\"sensor_id\":%q}\n", key.Timestamp, key.EventID, key.SensorID)
			}
		case strings.HasPrefix(sql, "SELECT timestamp,event_id,schema_version"):
			if strings.Contains(sql, "'event-1'") {
				t.Error("stale key from the narrower window entered the body page")
			}
			for _, key := range keys[:2] {
				fmt.Fprintf(w, "{\"timestamp\":%q,\"event_id\":%q,\"schema_version\":\"v1\",\"source\":\"test\",\"type\":\"dns\",\"observer_json\":\"{}\",\"payload_json\":\"{}\",\"flow_json\":\"{}\",\"raw_ref_json\":\"{}\"}\n", key.Timestamp, key.EventID)
			}
		default:
			t.Errorf("unexpected SQL: %s", sql)
		}
	}))
	defer server.Close()
	store, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.ListEvents(context.Background(), Query{SensorID: "sensor-a", Window: "1h", Limit: 2})
	if err != nil || keyQueries != 2 || len(page.Items) != 2 || page.Page.NextCursor == nil {
		t.Fatalf("sparse key expansion failed: page=%+v queries=%d err=%v", page, keyQueries, err)
	}
	query := Query{SensorID: "sensor-a", Window: "1h", Limit: 2, EventCursor: *page.Page.NextCursor}
	_, cursor, err := prepareEventListQuery(query, now)
	if err != nil || cursor.After.EventID != "event-2" {
		t.Fatalf("cursor retained stale key: %+v %v", cursor, err)
	}
}
