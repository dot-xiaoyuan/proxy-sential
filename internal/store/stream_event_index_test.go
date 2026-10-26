package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStreamEventIndexNeedsBoundedScopeAndTime(t *testing.T) {
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 10, 25, 20, 0, 0, 0, time.UTC)
	for _, query := range []StreamEventIndexQuery{
		{From: from, To: from.Add(time.Minute)},
		{ScopeID: "scope-a", From: from, To: from.Add(16 * time.Minute)},
		{ScopeID: "scope-a", From: from, To: from},
		{ScopeID: "scope-a", From: from, To: from.Add(time.Minute), Limit: 101},
	} {
		if _, err := ch.ListStreamEventIndex(context.Background(), query); err == nil {
			t.Fatalf("accepted unbounded query: %+v", query)
		}
	}
}

func TestIPTrafficCursorCannotCrossIPOrGeneration(t *testing.T) {
	ch, _ := NewClickHouseStore(ClickHouseOptions{DSN: "http://127.0.0.1:1"})
	from := time.Date(2026, 10, 26, 6, 40, 0, 0, time.UTC)
	q := StreamEventIndexQuery{ScopeID: "scope-a", SensorID: "sensor-a", SubjectIP: "10.157.2.191", Epoch: "generation-a", ObservationOnly: true, From: from, To: from.Add(15 * time.Minute), Limit: 20}
	cursor, _ := json.Marshal(streamIndexCursor{Filter: streamIndexFilter(q), Observed: from.Add(time.Minute).Format(time.RFC3339Nano), Key: "generation-a:event-one", Hash: strings.Repeat("a", 64)})
	q.Cursor = base64.RawURLEncoding.EncodeToString(cursor)
	for _, change := range []func(*StreamEventIndexQuery){
		func(q *StreamEventIndexQuery) { q.SubjectIP = "10.157.2.192" }, func(q *StreamEventIndexQuery) { q.Epoch = "generation-b" },
		func(q *StreamEventIndexQuery) { q.SensorID = "sensor-b" }, func(q *StreamEventIndexQuery) { q.From = q.From.Add(time.Second) },
	} {
		changed := q
		change(&changed)
		if _, err := ch.ListStreamEventIndex(context.Background(), changed); !errors.Is(err, ErrInvalidStreamEventIndexQuery) {
			t.Fatalf("cursor crossed query boundary: %+v %v", changed, err)
		}
	}
}

func TestStreamEventIndexPagesAndVerifiesLocator(t *testing.T) {
	ref := StreamBodyRef{Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:event-a", SHA256: strings.Repeat("a", 64)}
	encoded, _ := json.Marshal(ref)
	row := map[string]any{"observed_at": "2026-10-25T20:00:01Z", "event_key": ref.Key, "content_sha256": ref.SHA256,
		"scope_id": ref.Scope, "protocol": "ssdp", "event_type": "device", "source": "device-signals", "sensor_id": "sensor-a",
		"subject_ip": "192.0.2.1", "archive_month": 202610, "retention_class": ref.Class, "body_ref": string(encoded)}
	var sql []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		sql = append(sql, string(data))
		if len(sql) != 2 {
			_ = json.NewEncoder(w).Encode(row)
			_ = json.NewEncoder(w).Encode(map[string]any{"observed_at": "2026-10-25T20:00:00Z", "event_key": "fresh:event-b", "content_sha256": strings.Repeat("b", 64), "scope_id": ref.Scope, "protocol": "ssdp", "event_type": "device", "source": "device-signals", "sensor_id": "sensor-a", "subject_ip": "192.0.2.2", "archive_month": 202610, "retention_class": "evidence", "body_ref": `{"class":"evidence","month":"202610","scope":"scope-a","key":"fresh:event-b","sha256":"` + strings.Repeat("b", 64) + `"}`})
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 10, 25, 19, 59, 0, 0, time.UTC)
	query := StreamEventIndexQuery{ScopeID: ref.Scope, Protocol: "ssdp", From: from, To: from.Add(2 * time.Minute), Limit: 1}
	page, err := ch.ListStreamEventIndex(context.Background(), query)
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" || page.Items[0].Body != ref {
		t.Fatalf("first page: %+v %v", page, err)
	}
	if !strings.Contains(sql[0], "FROM stream_event_search PREWHERE") || !strings.Contains(sql[0], "scope_id='scope-a'") || !strings.Contains(sql[0], "SELECT DISTINCT") || strings.Contains(sql[0], "stream_event_body") {
		t.Fatalf("unbounded or wide lookup: %s", sql[0])
	}
	query.Cursor = page.NextCursor
	if _, err := ch.ListStreamEventIndex(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	if len(sql) != 2 || !strings.Contains(sql[1], "event_key<'fresh:event-a'") {
		t.Fatalf("cursor not applied: %v", sql)
	}
	query.Protocol = "dhcp"
	if _, err := ch.ListStreamEventIndex(context.Background(), query); err == nil {
		t.Fatal("cursor used with another filter")
	}
	row["content_sha256"] = strings.Repeat("c", 64)
	query.Cursor, query.Protocol = "", "ssdp"
	if _, err := ch.ListStreamEventIndex(context.Background(), query); err == nil {
		t.Fatal("changed body hash accepted")
	}
}
