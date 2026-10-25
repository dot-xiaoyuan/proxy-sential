package store

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/streamlog"
)

func TestStreamSharedIndexRejectsChangedBodyLocator(t *testing.T) {
	ref := StreamBodyRef{Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:event-a", SHA256: strings.Repeat("a", 64)}
	encoded, _ := json.Marshal(ref)
	row := map[string]any{"observed_at": "2026-10-25T10:00:01Z", "indexed_at": "2026-10-25T10:00:02Z", "event_key": ref.Key, "source": "handshake-sidecar", "protocol": "handshake", "sensor_id": "sensor-a", "campus_id": "campus-a", "access_domain": "bond0", "subject_ip": "10.2.3.4", "subject_mac": "", "collector_instance_id": "collector-a", "scope_id": ref.Scope, "content_sha256": ref.SHA256, "archive_month": 202610, "retention_class": ref.Class, "body_ref": string(encoded)}
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		query = string(data)
		if strings.Contains(query, "content_sha256>") {
			return
		}
		_ = json.NewEncoder(w).Encode(row)
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	scope := SharedObservationScope{SensorID: "sensor-a", CampusID: "campus-a", AccessDomain: "bond0", IP: "10.2.3.4"}
	from := time.Date(2026, 10, 25, 9, 59, 0, 0, time.UTC)
	to := from.Add(2 * time.Minute)
	got, err := ch.ListStreamSharedSignalRefs(context.Background(), scope, "scope-a", "handshake-sidecar", "fresh", scope.IP, from, to, time.Time{}, "", "", 100)
	if err != nil || len(got) != 1 || got[0].Body != ref || !strings.Contains(query, "stream_event_search PREWHERE") || !strings.Contains(query, "subject_ip IN ('','10.2.3.4')") {
		t.Fatalf("scoped body lookup failed: %+v %v %s", got, err, query)
	}
	row["content_sha256"] = strings.Repeat("b", 64)
	if _, err := ch.ListStreamSharedSignalRefs(context.Background(), scope, "scope-a", "handshake-sidecar", "fresh", scope.IP, from, to, time.Time{}, "", "", 100); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("changed locator passed: %v", err)
	}
	row["content_sha256"] = ref.SHA256
	if _, err := ch.ListStreamSharedSignalRefs(context.Background(), scope, "scope-a", "handshake-sidecar", "fresh", scope.IP, from, to, time.Date(2026, 10, 25, 10, 0, 1, 0, time.UTC), ref.Key, ref.SHA256, 100); err != nil {
		t.Fatalf("hash cursor rejected: %v", err)
	}
	if !strings.Contains(query, "content_sha256>'"+ref.SHA256+"'") || !strings.Contains(query, "ORDER BY observed_at,event_key,content_sha256") {
		t.Fatalf("same-key versions would be hidden at a page boundary: %s", query)
	}
}
