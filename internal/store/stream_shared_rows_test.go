package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestStreamSharedRowsResolveOnlyVerifiedScopedBody(t *testing.T) {
	event := normalized.Event{SchemaVersion: "v1", EventID: "position-one", Source: "handshake-sidecar", SourceEventType: "handshake", Type: "device", Timestamp: "2026-10-25T10:00:00Z",
		Observer: map[string]any{"sensor_id": "sensor-a", "capture_scope_id": "scope-a", "collector_instance_id": "collector-a"},
		Subject:  map[string]any{"campus_id": "campus-a", "ip": "10.2.3.4"},
		Payload:  map[string]any{"access_domain": "bond0", "handshake_schema": "handshake-samples/v1", "feature_samples": []any{}}}
	body, _ := json.Marshal(event)
	sum := sha256.Sum256(body)
	ref := StreamBodyRef{Class: "evidence", Month: "202610", Scope: "scope-a", Key: "fresh:position-one", SHA256: hex.EncodeToString(sum[:])}
	refJSON, _ := json.Marshal(ref)
	index := map[string]any{"observed_at": "2026-10-25T10:00:00Z", "indexed_at": "2026-10-25T10:00:01Z", "event_key": ref.Key, "source": event.Source, "protocol": event.SourceEventType,
		"sensor_id": "sensor-a", "campus_id": "campus-a", "access_domain": "bond0", "subject_ip": "10.2.3.4", "subject_mac": "", "collector_instance_id": "collector-a", "scope_id": ref.Scope,
		"content_sha256": ref.SHA256, "archive_month": 202610, "retention_class": ref.Class, "body_ref": string(refJSON)}
	var corrupt bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, _ := io.ReadAll(r.Body)
		if strings.Contains(string(query), "FROM stream_event_search") {
			_ = json.NewEncoder(w).Encode(index)
		} else if strings.Contains(string(query), "FROM stream_event_body_evidence") {
			content := string(body)
			if corrupt {
				content += " "
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"scope_id": ref.Scope, "event_key": ref.Key, "content_sha256": ref.SHA256, "body": content})
		} else {
			t.Errorf("unexpected ClickHouse query: %s", query)
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	s := &DBStore{ch: ch}
	scope := SharedObservationScope{SensorID: "sensor-a", CampusID: "campus-a", AccessDomain: "bond0", IP: "10.2.3.4"}
	from := time.Date(2026, 10, 25, 9, 59, 0, 0, time.UTC)
	rows, associations, err := s.readStreamSharedRows(context.Background(), scope, "scope-a", "handshake-sidecar", "fresh", scope.IP, from, from.Add(2*time.Minute))
	if err != nil || len(rows) != 1 || len(associations) != 0 || rows[0].EventID != event.EventID || rows[0].PayloadVersions != 1 {
		t.Fatalf("scoped shared evidence lost: %+v %+v %v", rows, associations, err)
	}
	corrupt = true
	if _, _, err := s.readStreamSharedRows(context.Background(), scope, "scope-a", "handshake-sidecar", "fresh", scope.IP, from, from.Add(2*time.Minute)); err == nil {
		t.Fatal("changed authoritative bytes passed shared reader")
	}
}
