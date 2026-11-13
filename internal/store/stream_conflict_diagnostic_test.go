package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestStreamConflictDiagnosticIdentifiesPositionWithoutBody(t *testing.T) {
	ref := StreamBodyRef{
		Class: "evidence", Month: "202611", Scope: "scope-a",
		Key: "packet-birth-20261111T022159Z:stream-1234567890abcdef1234567890abcdef", SHA256: strings.Repeat("a", 64),
	}
	err := streamPositionConflict("router.body_semantics", "protocol_mismatch", time.Date(2026, 11, 12, 4, 10, 16, 123456000, time.UTC), ref, "", strings.Repeat("b", 64))
	if !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("diagnostic lost content conflict identity: %v", err)
	}
	message := err.Error()
	for _, part := range []string{"stage=router.body_semantics", "kind=protocol_mismatch", "source_epoch=packet-birth-20261111T022159Z", "indexed_at=2026-11-12T04:10:16.123456Z", "event_key=" + ref.Key, "ref=evidence/202611/v1", "expected_sha256=" + ref.SHA256, "actual_sha256=" + strings.Repeat("b", 64)} {
		if !strings.Contains(message, part) {
			t.Fatalf("missing %q from diagnostic: %s", part, message)
		}
	}
	if len(message) > 512 {
		t.Fatalf("diagnostic grew beyond a bounded log line: %d bytes", len(message))
	}
}

func TestStreamRouterSemanticConflictNamesIndexWithoutLeakingBody(t *testing.T) {
	indexed := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	observed := indexed.Add(-time.Second)
	event := normalized.Event{
		EventID: "event-a", Timestamp: observed.Format(time.RFC3339Nano), Type: "flow",
		SourceEventType: "dhcp", Observer: map[string]any{"sensor_id": "sensor-a", "capture_scope_id": "scope-a"},
		Payload: map[string]any{"private_note": "canary-secret-personal-body"},
	}
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	ref := StreamBodyRef{Epoch: "packet-birth-20261111T022159Z", Class: "evidence", Month: "202611", Scope: "scope-a", Key: "packet-birth-20261111T022159Z:stream-1234567890abcdef1234567890abcdef", SHA256: hex.EncodeToString(sum[:])}
	encodedRef, _ := json.Marshal(ref)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(string(query), "FROM stream_router_signal_index"):
			_ = json.NewEncoder(w).Encode(map[string]any{"indexed_at": indexed.Format(time.RFC3339Nano), "event_key": ref.Key, "scope_id": ref.Scope, "content_sha256": ref.SHA256, "archive_month": 202611, "retention_class": ref.Class, "observed_at": observed.Format(time.RFC3339Nano), "protocol": "dhcp", "body_ref": string(encodedRef)})
		case strings.Contains(string(query), "SELECT scope_id,event_key,content_sha256,body FROM"):
			_ = json.NewEncoder(w).Encode(map[string]any{"scope_id": ref.Scope, "event_key": ref.Key, "content_sha256": ref.SHA256, "body": string(body)})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"scope_id": ref.Scope, "event_key": ref.Key, "content_sha256": ref.SHA256})
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	store := &DBStore{ch: ch}
	_, _, err = store.streamRouterSignalBatch(context.Background(), "sensor-a", streamRouterCursor{IndexedAt: indexed.Add(-time.Second)})
	if !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("unexpected router result: %v", err)
	}
	message := err.Error()
	for _, part := range []string{"stage=router.body_semantics", "kind=event_type_mismatch", "source_epoch=packet-birth-20261111T022159Z", "event_key=" + ref.Key, "expected_class=device_or_router", "actual_class=flow"} {
		if !strings.Contains(message, part) {
			t.Fatalf("missing %q from diagnostic: %s", part, message)
		}
	}
	if strings.Contains(message, "canary-secret-personal-body") {
		t.Fatalf("event body leaked into diagnostic: %s", message)
	}
}

func TestStreamConflictDiagnosticHashesUntrustedMetadata(t *testing.T) {
	secret := "secret-password\nbody={\"user\":\"person\"}"
	ref := StreamBodyRef{Epoch: secret, Class: "evidence", Month: "202611", Scope: secret, Key: secret, SHA256: strings.Repeat("a", 64)}
	err := streamPositionConflict("body.metadata", "unexpected_row", time.Time{}, ref, secret, secret)
	message := err.Error()
	if strings.Contains(message, secret) || strings.Contains(message, "person") || strings.Contains(message, "password") || strings.Contains(message, "\n") {
		t.Fatalf("diagnostic leaked untrusted metadata: %s", message)
	}
	if len(message) > 512 {
		t.Fatalf("diagnostic grew beyond a bounded log line: %d bytes", len(message))
	}
}
