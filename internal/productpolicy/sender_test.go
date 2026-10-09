package productpolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSenderUsesIndependentBearerAndStableIdempotencyKey(t *testing.T) {
	snapshot := Snapshot{SchemaVersion: SchemaVersion, Source: "office", InstanceID: "redis", ObservedAt: time.Now().UTC().Truncate(time.Microsecond), Complete: true, Products: []Product{}, Controls: []Control{}}
	if err := snapshot.NormalizeAndValidate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer policy-token" || r.Header.Get("Idempotency-Key") != "snapshot-id" {
			t.Errorf("unexpected integration headers: %q %q", r.Header.Get("Authorization"), r.Header.Get("Idempotency-Key"))
		}
		var received Snapshot
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil || received.ContentHash != snapshot.ContentHash {
			t.Errorf("snapshot body mismatch: %+v %v", received, err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"snapshot_id": "snapshot-id", "status": "completed", "content_hash": snapshot.ContentHash})
	}))
	defer server.Close()
	if err := (Sender{Endpoint: server.URL, Token: "policy-token"}).Send(context.Background(), snapshot, "snapshot-id"); err != nil {
		t.Fatal(err)
	}
}
