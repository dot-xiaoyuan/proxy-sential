package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"proxy-sentinel/internal/productpolicy"
)

func TestCatalogRetryRetainsSnapshotAndFollowsCommittedHost(t *testing.T) {
	reads, calls := 0, 0
	var received []productpolicy.BridgeCatalogSnapshot
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != productpolicy.BridgeCatalogPath || r.Header.Get("Authorization") != "Bearer bridge-token" {
			t.Errorf("unexpected channel")
		}
		var value productpolicy.BridgeCatalogSnapshot
		if json.NewDecoder(r.Body).Decode(&value) != nil {
			t.Error("invalid envelope")
		}
		received = append(received, value)
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "completed", "content_hash": value.Snapshot.ContentHash})
	}))
	defer server.Close()
	syncer := catalogSyncer{cfg: config{source: "ncu-srun4k"}, sender: productpolicy.Sender{Endpoint: server.URL, Token: "bridge-token"}, read: func(_ context.Context, host string) (productpolicy.Snapshot, error) {
		reads++
		value := productpolicy.Snapshot{SchemaVersion: productpolicy.SchemaVersion, Source: "ncu-srun4k", InstanceID: host, ObservedAt: time.Now().UTC().Truncate(time.Microsecond), Complete: true, Products: []productpolicy.Product{{ID: "p1", Name: "真实产品"}}, Controls: []productpolicy.Control{}}
		err := value.NormalizeAndValidate(time.Now().UTC())
		return value, err
	}}
	state := &runtimeState{activeHost: "222.204.3.224", activeConfigVersion: 1}
	if err := syncer.syncOnce(context.Background(), state); err == nil {
		t.Fatal("expected first send failure")
	}
	if err := syncer.syncOnce(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if reads != 1 || received[0].Snapshot.ContentHash != received[1].Snapshot.ContentHash || state.catalogProducts != 1 {
		t.Fatalf("retry replaced snapshot or did not publish health")
	}
	state.activeHost, state.activeConfigVersion = "222.204.3.225", 2
	if err := syncer.syncOnce(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if reads != 2 || received[2].Host != state.activeHost || received[2].ConfigVersion != 2 {
		t.Fatal("catalog did not follow committed identity host")
	}
}

func TestCatalogDoesNotPublishReadFromChangedHost(t *testing.T) {
	state := &runtimeState{activeHost: "222.204.3.224", activeConfigVersion: 1}
	syncer := catalogSyncer{read: func(context.Context, string) (productpolicy.Snapshot, error) {
		state.activeHost, state.activeConfigVersion = "222.204.3.225", 2
		return productpolicy.Snapshot{}, nil
	}}
	if err := syncer.syncOnce(context.Background(), state); err != errCatalogHostChanged || syncer.pending != nil {
		t.Fatalf("err=%v pending=%v", err, syncer.pending)
	}
}
