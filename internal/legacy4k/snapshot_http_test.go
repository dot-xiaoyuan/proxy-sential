package legacy4k

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSnapshotAcknowledgementAndReplayIdentity(t *testing.T) {
	in := OnlineInventory{InstanceID: "epoch", ObservedAt: time.Now().UTC(), Rows: []map[string]string{{"rad_online_id": "1", "user_name": "alice", "ip": "192.0.2.1"}}}
	for _, mode := range []string{"ok", "wrong_id", "wrong_count", "pending", "malformed", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			var previous string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				id := r.Header.Get("Idempotency-Key")
				if id != StableID(string(body)) || previous != "" && previous != id {
					t.Error("unstable retry identity")
				}
				previous = id
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("missing authentication")
				}
				ack := map[string]any{"status": "completed", "snapshot_id": id, "session_count": 1}
				switch mode {
				case "wrong_id":
					ack["snapshot_id"] = "other"
				case "wrong_count":
					ack["session_count"] = 0
				case "pending":
					ack["status"] = "pending"
				case "malformed":
					w.Write([]byte("not-json"))
					return
				case "unavailable":
					w.WriteHeader(503)
					return
				}
				json.NewEncoder(w).Encode(ack)
			}))
			defer srv.Close()
			sender := Sender{Endpoint: srv.URL, Token: "test-token", SensorID: "auth"}
			for i := 0; i < 2; i++ {
				err := sender.SendSnapshot(context.Background(), in, "source", "campus", "domain", 60)
				if (err == nil) != (mode == "ok") {
					t.Fatal(mode, err)
				}
			}
		})
	}
}

func TestLargeSnapshotUsesBoundedReplayableUpload(t *testing.T) {
	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	rows := make([]map[string]string, 10001)
	for i := range rows {
		rows[i] = map[string]string{
			"rad_online_id": fmt.Sprintf("%d", i+1),
			"user_name":     fmt.Sprintf("account-%d", i+1),
			"ip":            fmt.Sprintf("198.51.%d.%d", (i/254)%200, i%254+1),
			"add_time":      fmt.Sprintf("%d", observedAt.Add(-time.Minute).Unix()),
		}
	}
	var uploadID string
	var createCount, commitCount, recordCount int
	chunkIndexes := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing upload authentication")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/integrations/identity/snapshot-uploads":
			createCount++
			var manifest struct {
				UploadID        string `json:"upload_id"`
				IntervalSeconds int    `json:"reconcile_interval_seconds"`
				ExpectedCount   int    `json:"expected_count"`
				ExpectedChunks  int    `json:"expected_chunks"`
			}
			if err := json.NewDecoder(r.Body).Decode(&manifest); err != nil {
				t.Error(err)
			}
			if uploadID == "" {
				uploadID = manifest.UploadID
			}
			if manifest.UploadID != uploadID || manifest.IntervalSeconds != 1800 || manifest.ExpectedCount != len(rows) || manifest.ExpectedChunks < 6 {
				t.Fatalf("unexpected upload manifest: %+v", manifest)
			}
			json.NewEncoder(w).Encode(map[string]any{"upload_id": uploadID, "status": "uploading"})
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/chunks/"):
			body, _ := io.ReadAll(r.Body)
			if len(body) > snapshotChunkByteLimit {
				t.Fatalf("chunk exceeded byte limit: %d", len(body))
			}
			var records []map[string]string
			if err := json.Unmarshal(body, &records); err != nil || len(records) == 0 || len(records) > snapshotChunkRecordLimit {
				t.Fatalf("invalid bounded chunk: records=%d err=%v", len(records), err)
			}
			recordCount += len(records)
			chunkIndexes[r.URL.Path] = true
			json.NewEncoder(w).Encode(map[string]any{"status": "accepted"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/commit"):
			commitCount++
			if !strings.Contains(r.URL.Path, uploadID) || r.Header.Get("Idempotency-Key") == "" {
				t.Fatalf("unstable commit identity: %s", r.URL.Path)
			}
			json.NewEncoder(w).Encode(map[string]any{"upload_id": uploadID, "status": "completed"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	sender := Sender{Endpoint: server.URL, Token: "test-token", SensorID: "ncu-auth-redis"}
	if err := sender.SendSnapshot(context.Background(), OnlineInventory{InstanceID: "epoch", ObservedAt: observedAt, Rows: rows}, "ncu-srun4k", "ncu", "campus-auth", 1800); err != nil {
		t.Fatal(err)
	}
	if createCount != 1 || commitCount != 1 || recordCount != len(rows) || len(chunkIndexes) < 6 {
		t.Fatalf("upload coverage create=%d commit=%d records=%d chunks=%d", createCount, commitCount, recordCount, len(chunkIndexes))
	}
}
