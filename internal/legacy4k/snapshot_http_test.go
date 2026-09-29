package legacy4k

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
