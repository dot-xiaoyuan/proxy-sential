package legacy4k

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A snapshot the endpoint accepted but has not published yet must not be reported as a
// failed upload: the bridge re-sent a new snapshot on every such timeout and turned a
// 30-minute reconcile into a 3m20s rebuild loop. Only an explicit calibration failure
// is an error.
func TestSnapshotPublicationTimeoutIsPendingNotFailure(t *testing.T) {
	state := "building"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"snapshot_id": "snap", "published": false, "calibration_state": state})
	}))
	defer srv.Close()
	sender := Sender{Endpoint: srv.URL, SensorID: "s", Source: "src", PublicationWait: 1500 * time.Millisecond}
	if err := sender.waitSnapshotPublication(context.Background(), "snap", "c", "d"); !errors.Is(err, ErrSnapshotPublicationPending) {
		t.Fatalf("pending publication reported as %v", err)
	}
	state = "failed"
	if err := sender.waitSnapshotPublication(context.Background(), "snap", "c", "d"); err == nil || errors.Is(err, ErrSnapshotPublicationPending) {
		t.Fatalf("calibration failure reported as %v", err)
	}
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	state = "building"
	if err := sender.waitSnapshotPublication(parent, "snap", "c", "d"); !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown reported as %v", err)
	}
}
