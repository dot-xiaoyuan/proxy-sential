package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/store"
)

type replayIdentityReader struct {
	store.Reader
	events []normalized.Event
}

func (r *replayIdentityReader) IngestIdentityEvents(_ context.Context, events []normalized.Event) error {
	r.events = append(r.events, events...)
	return nil
}

func TestIdentityBatchReplayUsesRetainedNormalizedEvents(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	state, err := newIdentityIngestState("integration-token", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer state.db.Close()
	const batchID = "integration-replay-batch"
	scope := store.IdentityScope{Source: "radius", SensorID: "integration", CampusID: "east", AccessDomain: "wifi"}
	events := []normalized.Event{{SchemaVersion: "v1", EventID: "integration-replay-event", Source: "radius", Type: "identity", Timestamp: "2026-08-31T10:00:00Z", Observer: map[string]any{"sensor_id": scope.SensorID}, Subject: map[string]any{"campus_id": scope.CampusID}, Payload: map[string]any{"access_domain": scope.AccessDomain}}}
	eventsJSON, _ := json.Marshal(events)
	_, _ = state.db.ExecContext(ctx, `DELETE FROM identity_ingest_batches WHERE batch_id=$1`, batchID)
	_, err = state.db.ExecContext(ctx, `INSERT INTO identity_ingest_batches(batch_id,source,sensor_id,status,records_read,records_emitted,records_skipped,records_malformed,error_message,received_at,normalized_events) VALUES($1,'radius','integration','failed',1,1,0,0,'temporary failure',now(),$2)`, batchID, eventsJSON)
	if err != nil {
		t.Fatal(err)
	}
	reader := &replayIdentityReader{}
	server := &Server{reader: reader, identityIngest: state, identitySources: []identitySourceRegistration{{IdentityScope: scope, IntervalSeconds: 60}}}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/identity/batches/"+batchID+"/replay", nil)
	recorder := httptest.NewRecorder()
	server.handleIdentityBatchReplay(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected replay response %d: %s", recorder.Code, recorder.Body.String())
	}
	if len(reader.events) != 1 || reader.events[0].EventID != "integration-replay-event" {
		t.Fatalf("retained events were not replayed: %+v", reader.events)
	}
	var status string
	var retries int
	if err := state.db.QueryRowContext(ctx, `SELECT status,retry_count FROM identity_ingest_batches WHERE batch_id=$1`, batchID).Scan(&status, &retries); err != nil {
		t.Fatal(err)
	}
	if status != "completed" || retries != 1 {
		t.Fatalf("unexpected replay state: status=%s retries=%d", status, retries)
	}
	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/integrations/identity/batches?limit=20", nil)
	listRecorder := httptest.NewRecorder()
	server.handleIdentityBatches(listRecorder, listRequest)
	var page struct {
		Items []IdentityIngestBatch `json:"items"`
		Page  Page                  `json:"page"`
	}
	decodeResponse(t, listRecorder, http.StatusOK, &page)
	found := false
	for _, item := range page.Items {
		if item.BatchID == batchID && item.Status == "completed" && item.RetryCount == 1 {
			found = true
		}
	}
	if !found || page.Page.Limit != 20 {
		t.Fatalf("replayed batch status was not listed: %+v", page)
	}
}
