package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"proxy-sentinel/internal/normalized"
	"strings"
	"testing"
	"time"
)

func TestIdentityExportConfirmationLossDoesNotRepeatIdentity(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "export", SensorID: fmt.Sprintf("export-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	pg.sensorID = scope.SensorID
	key := IdentityScopeKey(scope)
	event := inboxEvent(scope, key+"event", "session", "192.0.2.1", "start", time.Now().UTC())
	if _, err := pg.acceptIdentityBatch(ctx, key+"batch", "hash", scope, []normalized.Event{event}, 1); err != nil {
		t.Fatal(err)
	}
	work, err := pg.claimIdentityInbox(ctx, scope.SensorID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.applyIdentityInbox(ctx, work); err != nil {
		t.Fatal(err)
	}
	inserted := false
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "INSERT INTO normalized_events") {
			writes++
			inserted = true
			// ClickHouse committed, but the export lease expired before PostgreSQL ACK.
			if _, e := pg.db.ExecContext(ctx, `UPDATE identity_ingest_batches SET export_lease_until=now()-interval '1 second' WHERE batch_id=$1`, key+"batch"); e != nil {
				t.Error(e)
			}
		} else if inserted {
			_ = json.NewEncoder(w).Encode(map[string]string{"event_id": event.EventID})
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	backend := &DBStore{pg: pg, ch: ch}
	if err = backend.exportIdentityInboxBatch(ctx); !errors.Is(err, ErrIdentityLeaseExpired) {
		t.Fatalf("expired export ack: %v", err)
	}
	summary, err := ReadIdentityPipelineSummary(ctx, pg.db, scope)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ExportPendingRecords != 1 || summary.PendingRecords != 0 || *summary.Sessions != 1 {
		t.Fatalf("phase ownership lost: %+v", summary)
	}
	if err = backend.exportIdentityInboxBatch(ctx); err != nil {
		t.Fatal(err)
	}
	summary, err = ReadIdentityPipelineSummary(ctx, pg.db, scope)
	if err != nil {
		t.Fatal(err)
	}
	if writes != 1 || summary.ExportPendingRecords != 0 || *summary.Sessions != 1 {
		t.Fatalf("replayed export counted again: writes=%d summary=%+v", writes, summary)
	}
}

func TestIdentityExportWaitsForAuthoritativeBacklog(t *testing.T) {
	pg := inboxTestStore(t)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	scope := IdentityScope{Source: "export-priority", SensorID: fmt.Sprintf("export-priority-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	pg.sensorID = scope.SensorID
	key := IdentityScopeKey(scope)
	event := inboxEvent(scope, key+"event", "session", "192.0.2.1", "start", time.Now().UTC())
	if _, err := pg.acceptIdentityBatch(ctx, key+"batch", "hash", scope, []normalized.Event{event}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.db.ExecContext(ctx, `UPDATE identity_pipeline_scopes SET oldest_pending_at=now()-interval '10 seconds' WHERE scope_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	requests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- struct{}{}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	backend := &DBStore{pg: pg, ch: ch}
	done := make(chan struct{})
	go func() { backend.runIdentityInboxExport(ctx); close(done) }()
	select {
	case <-requests:
		t.Fatal("raw export competed with pending current identity")
	case <-time.After(150 * time.Millisecond):
	}
	var pending int
	if err := pg.db.QueryRowContext(ctx, `SELECT export_pending_records FROM identity_pipeline_scopes WHERE scope_key=$1`, key).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("export responsibility changed: pending=%d err=%v", pending, err)
	}
	stop()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("export loop did not stop")
	}
}

func TestIdentityExportCombinesSmallBatchesWithinRecordBudget(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "export-bulk", SensorID: fmt.Sprintf("export-bulk-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	other := scope
	other.CampusID = "other"
	pg.sensorID = scope.SensorID
	for batch := 0; batch < 25; batch++ {
		batchScope := scope
		if batch%2 != 0 {
			batchScope = other
		}
		events := []normalized.Event{}
		for item := 0; item < 25; item++ {
			id := fmt.Sprintf("export-bulk-%d-%d", batch, item)
			events = append(events, inboxEvent(batchScope, id, id, "192.0.2.1", "start", time.Now().UTC()))
		}
		if _, err := pg.acceptIdentityBatch(ctx, fmt.Sprintf("%s-batch-%d", scope.SensorID, batch), "hash", batchScope, events, len(events)); err != nil {
			t.Fatal(err)
		}
	}
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "INSERT INTO normalized_events") {
			writes++
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	backend := &DBStore{pg: pg, ch: ch}
	if err := backend.exportIdentityInboxBatch(ctx); err != nil {
		t.Fatal(err)
	}
	summary, err := ReadIdentityPipelineSummary(ctx, pg.db, scope)
	otherSummary, otherErr := ReadIdentityPipelineSummary(ctx, pg.db, other)
	if err != nil || otherErr != nil || summary.ExportPendingRecords != 75 || otherSummary.ExportPendingRecords != 50 || summary.PendingRecords != 325 || otherSummary.PendingRecords != 300 || writes != 1 {
		t.Fatalf("first export changed responsibility: %+v writes=%d err=%v", summary, writes, err)
	}
	if err := backend.exportIdentityInboxBatch(ctx); err != nil {
		t.Fatal(err)
	}
	summary, err = ReadIdentityPipelineSummary(ctx, pg.db, scope)
	otherSummary, otherErr = ReadIdentityPipelineSummary(ctx, pg.db, other)
	if err != nil || otherErr != nil || summary.ExportPendingRecords != 0 || otherSummary.ExportPendingRecords != 0 || summary.PendingRecords != 325 || otherSummary.PendingRecords != 300 || writes != 2 {
		t.Fatalf("second export lost progress: %+v writes=%d err=%v", summary, writes, err)
	}
}

func TestIdentityExportCombinedWriteFailureKeepsEveryBatchPending(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "export-retry", SensorID: fmt.Sprintf("export-retry-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	other := scope
	other.CampusID = "other"
	pg.sensorID = scope.SensorID
	for i, current := range []IdentityScope{scope, other} {
		id := fmt.Sprintf("%s-batch-%d", scope.SensorID, i)
		event := inboxEvent(current, id+"-event", id, "192.0.2.1", "start", time.Now().UTC())
		if _, err := pg.acceptIdentityBatch(ctx, id, "hash", current, []normalized.Event{event}, 1); err != nil {
			t.Fatal(err)
		}
	}
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "INSERT INTO normalized_events") {
			writes++
			if writes == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	backend := &DBStore{pg: pg, ch: ch}
	if err := backend.exportIdentityInboxBatch(ctx); err == nil {
		t.Fatal("failed ClickHouse write was acknowledged")
	}
	for _, current := range []IdentityScope{scope, other} {
		summary, err := ReadIdentityPipelineSummary(ctx, pg.db, current)
		if err != nil || summary.ExportPendingRecords != 1 || summary.ExportError != "raw_export_failed" {
			t.Fatalf("failed batch lost responsibility: %+v err=%v", summary, err)
		}
	}
	if _, err := pg.db.ExecContext(ctx, `UPDATE identity_ingest_batches SET export_lease_until=now()-interval '1 second' WHERE sensor_id=$1`, scope.SensorID); err != nil {
		t.Fatal(err)
	}
	if err := backend.exportIdentityInboxBatch(ctx); err != nil {
		t.Fatal(err)
	}
	for _, current := range []IdentityScope{scope, other} {
		summary, err := ReadIdentityPipelineSummary(ctx, pg.db, current)
		if err != nil || summary.ExportPendingRecords != 0 || summary.ExportError != "" {
			t.Fatalf("retry failed to complete batch: %+v err=%v", summary, err)
		}
	}
	if writes != 2 {
		t.Fatalf("writes=%d, want 2", writes)
	}
}
