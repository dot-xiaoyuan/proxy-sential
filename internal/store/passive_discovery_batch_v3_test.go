package store

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
)

func TestPassiveDiscoveryBatchV3CarriesStableSelectedOrdinals(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_PASSIVE_DISCOVERY_BATCH_V3_STAGE", "true")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	events := []normalized.Event{
		{EventID: "arp", Timestamp: now, SourceEventType: "arp", Observer: map[string]any{"sensor_id": "sensor"}},
		{EventID: "dns", Timestamp: now, SourceEventType: "dns", Observer: map[string]any{"sensor_id": "sensor"}},
		{EventID: "mdns", Timestamp: now, SourceEventType: "mdns", Payload: map[string]any{"is_response": true}, Observer: map[string]any{"sensor_id": "sensor"}},
	}
	_, count, digest, err := passiveDiscoveryBatchV3Manifest(events)
	if err != nil || count != 2 || len(digest) != 64 {
		t.Fatalf("bad selected manifest: count=%d digest=%s err=%v", count, digest, err)
	}
	var rows []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		for _, line := range strings.Split(string(body), "\n")[1:] {
			if line == "" {
				continue
			}
			var row map[string]any
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Fatal(err)
			}
			rows = append(rows, row)
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	pg, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	mock.ExpectExec("INSERT INTO passive_discovery_batch_progress").WithArgs("batch-a", 2, digest).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT p.selected_count,p.selection_sha256,b.started_at").WithArgs("batch-a").WillReturnRows(sqlmock.NewRows([]string{"selected_count", "selection_sha256", "started_at"}).AddRow(2, digest, time.Now().UTC()))
	backend := &DBStore{pg: &PostgresStore{db: pg}, ch: ch}
	if err = backend.stagePassiveDiscoveryBatchV3(context.Background(), ingest.Batch{BatchID: "batch-a", SensorID: "sensor"}, events); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0]["ordinal"] != float64(0) || rows[1]["ordinal"] != float64(1) {
		t.Fatalf("selected positions changed or nonselected event was copied: %+v", rows)
	}
	if rows[0]["batch_id"] != "batch-a" || len(rows[0]["event_content_sha256"].(string)) != 64 || rows[0]["event_json"] == "" {
		t.Fatalf("selected source locator is incomplete: %+v", rows[0])
	}
}

func TestPassiveDiscoveryV3ManifestRetainsLateInputAndRejectsGaps(t *testing.T) {
	now := time.Now().UTC()
	events := []normalized.Event{
		{EventID: "late-arp", SourceEventType: "arp", Timestamp: now.Add(-15 * time.Minute).Format(time.RFC3339Nano)},
		{EventID: "current-arp", SourceEventType: "arp", Timestamp: now.Format(time.RFC3339Nano)},
	}
	positions, count, expected, err := passiveDiscoveryBatchV3Manifest(events)
	if err != nil || count != 2 {
		t.Fatalf("late event was excluded: count=%d err=%v", count, err)
	}
	rows := []passiveDiscoveryV3HashRow{{Ordinal: 0, EventID: "late-arp", Hash: positions[0].Hash}, {Ordinal: 1, EventID: "current-arp", Hash: positions[1].Hash}}
	actual, err := passiveDiscoveryV3ManifestHash(rows, count)
	if err != nil || actual != expected {
		t.Fatalf("batch manifest mismatch: actual=%s expected=%s err=%v", actual, expected, err)
	}
	rows[1].Ordinal = 2
	if _, err := passiveDiscoveryV3ManifestHash(rows, count); err == nil {
		t.Fatal("a missing ordinal was accepted")
	}
}

func TestPassiveDiscoveryV3RetainsRepeatedEventAtSeparateBatchPositions(t *testing.T) {
	event := normalized.Event{EventID: "replayed-arp", SourceEventType: "arp", Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	positions, count, digest, err := passiveDiscoveryBatchV3Manifest([]normalized.Event{event, event})
	if err != nil || count != 2 || positions[0].Ordinal != 0 || positions[1].Ordinal != 1 || positions[0].Hash != positions[1].Hash {
		t.Fatalf("repeated source event lost or changed: positions=%+v count=%d hash=%s err=%v", positions, count, digest, err)
	}
	rows := []passiveDiscoveryV3HashRow{{Ordinal: 0, EventID: event.EventID, Hash: positions[0].Hash}, {Ordinal: 1, EventID: event.EventID, Hash: positions[1].Hash}}
	verified, err := passiveDiscoveryV3ManifestHash(rows, count)
	if err != nil || verified != digest {
		t.Fatalf("repeated event positions failed manifest verification: %s %v", verified, err)
	}
	changed := event
	changed.Payload = map[string]any{"message": "changed"}
	if _, _, _, err := passiveDiscoveryBatchV3Manifest([]normalized.Event{event, changed}); err == nil {
		t.Fatal("same event ID with changed body was admitted")
	}
}

func TestPassiveDiscoveryV3PublishedCutoverRejectsUnstagedSourceBatch(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_PASSIVE_DISCOVERY_BATCH_V3_STAGE", "false")
	t.Setenv("PROXY_SENTINEL_DISCOVERY_V2", "false")
	pg, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	mock.ExpectQuery("SELECT COALESCE.*active.*read_model_runtime_state").WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(true))
	backend := &DBStore{pg: &PostgresStore{db: pg}}
	if err := backend.StageDiscoveryBatch(context.Background(), ingest.Batch{BatchID: "batch-after-cutover"}, nil); err == nil || !strings.Contains(err.Error(), "staging is disabled") {
		t.Fatalf("source checkpoint could advance without v3 staging: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveDiscoveryV3RejectsChangedContentForSameBatchID(t *testing.T) {
	pg, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	event := normalized.Event{EventID: "same-id", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), SourceEventType: "arp"}
	_, count, hash, err := passiveDiscoveryBatchV3Manifest([]normalized.Event{event})
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec("INSERT INTO passive_discovery_batch_progress").WithArgs("batch-conflict", count, hash).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT p.selected_count,p.selection_sha256,b.started_at").WithArgs("batch-conflict").WillReturnRows(sqlmock.NewRows([]string{"selected_count", "selection_sha256", "started_at"}).AddRow(count, strings.Repeat("0", 64), time.Now().UTC()))
	backend := &DBStore{pg: &PostgresStore{db: pg}}
	if err := backend.stagePassiveDiscoveryBatchV3(context.Background(), ingest.Batch{BatchID: "batch-conflict"}, []normalized.Event{event}); err == nil || !strings.Contains(err.Error(), "content conflict") {
		t.Fatalf("duplicate batch changed its selected body without being fenced: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveDiscoveryV3ReadFlagCannotCutWithoutOverlapAudit(t *testing.T) {
	pg, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	mock.ExpectQuery("SELECT COALESCE.*active.*read_model_runtime_state").WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(false))
	mock.ExpectQuery("SELECT COALESCE.*approved.*read_model_runtime_state").WillReturnRows(sqlmock.NewRows([]string{"approved", "overlap_from", "overlap_until", "coverage_sha256"}))
	backend := &DBStore{pg: &PostgresStore{db: pg}}
	ready, err := backend.passiveDiscoveryV3CutoverReady(context.Background(), "campus-204")
	if err != nil || ready {
		t.Fatalf("read switch bypassed overlap audit: ready=%t err=%v", ready, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
