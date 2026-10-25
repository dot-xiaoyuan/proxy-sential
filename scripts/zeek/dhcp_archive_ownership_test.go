package zeekvalidation

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

// StageDiscoveryBatch stores the bound observation alongside the original file
// ledger. The file ingester already owns normalized_events; moving the task to
// a recovery lane must not transfer that ownership to the discovery writer.
func TestDHCPStagedBatchDoesNotArchiveNormalizedEventAgain(t *testing.T) {
	for _, lane := range []string{"realtime", "backfill"} {
		for _, source := range []string{"zeek-dhcp", "discovery-v2"} {
			t.Run(lane+"/"+source, func(t *testing.T) {
				event, config := dhcpBindingFixture()
				selected := config.SelectEvents([]normalized.Event{event})
				if len(selected) != 1 || selected[0].Type != "discovery" || event.Type != "device" {
					t.Fatal("fixture must exercise the distinct derived and source event documents")
				}
				raw, err := discovery.EncodeDiscoveryBatch(selected)
				if err != nil {
					t.Fatal(err)
				}
				db, mock, err := sqlmock.New()
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				mock.ExpectQuery("UPDATE discovery_batch_work").WithArgs(lane, sqlmock.AnyArg(), "").
					WillReturnRows(sqlmock.NewRows([]string{"id", "events", "offset", "archived", "accepted", "source", "selected_count"}).
						AddRow("file-batch", raw, 0, false, sampleTime, source, nil))
				// Stop after the evidence boundary, before unrelated projection SQL.
				mock.ExpectExec("UPDATE discovery_batch_work SET attempts").WillReturnResult(sqlmock.NewResult(0, 1))
				stop := errors.New("test reached independent evidence archive")
				normalizedWrites, evidenceWrites := 0, 0
				repo := discovery.Repository{DB: db,
					Archive: func(context.Context, []normalized.Event) error {
						normalizedWrites++
						return nil
					},
					ArchiveDiscovery: func(_ context.Context, batch string, accepted time.Time, got []normalized.Event) error {
						evidenceWrites++
						if batch != "file-batch/segment/0" || !accepted.Equal(sampleTime) || len(got) != 1 || got[0].EventID != event.EventID || got[0].Type != "discovery" {
							t.Fatal("evidence archive lost its original file batch or derived document")
						}
						return stop
					},
				}
				worked, err := repo.ProcessDiscoveryLane(context.Background(), lane)
				if !worked || !errors.Is(err, stop) || evidenceWrites != 1 {
					t.Fatalf("evidence boundary: worked=%v writes=%d err=%v", worked, evidenceWrites, err)
				}
				wantNormalized := 0
				if source == "discovery-v2" {
					wantNormalized = 1
				}
				if normalizedWrites != wantNormalized {
					t.Fatalf("normalized archive writes=%d want=%d for %s", normalizedWrites, wantNormalized, source)
				}
				if err = mock.ExpectationsWereMet(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// Legacy DHCP observations retain the immutable source in Evidence. A native
// discovery-v2 backfill must reconcile that exact event, not SelectEvents' bound
// copy with a different source_id and type under the same event_id.
func TestDHCPLegacyBackfillRetainsOriginalNormalizedDocument(t *testing.T) {
	event, _ := dhcpBindingFixture()
	observation := discovery.Observation{ID: event.EventID, Evidence: event}
	document, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	events := []normalized.Event{event}
	raw, err := discovery.EncodeDiscoveryBatch(events)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO discovery_rebuild_progress").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT last_key,completed").WillReturnRows(sqlmock.NewRows([]string{"last_key", "completed"}).AddRow("", false))
	mock.ExpectQuery("SELECT id,data FROM discovery_observations").WithArgs("").
		WillReturnRows(sqlmock.NewRows([]string{"id", "data"}).AddRow(event.EventID, document))
	mock.ExpectRollback()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO ingest_batches").WithArgs(sqlmock.AnyArg(), event.Observer["sensor_id"], 1, hash).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT checksum FROM ingest_batches").WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"checksum"}).AddRow(hash))
	// The bounded segment retains the original Type=device document, without
	// synthetic source_id or binding fields from SelectEvents.
	mock.ExpectExec("INSERT INTO discovery_batch_work").WithArgs(sqlmock.AnyArg(), "backfill", 1, hash).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO discovery_batch_segments").WithArgs(sqlmock.AnyArg(), originalDHCPRecord{event.EventID}).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectExec("UPDATE discovery_rebuild_progress SET last_key").WithArgs(event.EventID, true, "").
		WillReturnResult(sqlmock.NewResult(0, 1))
	worked, err := (discovery.Repository{DB: db}).BackfillDiscoveryPage(context.Background())
	if !worked || err != nil {
		t.Fatalf("backfill: worked=%v err=%v", worked, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

type originalDHCPRecord struct{ eventID string }

func (want originalDHCPRecord) Match(value driver.Value) bool {
	raw, ok := value.([]byte)
	if !ok {
		return false
	}
	var rows []struct {
		Events []normalized.Event `json:"events"`
	}
	return json.Unmarshal(raw, &rows) == nil && len(rows) == 1 && len(rows[0].Events) == 1 &&
		rows[0].Events[0].EventID == want.eventID && rows[0].Events[0].Type == "device" &&
		rows[0].Events[0].Observer["source_id"] == nil
}
