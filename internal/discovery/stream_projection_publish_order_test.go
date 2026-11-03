package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// History and receipts can fail without ever holding the global publication
// lock. All writes still belong to the same transaction, including rollback
// when the final current-state publication fails.
func TestStreamProjectionPublishesAfterEvidenceWrites(t *testing.T) {
	for _, failAt := range []string{"history", "manifest", "state", ""} {
		t.Run("failure_"+failAt, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(streamStateArrayConverter{}))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			id, segment := stream3ProjectionTestSegment()
			prepared, err := prepareStreamDiscovery(segment)
			if err != nil || len(prepared) != 1 || !prepared[0].HasFact {
				t.Fatalf("prepare fact: %v", err)
			}
			fact := prepared[0].Fact
			factRaw, _ := json.Marshal(fact)
			injected := errors.New("interrupted " + failAt)
			mock.ExpectBegin()
			mock.ExpectExec("INSERT INTO stream_projection_segments").WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectExec("SELECT pg_advisory_xact_lock\\(hashtextextended").WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectQuery("SELECT f.device_key,f.fact_key,f.scope_id").WillReturnRows(sqlmock.NewRows([]string{"device_key"}))
			mock.ExpectExec("INSERT INTO stream_discovery_facts").WillReturnResult(sqlmock.NewResult(0, 1))
			history := mock.ExpectExec("INSERT INTO stream_discovery_changes")
			if failAt == "history" {
				history.WillReturnError(injected)
			} else {
				history.WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectQuery("SELECT .*since").WillReturnRows(sqlmock.NewRows([]string{"since"}))
				manifest := mock.ExpectExec("INSERT INTO stream_discovery_segment_receipt_manifests")
				if failAt == "manifest" {
					manifest.WillReturnError(injected)
				} else {
					manifest.WillReturnResult(sqlmock.NewResult(0, 1))
					mock.ExpectQuery("FROM stream_discovery_device_state").WillReturnRows(sqlmock.NewRows([]string{"device_key"}))
					mock.ExpectQuery("JOIN LATERAL").WillReturnRows(sqlmock.NewRows([]string{"device_key", "fact"}).AddRow(fact.Device, factRaw))
					mock.ExpectExec("SELECT pg_advisory_xact_lock\\(9184,213\\)").WillReturnResult(sqlmock.NewResult(0, 1))
					state := mock.ExpectExec("INSERT INTO stream_discovery_device_state")
					if failAt == "state" {
						state.WillReturnError(injected)
					} else {
						state.WillReturnResult(sqlmock.NewResult(0, 1))
						mock.ExpectQuery("WITH scopes AS").WillReturnRows(sqlmock.NewRows([]string{"mac", "saturated"}))
					}
				}
			}
			if failAt == "" {
				mock.ExpectCommit()
			} else {
				mock.ExpectRollback()
			}
			err = (StreamDiscoveryProjector{DB: db}).ProjectStreamSegment(context.Background(), id, segment)
			if failAt == "" && err != nil || failAt != "" && !errors.Is(err, injected) {
				t.Fatalf("projection error: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
