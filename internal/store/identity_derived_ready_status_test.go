package store

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

type identityReadyStatusMatch struct {
	state                            string
	fresh, older, scanDone, hasError bool
	sampledAt                        time.Time
}

func (want identityReadyStatusMatch) Match(value driver.Value) bool {
	var raw []byte
	switch v := value.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return false
	}
	var got struct {
		State     string    `json:"state"`
		Fresh     bool      `json:"fresh_index_keys_present"`
		Older     bool      `json:"existing_index_keys_present"`
		ScanDone  bool      `json:"pending_key_scan_complete"`
		HasError  bool      `json:"index_error_keys_present"`
		Scope     string    `json:"scope"`
		SampledAt time.Time `json:"sampled_at"`
	}
	return json.Unmarshal(raw, &got) == nil && got.State == want.state && got.Fresh == want.fresh && got.Older == want.older && got.ScanDone == want.scanDone && got.HasError == want.hasError && got.Scope == "ready_index_only" && got.SampledAt.Equal(want.sampledAt)
}

func TestIdentityDerivedReadyStatusDoesNotCallUnindexedWorkComplete(t *testing.T) {
	for _, tc := range []struct {
		state                        string
		done, fresh, older, hasError bool
	}{
		{"indexing", false, false, false, false},
		{"index_keys_present", true, true, false, false},
		{"index_keys_present", true, false, true, false},
		{"index_errors", true, true, false, true},
		{"ready_index_empty", true, false, false, false},
	} {
		t.Run(tc.state+string(rune('0'+boolInt(tc.fresh)*2+boolInt(tc.older))), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			sampled := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
			mock.ExpectQuery(`SELECT s.done,EXISTS`).WithArgs("sensor").WillReturnRows(sqlmock.NewRows([]string{"done", "fresh", "older", "has_error", "sampled_at"}).AddRow(tc.done, tc.fresh, tc.older, tc.hasError, sampled))
			mock.ExpectExec(`INSERT INTO read_model_runtime_state.*WHERE.*sampled_at`).WithArgs("identity-derived-ready:sensor", identityReadyStatusMatch{tc.state, tc.fresh, tc.older, tc.done, tc.hasError, sampled}).WillReturnResult(sqlmock.NewResult(0, 1))
			if err := (&PostgresStore{db: db, sensorID: "sensor"}).publishIdentityDerivedReadyStatus(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func TestIdentityDerivedReadyStatusDoesNotPublishOnReadFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	failure := errors.New("queue status unavailable")
	mock.ExpectQuery(`SELECT s.done,EXISTS`).WithArgs("sensor").WillReturnError(failure)
	if err := (&PostgresStore{db: db, sensorID: "sensor"}).publishIdentityDerivedReadyStatus(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("status read error hidden: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityMaterializerStatusExposesCachedReadySnapshotWithAge(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`SELECT jsonb_build_object.*updated_at.*stale.*identity-derived-ready:`).WithArgs("sensor").WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow([]byte(`{"health":{},"cursors":[],"pending_snapshots":0,"derived_ready":{"state":"indexing","scope":"ready_index_only","stale":false}}`)))
	status, err := (&DBStore{pg: &PostgresStore{db: db, sensorID: "sensor"}}).IdentityMaterializerStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ready, ok := status["derived_ready"].(map[string]any)
	if !ok || ready["state"] != "indexing" || ready["stale"] != false {
		t.Fatalf("missing or incorrect ready status: %+v", status)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
