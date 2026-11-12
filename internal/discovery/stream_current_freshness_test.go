package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestStreamCurrentFreshnessNeverTreatsProcessingAsSourceCatchup(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name            string
		accepted        any
		projected       any
		processingLag   any
		active          int64
		projectedEpochs int64
		wantStatus      string
		minLag          float64
	}{
		{"recent completion with unverified source", now.Add(-20 * time.Second), now, float64(20), 1, 1, "unknown", 0},
		{"growing journal backlog despite a recent write", now.Add(-20 * time.Minute), now, float64(20 * 60), 1, 1, "delayed", 20 * 60},
		{"no recent completion", now.Add(-12 * time.Minute), now.Add(-12 * time.Minute), float64(0), 1, 1, "delayed", 12 * 60},
		{"active epoch without projected input", now, now, float64(0), 2, 1, "initializing", 0},
		{"no active epoch", nil, nil, nil, 0, 0, "initializing", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery(`(?s)SELECT min\(p.accepted_at\),min\(p.projected_at\).*WHERE epoch=c.epoch ORDER BY projected_at DESC LIMIT 1`).
				WillReturnRows(sqlmock.NewRows([]string{"accepted", "projected", "processing_lag", "version", "active", "projected_epochs"}).
					AddRow(tc.accepted, tc.projected, tc.processingLag, int64(9), tc.active, tc.projectedEpochs))
			got, err := (Repository{DB: db}).StreamCurrentFreshness(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got["status"] != tc.wantStatus || got["source_progress_status"] != "unverified" || got["result_version"] != int64(9) {
				t.Fatalf("freshness=%+v", got)
			}
			if got["lag_seconds"].(float64) < tc.minLag {
				t.Fatalf("lag below observed processing delay: %+v", got)
			}
			if tc.projected != nil && got["last_projected_input_at"] != tc.accepted {
				t.Fatalf("projected input acceptance time lost: %+v", got)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
