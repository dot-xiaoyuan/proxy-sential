package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestEventBusCurrentFreshnessReportsCopyWatermarkWithoutClaimingReadiness(t *testing.T) {
	for _, tc := range []struct {
		name     string
		version  int64
		caughtUp bool
		want     string
	}{
		{"copy behind", 10, false, "delayed"},
		{"copy caught up but source unverified", 20, true, "processing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery(`SELECT count\(\*\),count\(p.epoch\)`).WillReturnRows(sqlmock.NewRows([]string{"active", "copied", "caught", "updated", "version"}).AddRow(1, 1, tc.caughtUp, time.Now().UTC(), tc.version))
			got, err := (Repository{DB: db}).EventBusCurrentFreshness(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got["status"] != tc.want || got["result_version"] != tc.version || got["source_progress_status"] != "unverified" {
				t.Fatalf("freshness=%+v", got)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
