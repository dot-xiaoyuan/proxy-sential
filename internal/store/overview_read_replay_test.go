package store

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// The workbench gets windowed event counts from GetActivityOverview. A second
// 24h raw-event scan here used up the shared request deadline before that read.
func TestOverviewDoesNotScanRawEvents(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`FROM sensors.*CROSS JOIN LATERAL`).WithArgs(1).
		WillReturnRows(sqlmock.NewRows([]string{"run_id"}))
	mock.ExpectQuery(`SELECT level, count\(\*\) FROM risk_snapshots`).
		WillReturnRows(sqlmock.NewRows([]string{"level", "count"}).AddRow("high", 2))
	mock.ExpectQuery(`SELECT type,evidence_count FROM evidence_type_counts`).
		WillReturnRows(sqlmock.NewRows([]string{"type", "evidence_count"}).AddRow("ttl_clusters", 3))
	mock.ExpectQuery(`FROM risk_snapshots`).
		WillReturnRows(sqlmock.NewRows([]string{"ip"}))
	mock.ExpectQuery(`FROM labels`).
		WillReturnRows(sqlmock.NewRows([]string{"label_id"}))
	var rawScans atomic.Int32
	chServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawScans.Add(1)
		// Replay a scan that outlives the caller's budget without a real large DB.
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}))
	defer chServer.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: chServer.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	result, err := (&DBStore{pg: &PostgresStore{db: db}, ch: ch}).Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rawScans.Load() != 0 || ctx.Err() != nil {
		t.Fatalf("overview consumed the activity-read budget: raw_scans=%d context=%v", rawScans.Load(), ctx.Err())
	}
	if result.LevelCounts["high"] != 2 || len(result.TopEvidence) != 1 || result.TopEvidence[0].Count != 3 {
		t.Fatalf("risk/evidence summary changed: %+v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIngestStatusUsesLatestBatchWithoutRawScan(t *testing.T) {
	for _, tc := range []struct {
		name      string
		malformed int
		truncated bool
		byType    string
	}{
		{"healthy", 0, false, `{"dns":3}`},
		{"malformed", 1, false, `{"dns":3}`},
		{"rotated", 0, true, `{"dns":3}`},
		{"empty distribution", 0, false, `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			at := time.Now().UTC()
			rows := sqlmock.NewRows([]string{"run_id", "sensor_id", "started_at", "finished_at", "previous_offset", "new_offset", "truncated", "normalized_read", "normalized_emitted", "normalized_skipped", "normalized_malformed", "evidence_count", "risk_count", "risk_list_count", "summary"}).AddRow("local-run", "local", at, at, 0, 3, tc.truncated, 3, 3, 0, tc.malformed, 0, 0, 0, fmt.Sprintf(`{"normalized":{"by_type":%s},"zeek_status":"ready"}`, tc.byType))
			mock.ExpectQuery(`FROM collector_runs WHERE sensor_id=\$1`).WithArgs("local", 1).WillReturnRows(rows)
			var scans atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				scans.Add(1)
				fmt.Fprintln(w, `{"type":"dns","count":999999}`)
			}))
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			status, err := (&DBStore{pg: &PostgresStore{db: db, sensorID: "local"}, ch: ch}).IngestStatus(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			wantDNS := 3
			if tc.byType == `{}` {
				wantDNS = 0
			}
			if scans.Load() != 0 || status.LastEventTypeDist == nil || status.LastEventTypeDist["dns"] != wantDNS {
				t.Fatalf("last batch borrowed 24h scan: scans=%d distribution=%v", scans.Load(), status.LastEventTypeDist)
			}
			if status.LatestRunID != "local-run" || status.SensorID != "local" || status.LastCounters["emitted"] != 3 || status.Healthy != (tc.malformed == 0 && !tc.truncated) {
				t.Fatalf("collector state changed: %+v", status)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
