package controlplane

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestClassifyPassiveStreamCaptureDoesNotTreatOldCaptureAsReady(t *testing.T) {
	now := time.Date(2026, 11, 12, 7, 30, 0, 0, time.UTC)
	cases := []struct {
		name    string
		enabled int64
		at      sql.NullTime
		err     sql.NullString
		want    string
	}{
		{"recovering with old heartbeat", 4, sql.NullTime{Time: now.Add(-time.Hour), Valid: true}, sql.NullString{}, "stale"},
		{"short capture delay", 4, sql.NullTime{Time: now.Add(-30 * time.Second), Valid: true}, sql.NullString{}, "delayed"},
		{"current capture", 4, sql.NullTime{Time: now.Add(-time.Second), Valid: true}, sql.NullString{}, "ready"},
		{"source not configured", 0, sql.NullTime{}, sql.NullString{}, "initializing"},
		{"capture error", 4, sql.NullTime{Time: now.Add(-time.Second), Valid: true}, sql.NullString{String: "capture_failed", Valid: true}, "failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyPassiveStreamCapture(c.enabled, c.at, c.err, now)
			if got.Status != c.want {
				t.Fatalf("status=%s want=%s: %+v", got.Status, c.want, got)
			}
			if c.at.Valid && got.UpdatedAt != c.at.Time.Format(time.RFC3339Nano) {
				t.Fatalf("capture watermark missing: %+v", got)
			}
		})
	}
}

func TestPassiveStreamCaptureHealthUsesScopedCaptureAndProjectionWatermarks(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery(`FROM discovery_protocol_runtime`).WithArgs("ncu-184-router-pilot").WillReturnRows(
		sqlmock.NewRows([]string{"enabled", "updated_at", "error"}).AddRow(4, now.Add(-time.Second), nil),
	)
	mock.ExpectQuery(`FROM stream_source_cutovers`).WithArgs("ncu-184-router-pilot").WillReturnRows(
		sqlmock.NewRows([]string{"epoch", "accepted_at", "projected_at"}).AddRow("fixed-epoch", now.Add(-10*time.Minute), now.Add(-time.Second)),
	)
	got := passiveStreamCaptureHealth(context.Background(), db, "ncu-184-router-pilot")
	if got.Status != "delayed" || got.ProcessingLagSeconds == nil || *got.ProcessingLagSeconds < 8*60 {
		t.Fatalf("last completed segment delay hidden: %+v", got)
	}
	if got.SourceEpoch != "fixed-epoch" || got.LastProjectedInputAt == "" || got.ProcessedAt == "" || got.SourceProgressStatus != "unverified" {
		t.Fatalf("projection watermark or source limit missing: %+v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveStreamCaptureHealthShowsProjectionWhileCaptureStale(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`FROM discovery_protocol_runtime`).WithArgs("ncu-184-router-pilot").WillReturnRows(
		sqlmock.NewRows([]string{"enabled", "updated_at", "error"}).AddRow(4, time.Now().Add(-time.Hour), nil),
	)
	mock.ExpectQuery(`FROM stream_source_cutovers`).WithArgs("ncu-184-router-pilot").WillReturnRows(
		sqlmock.NewRows([]string{"epoch", "accepted_at", "projected_at"}).AddRow("fixed-epoch", time.Now().Add(-10*time.Minute), time.Now().Add(-time.Second)),
	)
	got := passiveStreamCaptureHealth(context.Background(), db, "ncu-184-router-pilot")
	if got.Status != "stale" || got.Error == "" || got.ProcessedAt == "" || got.ProcessingLagSeconds == nil {
		t.Fatalf("recovery pause hidden: %+v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveStreamCaptureHealthDoesNotCallOldProjectionReady(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery(`FROM discovery_protocol_runtime`).WithArgs("ncu-184-router-pilot").WillReturnRows(
		sqlmock.NewRows([]string{"enabled", "updated_at", "error"}).AddRow(4, now.Add(-time.Second), nil),
	)
	mock.ExpectQuery(`FROM stream_source_cutovers`).WithArgs("ncu-184-router-pilot").WillReturnRows(
		sqlmock.NewRows([]string{"epoch", "accepted_at", "projected_at"}).AddRow("fixed-epoch", now.Add(-time.Hour-time.Second), now.Add(-time.Hour)),
	)
	got := passiveStreamCaptureHealth(context.Background(), db, "ncu-184-router-pilot")
	if got.Status != "unknown" || got.SourceProgressStatus != "unverified" || got.ProcessingLagSeconds == nil || *got.ProcessingLagSeconds > 5 {
		t.Fatalf("old projection misreported as current or failed: %+v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPassiveStreamHealthIncludesRouterAssetReadSource(t *testing.T) {
	for _, c := range []struct {
		discovery, router string
		want              bool
	}{
		{"", "", false},
		{"stream", "", true},
		{"", "stream", true},
		{"shadow", "stream", true},
		{"shadow", "shadow", false},
	} {
		t.Setenv("PROXY_SENTINEL_DISCOVERY_CURRENT_SOURCE", c.discovery)
		t.Setenv("PROXY_SENTINEL_ROUTER_ASSET_CURRENT_SOURCE", c.router)
		if got := passiveStreamCurrentReadEnabled(); got != c.want {
			t.Fatalf("discovery=%q router=%q got=%t want=%t", c.discovery, c.router, got, c.want)
		}
	}
}
