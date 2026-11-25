package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"
)

var ErrReportPreparing = errors.New("discovery report has no published result")

type ReportPublication struct {
	BucketStart time.Time `json:"bucket_start"`
	PublishedAt time.Time `json:"published_at"`
	Delayed     bool      `json:"delayed"`
}

func publishedWindow(window time.Duration) bool {
	return window == 24*time.Hour || window == 168*time.Hour || window == 720*time.Hour
}

func defaultMetadataScope(q DeviceQuery) bool {
	q.structured = true
	return q.IdentityScope == "devices" && !q.Export && q.SnapshotAt.IsZero() && cachedGroupWindow(q) > 0
}

func (r Repository) readPublication(ctx context.Context, sensor, report string, window time.Duration, dst any) (*ReportPublication, error) {
	var raw []byte
	p := new(ReportPublication)
	err := r.DB.QueryRowContext(ctx, `SELECT document,bucket_start,published_at,
		bucket_start + interval '10 minutes' <= now()
		FROM discovery_report_publications WHERE sensor_id=$1 AND report=$2 AND hours=$3`, sensor, report, int(window.Hours())).Scan(&raw, &p.BucketStart, &p.PublishedAt, &p.Delayed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrReportPreparing
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, dst); err != nil {
		return nil, err
	}
	return p, nil
}

func (r Repository) ReadDeviceMetadata(ctx context.Context, sensor string, q DeviceQuery) (IndexedDeviceMetadata, error) {
	if !r.HardwareV2 || !structuredReadEnabled("published_metadata") || !defaultMetadataScope(q) {
		return r.DevicesIndexedMetadata(ctx, q)
	}
	var out IndexedDeviceMetadata
	p, err := r.readPublication(ctx, sensor, "metadata", q.Window, &out)
	out.Publication = p
	if q.SkipOverview {
		out.Overview = nil
	}
	return out, err
}

func (r Repository) ReadCoverageReport(ctx context.Context, sensor string, window time.Duration) (CoverageReport, error) {
	if !r.HardwareV2 || !structuredReadEnabled("published_coverage") || !publishedWindow(window) {
		return r.DiscoveryCoverageReport(ctx, sensor, window)
	}
	var out CoverageReport
	p, err := r.readPublication(ctx, sensor, "coverage", window, &out)
	out.Publication = p
	return out, err
}

// One publication at a time per worker. A transaction-scoped lock also covers
// overlapping process lifetimes during restarts. Readers only access committed rows.
func (r Repository) publishReport(ctx context.Context, sensor, report string, window time.Duration) error {
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	hours := int(window.Hours())
	var bucket time.Time
	var due bool
	err = tx.QueryRowContext(ctx, `WITH cadence AS (SELECT date_bin(interval '5 minutes',now(),timestamptz '2000-01-01Z') AS bucket)
	SELECT bucket,NOT EXISTS(SELECT 1 FROM discovery_report_publications WHERE sensor_id=$1 AND report=$2 AND hours=$3 AND bucket_start>=bucket)
	AND pg_try_advisory_xact_lock(hashtextextended(concat_ws('/',current_schema(),$1::text,$2::text,$3::integer),1)) FROM cadence`, sensor, report, hours).Scan(&bucket, &due)
	if err != nil || !due {
		return err
	}
	var doc any
	var asOf time.Time
	switch report {
	case "metadata":
		meta, err := r.devicesIndexedMetadata(ctx, tx, DeviceQuery{Window: window, Mode: "passive", IdentityScope: "devices"}, true)
		if err != nil {
			return err
		}
		if err = tx.QueryRowContext(ctx, "SELECT cursor_timestamp FROM passive_discovery_state WHERE sensor_id=$1 AND last_success_at IS NOT NULL", sensor).Scan(&meta.AsOf); err != nil {
			return err
		}
		doc, asOf = meta, meta.AsOf
	case "coverage":
		coverage, err := r.DiscoveryCoverageReport(ctx, sensor, window)
		if err != nil {
			return err
		}
		if coverage.IdentityStatus == "timeout" {
			return fmt.Errorf("coverage identities: %w", context.DeadlineExceeded)
		}
		if hours == 168 || hours == 720 {
			trendCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			trend, trendErr := hardwareTrend(trendCtx, r.DB, sensor, coverage.AsOf, window)
			cancel()
			if trendErr != nil {
				log.Printf("hardware trend %s %dh: %v", sensor, hours, trendErr)
			} else {
				coverage.HardwareTrend = trend
			}
		}
		rangeCtx, cancelRanges := context.WithTimeout(ctx, 3*time.Second)
		planned, rangeErr := readPlannedIPv4(rangeCtx, r.DB, sensor, window, os.Getenv("PROXY_SENTINEL_CENSUS_REPORT_RANGES"))
		cancelRanges()
		if rangeErr != nil {
			log.Printf("planned IPv4 coverage %s %dh: %v", sensor, hours, rangeErr)
		}
		coverage.PlannedIPv4 = planned
		doc, asOf = coverage, coverage.AsOf
	default:
		return fmt.Errorf("invalid discovery publication %q", report)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO discovery_report_publications(sensor_id,report,hours,bucket_start,as_of,document)
		VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(sensor_id,report,hours)
		DO UPDATE SET bucket_start=excluded.bucket_start,as_of=excluded.as_of,published_at=excluded.published_at,document=excluded.document
		WHERE discovery_report_publications.bucket_start<excluded.bucket_start`, sensor, report, hours, bucket, asOf, raw)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r Repository) RunReportPublisher(ctx context.Context, sensor string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		for _, hours := range []int{24, 168, 720} {
			for _, report := range []string{"metadata", "coverage"} {
				job, cancel := context.WithTimeout(ctx, 45*time.Second)
				err := r.publishReport(job, sensor, report, time.Duration(hours)*time.Hour)
				cancel()
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					log.Printf("discovery report publication %s %dh: %v", report, hours, err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
