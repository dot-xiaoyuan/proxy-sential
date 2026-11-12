package discovery

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestRiskDirtyGenerationCoalescesOnlyUnclaimedWork(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires owned isolated database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, ddl := range []string{
		`CREATE TEMP SEQUENCE risk_feature_dirty_generation`,
		`CREATE TEMP TABLE risk_feature_segment_receipts(segment_id text PRIMARY KEY,segment_sha256 text NOT NULL,source_epoch text NOT NULL,accepted_at timestamptz NOT NULL)`,
		`CREATE TEMP TABLE risk_feature_dirty_subjects(sensor_id text NOT NULL,subject_type text NOT NULL,subject_id text NOT NULL,generation bigint NOT NULL,first_dirty_at timestamptz NOT NULL DEFAULT now(),last_dirty_at timestamptz NOT NULL DEFAULT now(),last_observed_at timestamptz NOT NULL,claim_until timestamptz,claimed_generation bigint,PRIMARY KEY(sensor_id,subject_type,subject_id))`,
		`CREATE TEMP TABLE stream_risk_fresh_cutovers(sensor_id text PRIMARY KEY,accepted_after timestamptz NOT NULL)`,
	} {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	projector := StreamDiscoveryProjector{DB: db}
	base := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	queue := func(id string, at time.Time) {
		t.Helper()
		segment := streamlog.Segment{Epoch: "fresh", AcceptedAt: at, Events: []normalized.Event{{
			Type: "device", Timestamp: at.Format(time.RFC3339Nano),
			Observer: map[string]any{"sensor_id": "sensor-a"}, Subject: map[string]any{"ip": "192.0.2.8"},
		}}}
		if err := projector.MarkStreamRiskSubjectsDirty(ctx, id, segment); err != nil {
			t.Fatal(err)
		}
	}
	queue("segment-a", base)
	var first, second, third int64
	if err := db.QueryRowContext(ctx, `SELECT generation FROM risk_feature_dirty_subjects WHERE sensor_id='sensor-a' AND subject_type='ip'`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	queue("segment-b", base.Add(time.Second))
	if err := db.QueryRowContext(ctx, `SELECT generation FROM risk_feature_dirty_subjects WHERE sensor_id='sensor-a' AND subject_type='ip'`).Scan(&second); err != nil || second != first {
		t.Fatalf("unclaimed work created another generation: %d -> %d, %v", first, second, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE risk_feature_dirty_subjects SET claimed_generation=generation,claim_until=now()+interval '1 minute' WHERE sensor_id='sensor-a'`); err != nil {
		t.Fatal(err)
	}
	queue("segment-c", base.Add(2*time.Second))
	if err := db.QueryRowContext(ctx, `SELECT generation FROM risk_feature_dirty_subjects WHERE sensor_id='sensor-a' AND subject_type='ip'`).Scan(&third); err != nil || third <= second {
		t.Fatalf("claimed work lost later change: %d -> %d, %v", second, third, err)
	}
	queue("segment-c", base.Add(2*time.Second))
	var replay int64
	if err := db.QueryRowContext(ctx, `SELECT generation FROM risk_feature_dirty_subjects WHERE sensor_id='sensor-a' AND subject_type='ip'`).Scan(&replay); err != nil || replay != third {
		t.Fatalf("segment replay created another generation: %d -> %d, %v", third, replay, err)
	}
}
