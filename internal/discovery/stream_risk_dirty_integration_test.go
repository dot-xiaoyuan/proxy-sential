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
		`CREATE TEMP TABLE risk_feature_segment_receipts(segment_id text PRIMARY KEY,segment_sha256 text NOT NULL,source_epoch text NOT NULL,accepted_at timestamptz NOT NULL,skipped_old_subjects integer NOT NULL DEFAULT 0,skipped_old_max_window_seconds integer)`,
		`CREATE TEMP TABLE risk_feature_dirty_subjects(sensor_id text NOT NULL,subject_type text NOT NULL,subject_id text NOT NULL,generation bigint NOT NULL,first_dirty_at timestamptz NOT NULL DEFAULT now(),last_dirty_at timestamptz NOT NULL DEFAULT now(),last_observed_at timestamptz NOT NULL,claim_until timestamptz,claimed_generation bigint,PRIMARY KEY(sensor_id,subject_type,subject_id))`,
		`CREATE TEMP TABLE stream_risk_fresh_cutovers(sensor_id text PRIMARY KEY,accepted_after timestamptz NOT NULL)`,
		`CREATE TEMP TABLE stream_risk_window_policies(sensor_id text PRIMARY KEY,active_window_seconds integer NOT NULL,safe_skip_seconds integer NOT NULL,lease_until timestamptz NOT NULL)`,
		`CREATE TEMP TABLE stream_risk_current(sensor_id text NOT NULL,subject_type text NOT NULL,subject_id text NOT NULL,PRIMARY KEY(sensor_id,subject_type,subject_id))`,
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

func TestOldPacketWakeRequiresLiveWindowAndAbsentCurrentStatePostgres(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, ddl := range []string{
		`CREATE TEMP SEQUENCE risk_feature_dirty_generation`,
		`CREATE TEMP TABLE risk_feature_segment_receipts(segment_id text PRIMARY KEY,segment_sha256 text NOT NULL,source_epoch text NOT NULL,accepted_at timestamptz NOT NULL,skipped_old_subjects integer NOT NULL DEFAULT 0,skipped_old_max_window_seconds integer)`,
		`CREATE TEMP TABLE risk_feature_dirty_subjects(sensor_id text NOT NULL,subject_type text NOT NULL,subject_id text NOT NULL,generation bigint NOT NULL,first_dirty_at timestamptz NOT NULL DEFAULT now(),last_dirty_at timestamptz NOT NULL DEFAULT now(),last_observed_at timestamptz NOT NULL,claim_until timestamptz,claimed_generation bigint,PRIMARY KEY(sensor_id,subject_type,subject_id))`,
		`CREATE TEMP TABLE stream_risk_fresh_cutovers(sensor_id text PRIMARY KEY,accepted_after timestamptz NOT NULL)`,
		`CREATE TEMP TABLE stream_risk_window_policies(sensor_id text PRIMARY KEY,active_window_seconds integer NOT NULL,safe_skip_seconds integer NOT NULL,lease_until timestamptz NOT NULL)`,
		`CREATE TEMP TABLE stream_risk_current(sensor_id text NOT NULL,subject_type text NOT NULL,subject_id text NOT NULL,PRIMARY KEY(sensor_id,subject_type,subject_id))`,
	} {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_risk_window_policies VALUES('sensor-a',1800,1800,statement_timestamp()+interval '1 minute')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_risk_current VALUES('sensor-a','ip','192.0.2.4')`); err != nil {
		t.Fatal(err)
	}
	projector := StreamDiscoveryProjector{DB: db}
	queue := func(id, source, ip string, observed time.Time, extra ...normalized.Event) (int, int) {
		t.Helper()
		events := []normalized.Event{{Type: "device", Source: source, Timestamp: observed.Format(time.RFC3339Nano),
			Observer: map[string]any{"sensor_id": "sensor-a"}, Subject: map[string]any{"ip": ip}}}
		events = append(events, extra...)
		segment := streamlog.Segment{Epoch: "fixed-new", AcceptedAt: now, Events: events}
		if err := projector.MarkStreamRiskSubjectsDirty(ctx, id, segment); err != nil {
			t.Fatal(err)
		}
		var skipped, queued int
		if err := db.QueryRowContext(ctx, `SELECT skipped_old_subjects FROM risk_feature_segment_receipts WHERE segment_id=$1`, id).Scan(&skipped); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM risk_feature_dirty_subjects WHERE sensor_id='sensor-a' AND subject_id=$1`, ip).Scan(&queued); err != nil {
			t.Fatal(err)
		}
		return skipped, queued
	}
	old := now.Add(-time.Hour)
	if skipped, queued := queue("old-packet", "packet-sidecar", "192.0.2.1", old); skipped != 1 || queued != 0 {
		t.Fatalf("old packet-only wake: skipped=%d queued=%d", skipped, queued)
	}
	if skipped, queued := queue("fresh-packet", "packet-sidecar", "192.0.2.2", now); skipped != 0 || queued != 1 {
		t.Fatalf("fresh packet wake: skipped=%d queued=%d", skipped, queued)
	}
	if skipped, queued := queue("old-zeek", "zeek", "192.0.2.3", old); skipped != 0 || queued != 1 {
		t.Fatalf("old nonpacket wake: skipped=%d queued=%d", skipped, queued)
	}
	if skipped, queued := queue("old-with-current", "packet-sidecar", "192.0.2.4", old); skipped != 0 || queued != 1 {
		t.Fatalf("old packet with current risk: skipped=%d queued=%d", skipped, queued)
	}
	mixed := normalized.Event{Type: "device", Source: "zeek", Timestamp: old.Format(time.RFC3339Nano),
		Observer: map[string]any{"sensor_id": "sensor-a"}, Subject: map[string]any{"ip": "192.0.2.5"}}
	if skipped, queued := queue("mixed-source", "packet-sidecar", "192.0.2.5", old, mixed); skipped != 0 || queued != 1 {
		t.Fatalf("cross-source wake: skipped=%d queued=%d", skipped, queued)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO stream_risk_fresh_cutovers VALUES('sensor-a',$1)`, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if skipped, queued := queue("pre-cutover", "packet-sidecar", "192.0.2.7", old); skipped != 0 || queued != 0 {
		t.Fatalf("pre-cutover suppression was attributed to the window: skipped=%d queued=%d", skipped, queued)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM stream_risk_fresh_cutovers WHERE sensor_id='sensor-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE stream_risk_window_policies SET lease_until=statement_timestamp()-interval '1 second' WHERE sensor_id='sensor-a'`); err != nil {
		t.Fatal(err)
	}
	if skipped, queued := queue("expired-policy", "packet-sidecar", "192.0.2.6", old); skipped != 0 || queued != 1 {
		t.Fatalf("expired policy must fail open: skipped=%d queued=%d", skipped, queued)
	}
	if skipped, queued := queue("old-packet", "packet-sidecar", "192.0.2.1", old); skipped != 1 || queued != 0 {
		t.Fatalf("receipt replay must preserve the first decision: skipped=%d queued=%d", skipped, queued)
	}
}
