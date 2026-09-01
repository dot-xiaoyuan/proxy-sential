package store

import (
	"context"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
)

func TestRiskRecalculationProducesComparisonAndArchivesBeforeApply(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	postgres, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer postgres.Close()
	ip := "192.0.2.88"
	_, _ = postgres.db.ExecContext(ctx, `DELETE FROM evidence WHERE ip=$1::inet`, ip)
	_, _ = postgres.db.ExecContext(ctx, `DELETE FROM risk_snapshots WHERE ip=$1::inet`, ip)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := postgres.WriteEvidence(ctx, []evidence.Evidence{{EvidenceID: "recalc-strong-1", IP: ip, SubjectType: "ip", SubjectID: ip, Type: "vpn_proxy_rule_match", Window: "10m", Score: 95, Confidence: .96, Severity: "high", Reason: "明确代理规则", Samples: []string{"OpenVPN"}, CreatedAt: now}}); err != nil {
		t.Fatal(err)
	}
	if err := postgres.WriteRiskSnapshots(ctx, []risk.Snapshot{{IP: ip, SubjectType: "ip", SubjectID: ip, Score: 10, Level: "normal", Confidence: .2, Window: "10m", EvidenceIDs: []string{}, Summary: "旧规则", RecommendedAction: "record", UpdatedAt: now, AssessmentLevel: "normal", ReviewDisposition: "benign"}}); err != nil {
		t.Fatal(err)
	}
	report, err := postgres.RecalculateRisks(ctx, 7*24*time.Hour, "integration-v2", true)
	if err != nil {
		t.Fatal(err)
	}
	if report.ChangedCount == 0 || !report.Applied {
		t.Fatalf("unexpected recalculation report: %#v", report)
	}
	updated, err := postgres.GetIPRisk(ctx, ip)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Score <= 10 || updated.ReviewDisposition != "benign" {
		t.Fatalf("recalculation did not preserve disposition: %#v", updated)
	}
	var history int
	if err := postgres.db.QueryRowContext(ctx, `SELECT count(*) FROM risk_snapshot_history WHERE ip=$1::inet`, ip).Scan(&history); err != nil {
		t.Fatal(err)
	}
	if history < 2 {
		t.Fatalf("expected archived old and new snapshots, got %d", history)
	}
}
