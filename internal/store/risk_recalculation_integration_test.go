package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/sharedaccess"
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
	windowEnd := time.Now().UTC()
	window := &sharedaccess.Window{Complete: true, CoverageVerified: true, From: windowEnd.Add(-10 * time.Minute), To: windowEnd}
	assessment := sharedaccess.BehaviorAssessment{ObservationID: "recalc-shared-anchor", GenerationID: "generation-integration", SensorID: "integration", IP: ip, Status: "confirmed", Confidence: 90, CoverageState: "verified", RuleVersion: sharedaccess.BehaviorRuleVersion, FirstSeen: window.From, LastSeen: windowEnd, WindowStart: window.From, WindowEnd: windowEnd, ExpiresAt: windowEnd.Add(time.Hour), StrongAnchor: "ieee1905_association", DeviceLowerBound: 2}
	assessmentJSON, _ := json.Marshal(assessment)
	if _, err = postgres.db.ExecContext(ctx, `INSERT INTO shared_behavior_observations(
observation_id,sensor_id,campus_id,access_domain,ip,status,confidence,rule_version,coverage_state,first_seen,last_seen,window_start,window_end,expires_at,observation,generation_id,current)
VALUES($1,$2,'','',$3::inet,'confirmed',90,$4,'verified',$5,$6,$5,$6,$7,$8,$9,true)
ON CONFLICT(observation_id) DO UPDATE SET observation=EXCLUDED.observation,generation_id=EXCLUDED.generation_id,current=true,status='confirmed',coverage_state='verified'`, assessment.ObservationID, assessment.SensorID, ip, assessment.RuleVersion, assessment.WindowStart, assessment.WindowEnd, assessment.ExpiresAt, assessmentJSON, assessment.GenerationID); err != nil {
		t.Fatal(err)
	}
	defer postgres.db.ExecContext(context.Background(), `DELETE FROM shared_behavior_observations WHERE observation_id=$1`, assessment.ObservationID)
	if err := postgres.WriteEvidence(ctx, []evidence.Evidence{
		{EvidenceID: "recalc-vpn-retained", IP: ip, SubjectType: "ip", SubjectID: ip, Type: "vpn_proxy_rule_match", Window: "10m", Score: 100, Confidence: 1, Severity: "high", Reason: "VPN evidence retained", Samples: []string{"WireGuard"}, CreatedAt: now},
		{EvidenceID: "recalc-shared-anchor", IP: ip, SubjectType: "ip", SubjectID: ip, Type: "shared_access_window", Window: "10m", Score: 90, Confidence: .9, Severity: "high", Reason: "current shared anchor", CreatedAt: now, SharedAccess: window, RiskKind: "shared_access", StrongAnchor: "ieee1905_association", DeviceLowerBound: 2, CoverageState: "verified", GenerationID: "generation-integration"},
	}); err != nil {
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
	if updated.RiskKind != "shared_access" || updated.StrongAnchor != "ieee1905_association" || updated.ReviewDisposition != "benign" {
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
