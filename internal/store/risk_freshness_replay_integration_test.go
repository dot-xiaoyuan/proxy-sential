package store

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

func ownedRiskFreshnessReplayStore(t *testing.T) (*PostgresStore, context.Context) {
	t.Helper()
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_acceptance_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires an owned isolated replay database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	if _, err = ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, ctx
}

func TestRiskObservationAgeThroughStorageReplay(t *testing.T) {
	s, ctx := ownedRiskFreshnessReplayStore(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	observed := now.Add(-7 * time.Minute)
	ip := "192.0.2.93"
	events := []normalized.Event{
		{EventID: "fixture-rule-old", Type: "alert", Timestamp: observed.Format(time.RFC3339Nano), Subject: map[string]any{"ip": ip}, Payload: map[string]any{"signature": "ET POLICY OpenVPN Client Connection", "metadata": []string{"proxy_sentinel_confidence high", "source proxy-sentinel"}}},
		{EventID: "fixture-normal-same-host", Type: "flow", Timestamp: now.Format(time.RFC3339Nano), Subject: map[string]any{"ip": ip}},
		{EventID: "fixture-normal-other-host", Type: "flow", Timestamp: now.Format(time.RFC3339Nano), Subject: map[string]any{"ip": "192.0.2.94"}},
	}
	var input bytes.Buffer
	for _, event := range events {
		if err := json.NewEncoder(&input).Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	proofs, err := evidence.Analyze(&input, evidence.Options{Window: 10 * time.Minute})
	if err != nil || len(proofs.Evidence) != 1 {
		t.Fatal("fixture strong evidence lost", proofs, err)
	}
	raw, err := json.Marshal(proofs)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := risk.Batch(bytes.NewReader(raw))
	if err != nil || len(batch.Snapshots) != 1 {
		t.Fatal("fixture risk lost", batch, err)
	}
	if err := s.WriteEvidence(ctx, proofs.Evidence); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteRiskSnapshots(ctx, batch.Snapshots); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetIPRisk(ctx, ip)
	gotAt, parseErr := time.Parse(time.RFC3339Nano, got.UpdatedAt)
	if err != nil || parseErr != nil || !gotAt.Equal(observed) {
		t.Errorf("aggregate/score/store chain renewed old evidence: %s, %v, %v", got.UpdatedAt, err, parseErr)
	}
	// Simulate the later expiry cutoff without changing any stored timestamps.
	if err := s.ExpireRiskSnapshots(ctx, observed.Add(time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	var active, history, original int
	if err := s.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM risk_snapshots WHERE ip=$1::inet),(SELECT count(*) FROM risk_snapshot_history WHERE ip=$1::inet),(SELECT count(*) FROM evidence WHERE ip=$1::inet)`, ip).Scan(&active, &history, &original); err != nil || active != 0 || history != 1 || original != 1 {
		t.Fatalf("expiry must remove only current materialization: %d, %d, %d, %v", active, history, original, err)
	}
}

func TestRiskLateReplayPreservesCurrentEvidence(t *testing.T) {
	s, ctx := ownedRiskFreshnessReplayStore(t)
	newAt := time.Now().UTC().Truncate(time.Microsecond)
	oldAt := newAt.Add(-time.Minute)
	for _, subject := range []string{"ip", "account"} {
		t.Run(subject, func(t *testing.T) {
			id := "192.0.2.91"
			if subject == "account" {
				id = "fixture-freshness-account"
			}
			latest := risk.Snapshot{IP: "192.0.2.91", SubjectType: subject, SubjectID: id, Score: 95, Level: "high", Confidence: .96, Window: "10m", EvidenceIDs: []string{"new-evidence"}, Summary: "最新证据", RecommendedAction: "shadow_manual_review", UpdatedAt: newAt.Format(time.RFC3339Nano), AssessmentLevel: "high", ReviewDisposition: "benign", AutomationBlockers: []string{}, IndependentSignalGroups: []string{"protocol_rule"}, DetectionBasis: "explicit_tunnel"}
			if err := s.WriteRiskSnapshots(ctx, []risk.Snapshot{latest}); err != nil {
				t.Fatal(err)
			}
			late := latest
			late.Score, late.Level, late.AssessmentLevel = 0, "normal", "normal"
			late.EvidenceIDs, late.UpdatedAt = []string{"old-evidence"}, oldAt.Format(time.RFC3339Nano)
			if err := s.WriteRiskSnapshots(ctx, []risk.Snapshot{late}); err != nil {
				t.Fatal(err)
			}
			current, err := s.currentRiskSnapshots(ctx)
			if err != nil {
				t.Fatal(err)
			}
			got := current[riskKey(latest)]
			gotAt, parseErr := time.Parse(time.RFC3339Nano, got.UpdatedAt)
			if parseErr != nil || got.Score != 95 || !gotAt.Equal(newAt) || len(got.EvidenceIDs) != 1 || got.EvidenceIDs[0] != "new-evidence" || got.ReviewDisposition != "benign" {
				t.Errorf("late replay replaced current risk evidence: %+v", got)
			}
			var history int
			if subject == "ip" {
				err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM risk_snapshot_history WHERE ip=$1::inet`, latest.IP).Scan(&history)
			} else {
				err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM subject_risk_snapshot_history WHERE subject_type=$1 AND subject_id=$2`, subject, id).Scan(&history)
			}
			if err != nil || history != 2 {
				t.Fatalf("late replay must remain auditable: %d, %v", history, err)
			}
			// A corrected rule can change the interpretation of the same event
			// time. A late stronger result must not resurrect its old risk later.
			corrected := latest
			corrected.Score, corrected.Level, corrected.AssessmentLevel = 0, "normal", "normal"
			corrected.EvidenceIDs = []string{"corrected-evidence"}
			if err := s.WriteRiskSnapshots(ctx, []risk.Snapshot{corrected}); err != nil {
				t.Fatal(err)
			}
			late.Score, late.Level, late.AssessmentLevel = 100, "high", "high"
			if err := s.WriteRiskSnapshots(ctx, []risk.Snapshot{late}); err != nil {
				t.Fatal(err)
			}
			current, err = s.currentRiskSnapshots(ctx)
			if err != nil {
				t.Fatal(err)
			}
			got = current[riskKey(latest)]
			if got.Score != 0 || got.Level != "normal" || len(got.EvidenceIDs) != 1 || got.EvidenceIDs[0] != "corrected-evidence" || got.ReviewDisposition != "benign" {
				t.Fatalf("late stronger result resurrected corrected risk: %+v", got)
			}
		})
	}
}

func TestRiskRecalculationDoesNotRenewEvidenceAge(t *testing.T) {
	s, ctx := ownedRiskFreshnessReplayStore(t)
	ip := "192.0.2.92"
	observed := time.Now().UTC().Add(-20 * time.Minute).Truncate(time.Microsecond)
	if err := s.WriteEvidence(ctx, []evidence.Evidence{{EvidenceID: "freshness-old-proof", IP: ip, Type: "vpn_proxy_rule_match", Window: "10m", Score: 95, Confidence: .96, Severity: "high", Reason: "历史协议证据", Samples: []string{"fixture"}, CreatedAt: observed.Format(time.RFC3339Nano)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecalculateRisks(ctx, time.Hour, "freshness-replay", true); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetIPRisk(ctx, ip)
	if err != nil {
		t.Fatal(err)
	}
	gotAt, parseErr := time.Parse(time.RFC3339Nano, got.UpdatedAt)
	if parseErr != nil || !gotAt.Equal(observed) {
		t.Errorf("recalculation renewed old evidence: observed=%s snapshot=%s", observed.Format(time.RFC3339Nano), got.UpdatedAt)
	}
	if err := s.ExpireRiskSnapshots(ctx, time.Now().UTC().Add(-11*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var active, historical, original int
	if err := s.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM risk_snapshots WHERE ip=$1::inet),(SELECT count(*) FROM risk_snapshot_history WHERE ip=$1::inet),(SELECT count(*) FROM evidence WHERE ip=$1::inet)`, ip).Scan(&active, &historical, &original); err != nil {
		t.Fatal(err)
	}
	if active != 0 || historical < 1 || original != 1 {
		t.Fatalf("old evidence must expire from current view while preserving audit: active=%d history=%d evidence=%d", active, historical, original)
	}
}
