package controlplane

import (
	"proxy-sentinel/internal/risk"
	"testing"
	"time"
)

func TestCaseAssessmentCurrentUsesDetectionWindowAndSameEstimate(t *testing.T) {
	now := time.Now().UTC()
	base := RiskCase{IP: "192.0.2.82", RiskScore: 95, RiskConfidence: .95, AssessmentLevel: "high", Status: "investigating", UpdatedAt: now.Format(time.RFC3339Nano)}
	for _, name := range []string{"fresh", "expired", "future", "missing_stamp", "missing_window", "invalid_window", "negative_window", "changed_score", "changed_confidence", "changed_level", "different_ip", "different_account", "different_endpoint", "different_subject", "invalid_subject", "closed", "resolved", "missing_snapshot", "confirmed"} {
		t.Run(name, func(t *testing.T) {
			item := base
			snapshot := risk.Snapshot{IP: base.IP, Score: 95, Confidence: .95, Level: "high", Window: "10m", UpdatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano)}
			want := name == "fresh" || name == "confirmed"
			var current *risk.Snapshot = &snapshot
			switch name {
			case "expired":
				snapshot.UpdatedAt = now.Add(-10 * time.Minute).Format(time.RFC3339Nano)
			case "future":
				snapshot.UpdatedAt = now.Add(time.Second).Format(time.RFC3339Nano)
			case "missing_stamp":
				snapshot.UpdatedAt = ""
			case "missing_window":
				snapshot.Window = ""
			case "invalid_window":
				snapshot.Window = "invalid"
			case "negative_window":
				snapshot.Window = "-10m"
			case "changed_score":
				snapshot.Score = 24
			case "changed_confidence":
				snapshot.Confidence = .81
			case "changed_level":
				snapshot.Level = "suspicious"
			case "different_ip":
				snapshot.IP = "192.0.2.83"
			case "different_account":
				snapshot.AccountID = "other-owner"
			case "different_endpoint":
				snapshot.EndpointID = "other-device"
			case "invalid_subject":
				snapshot.SubjectType = "invalid"
			case "different_subject":
				snapshot.SubjectType = "account"
				snapshot.SubjectID = "other-owner"
			case "closed", "resolved":
				item.Status = name
			case "missing_snapshot":
				current = nil
			case "confirmed":
				snapshot.Level = "confirmed"
			}
			got := projectCaseAssessment(item, current, now)
			if got.AssessmentCurrent != want || got.RiskScore != item.RiskScore || got.RiskConfidence != item.RiskConfidence || got.Status != item.Status || got.UpdatedAt != item.UpdatedAt {
				t.Fatalf("projection altered assessment/history: %+v", got)
			}
		})
	}
}

func TestCaseAssessmentCurrentRequiresSameCompleteSubject(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, caseAccount, caseEndpoint, riskAccount, riskEndpoint, subjectType, subjectID string
		want                                                                               bool
	}{
		{"account_disappeared", "account-old", "", "", "", "ip", "192.0.2.82", false},
		{"endpoint_disappeared", "", "endpoint-old", "", "", "ip", "192.0.2.82", false},
		{"empty_account_subject", "", "", "", "", "account", "", false},
		{"empty_endpoint_subject", "", "", "", "", "endpoint", "", false},
		{"matching_account_subject", "account-current", "", "account-current", "", "account", "account-current", true},
		{"matching_endpoint_subject", "", "endpoint-current", "", "endpoint-current", "endpoint", "endpoint-current", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := RiskCase{IP: "192.0.2.82", AccountID: tc.caseAccount, EndpointID: tc.caseEndpoint, Status: "investigating", AssessmentLevel: "high", RiskScore: 95, RiskConfidence: .95}
			snapshot := risk.Snapshot{IP: item.IP, AccountID: tc.riskAccount, EndpointID: tc.riskEndpoint, SubjectType: tc.subjectType, SubjectID: tc.subjectID, Level: "high", Score: 95, Confidence: .95, UpdatedAt: now.Format(time.RFC3339Nano), Window: "10m"}
			got := projectCaseAssessment(item, &snapshot, now)
			if got.AssessmentCurrent != tc.want {
				t.Errorf("current=%v want=%v", got.AssessmentCurrent, tc.want)
			}
			if got.AccountID != item.AccountID || got.EndpointID != item.EndpointID || got.RiskScore != 95 || got.Status != item.Status {
				t.Fatal("projection rewrote retained case", got)
			}
		})
	}
}

func TestCaseAssessmentCurrentRejectsMismatchedCaseSubject(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct{ name, kind, id string }{
		{"account_subject_changed", "account", "other-account"},
		{"endpoint_subject_changed", "endpoint", "other-endpoint"},
		{"ip_subject_changed", "ip", "192.0.2.83"},
		{"unsupported_subject", "device", "physical-id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := RiskCase{IP: "192.0.2.82", SubjectType: tc.kind, SubjectID: tc.id, AccountID: "account-current", EndpointID: "endpoint-current", Status: "new", AssessmentLevel: "high", RiskScore: 95, RiskConfidence: .95}
			snapshot := risk.Snapshot{IP: item.IP, SubjectType: "endpoint", SubjectID: item.EndpointID, AccountID: item.AccountID, EndpointID: item.EndpointID, Level: "high", Score: 95, Confidence: .95, UpdatedAt: now.Format(time.RFC3339Nano), Window: "10m"}
			if got := projectCaseAssessment(item, &snapshot, now); got.AssessmentCurrent {
				t.Fatal("mismatched retained subject borrowed a fresh assessment", got)
			}
		})
	}
}
