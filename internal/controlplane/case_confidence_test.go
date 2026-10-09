package controlplane

import (
	"context"
	"testing"

	"proxy-sentinel/internal/sharedaccess"
)

func TestSharedCaseConfidenceUsesConfirmedAssessment(t *testing.T) {
	s, r, assessment := caseSyncFixture()
	assessment.Confidence = 81
	r.shared = []sharedaccess.BehaviorAssessment{assessment}
	if err := s.syncCasesContext(context.Background(), "test", "10m"); err != nil {
		t.Fatal(err)
	}
	for _, item := range s.operations.doc.Cases {
		if item.RiskConfidence != .81 {
			t.Fatalf("case confidence=%v want=.81", item.RiskConfidence)
		}
	}
}
