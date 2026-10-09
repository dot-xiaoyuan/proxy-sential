package store

import (
	"proxy-sentinel/internal/sharedaccess"
	"testing"
	"time"
)

func TestSharedBehaviorHistoryBasisReplay(t *testing.T) {
	s, ctx := ownedRiskFreshnessReplayStore(t)
	dbs := &DBStore{pg: s}
	now := time.Now().UTC().Truncate(time.Microsecond)
	base := sharedaccess.BehaviorAssessment{SensorID: "history-basis", IP: "192.0.2.22", EndpointID: "mac:22", RuleVersion: "shared-behavior/v10", Status: "confirmed", Confidence: 90, CoverageState: "verified", StrongAnchor: "ieee1905_association", DeviceLowerBound: 2, SignalGroups: []string{"ieee1905_association"}, FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-time.Hour), WindowStart: now.Add(-70 * time.Minute), WindowEnd: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}
	for _, kind := range []string{"strong", "candidate", "old-confirmed", "unsupported-anchor", "partial", "conflict"} {
		item := base
		item.ObservationID = kind
		switch kind {
		case "candidate":
			item.Status, item.Confidence, item.StrongAnchor, item.DeviceLowerBound = "candidate", 59, "", 0
		case "old-confirmed":
			item.RuleVersion, item.StrongAnchor, item.DeviceLowerBound = "shared-behavior/v8", "", 0
		case "unsupported-anchor":
			item.StrongAnchor = "router_identity"
		case "partial":
			item.CoverageState = "partial"
		case "conflict":
			item.Conflicts = []string{"identity_conflict"}
		}
		// A later weak observation at the same IP must not hide the earlier
		// strong historical episode in the default history view.
		if kind != "strong" {
			item.LastSeen = now.Add(-30 * time.Minute)
		}
		if err := dbs.persistSharedBehavior(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ListSharedBehavior(ctx, SharedBehaviorQuery{View: "history"})
	if err != nil || page.Page.Total != 1 || len(page.Items) != 1 || page.Items[0].ObservationID != "strong" || page.Items[0].Current {
		t.Fatalf("weak historical records entered default sharing history: %+v %v", page, err)
	}
	clues, err := s.ListSharedBehavior(ctx, SharedBehaviorQuery{View: "history", HistoryBasis: "clues"})
	if err != nil || clues.Page.Total != 1 || len(clues.Items) != 1 || clues.Items[0].ObservationID == "strong" || clues.Items[0].Current {
		t.Fatalf("explicit clue review lost records or revived sharing: %+v %v", clues, err)
	}
	// Inspect each weak kind independently; filters apply before episode deduplication.
	for _, kind := range []string{"candidate", "old-confirmed", "unsupported-anchor", "partial", "conflict"} {
		page, err = s.ListSharedBehavior(ctx, SharedBehaviorQuery{View: "history", HistoryBasis: "clues", Keyword: kind})
		if err != nil || len(page.Items) != 1 || page.Items[0].ObservationID != kind {
			t.Fatalf("clue missing %s: %+v %v", kind, page, err)
		}
	}
	var count int
	if err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM shared_behavior_observations").Scan(&count); err != nil || count != 6 {
		t.Fatalf("history view changed audit evidence: %d %v", count, err)
	}
}

func TestSharedBehaviorHistoryBasisValidation(t *testing.T) {
	for _, q := range []SharedBehaviorQuery{{View: "history", HistoryBasis: "all"}, {HistoryBasis: "clues"}} {
		if _, _, err := sharedBehaviorWhere(q); err == nil {
			t.Fatalf("invalid history basis accepted: %+v", q)
		}
	}
}
