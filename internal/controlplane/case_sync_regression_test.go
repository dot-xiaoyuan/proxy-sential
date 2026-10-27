package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
)

type caseSyncReader struct {
	store.Reader
	shared    []sharedaccess.BehaviorAssessment
	sharedErr error
}

func (r *caseSyncReader) ReadStreamSharedCaseRefs(_ context.Context, observationID, generationID string) ([]store.StreamBodyRef, error) {
	if observationID == "" || generationID == "" {
		return nil, errors.New("missing case source generation")
	}
	return []store.StreamBodyRef{{Epoch: generationID, Class: "evidence", Month: "202610", Scope: "scope", Key: generationID + ":event-a", SHA256: strings.Repeat("a", 64)}}, nil
}

type routerCaseSyncReader struct {
	*caseSyncReader
	routers []evidence.RouterAssessment
}

func (r *routerCaseSyncReader) ListRouterObservations(context.Context, store.RouterQuery) (store.RouterAssessmentPage, error) {
	return store.RouterAssessmentPage{Items: r.routers, Page: store.Page{Limit: 100, Total: len(r.routers)}}, nil
}

func (r *routerCaseSyncReader) GetRouterObservation(context.Context, string) (store.RouterObservationDetail, bool, error) {
	return store.RouterObservationDetail{}, false, nil
}

func (r *caseSyncReader) ListSharedBehavior(context.Context, store.SharedBehaviorQuery) (store.SharedBehaviorPage, error) {
	return store.SharedBehaviorPage{Items: r.shared, Page: store.Page{Limit: 100, Total: len(r.shared)}}, r.sharedErr
}

func (r *caseSyncReader) GetSharedBehavior(context.Context, string) (store.SharedBehaviorDetail, bool, error) {
	return store.SharedBehaviorDetail{}, false, nil
}

func caseSyncFixture() (*Server, *caseSyncReader, sharedaccess.BehaviorAssessment) {
	now := time.Now().UTC()
	assessment := sharedaccess.BehaviorAssessment{
		Current: true, ObservationID: "shared-observation", SensorID: "test",
		CampusID: "campus", AccessDomain: "vlan:20", IP: "192.0.2.82", Status: "confirmed", Confidence: 92,
		CoverageState: "verified", RuleVersion: sharedaccess.BehaviorRuleVersion, StrongAnchor: "ieee1905_association",
		DeviceLowerBound: 2, FirstSeen: now.Add(-10 * time.Minute), LastSeen: now, WindowStart: now.Add(-10 * time.Minute), WindowEnd: now,
		FeatureSamples: map[string]map[string]sharedaccess.FeatureSample{"ieee1905_association": {"client-a": {}, "client-b": {}}},
		EventIDs:       []string{"event-a", "event-b"},
	}
	r := &caseSyncReader{shared: []sharedaccess.BehaviorAssessment{assessment}}
	s := &Server{reader: r, operations: &operationsState{doc: emptyOperationsDocument()}, exceptions: newExceptionManager(nil)}
	return s, r, assessment
}

func TestFreshSharedCaseCarriesProtectedSourceReferences(t *testing.T) {
	s, r, assessment := caseSyncFixture()
	assessment.GenerationID = "generation-1"
	r.shared = []sharedaccess.BehaviorAssessment{assessment}
	if err := s.syncCasesContext(context.Background(), "test", "10m"); err != nil {
		t.Fatal(err)
	}
	caseID := proxyReviewCaseForSharedAssessment(assessment).CaseID
	got := s.operations.doc.Cases[caseID]
	if len(got.EvidenceSnapshot.StreamSharedEvidenceRefs) != 1 ||
		len(got.EvidenceHistory) != 1 || len(got.EvidenceHistory[0].Evidence.StreamSharedEvidenceRefs) != 1 {
		t.Fatalf("fresh shared case lost its source originals: %+v", got.EvidenceSnapshot)
	}
	if err := s.syncCasesContext(context.Background(), "test", "10m"); err != nil {
		t.Fatal(err)
	}
	got = s.operations.doc.Cases[caseID]
	if len(got.EvidenceHistory) != 1 || len(got.EvidenceSnapshot.StreamSharedEvidenceRefs) != 1 {
		t.Fatalf("unchanged fresh case rewrote its evidence: %+v", got)
	}
}

func TestCaseSynchronizationOnlyCreatesConfirmedSharedAccess(t *testing.T) {
	s, r, assessment := caseSyncFixture()
	for _, mutate := range []func(*sharedaccess.BehaviorAssessment){
		func(item *sharedaccess.BehaviorAssessment) { item.Status = "likely" },
		func(item *sharedaccess.BehaviorAssessment) { item.CoverageState = "partial" },
		func(item *sharedaccess.BehaviorAssessment) { item.StrongAnchor = "" },
		func(item *sharedaccess.BehaviorAssessment) { item.DeviceLowerBound = 1 },
	} {
		candidate := assessment
		mutate(&candidate)
		r.shared = []sharedaccess.BehaviorAssessment{candidate}
		if err := s.syncCasesContext(context.Background(), "test", "10m"); err != nil {
			t.Fatal(err)
		}
		if len(s.operations.doc.Cases) != 0 {
			t.Fatalf("non-confirmed assessment created a case: %+v", candidate)
		}
	}
	r.shared = []sharedaccess.BehaviorAssessment{assessment}
	if err := s.syncCasesContext(context.Background(), "test", "10m"); err != nil {
		t.Fatal(err)
	}
	for _, item := range s.operations.doc.Cases {
		if item.RiskKind != "shared_access" || item.RiskConfidence != .92 || item.EvidenceSnapshot.SharedAccess == nil {
			t.Fatalf("shared case lost its decision basis: %+v", item)
		}
	}
}

func TestCaseSynchronizationDoesNotRewriteUnchangedCase(t *testing.T) {
	s, _, _ := caseSyncFixture()
	if err := s.syncCasesContext(context.Background(), "test", "10m"); err != nil {
		t.Fatal(err)
	}
	var first RiskCase
	for _, item := range s.operations.doc.Cases {
		first = item
	}
	time.Sleep(2 * time.Millisecond)
	if err := s.syncCasesContext(context.Background(), "test", "10m"); err != nil {
		t.Fatal(err)
	}
	second := s.operations.doc.Cases[first.CaseID]
	if second.UpdatedAt != first.UpdatedAt || len(second.EvidenceHistory) != len(first.EvidenceHistory) {
		t.Fatalf("unchanged case was rewritten: first=%s second=%s", first.UpdatedAt, second.UpdatedAt)
	}
}

func TestCaseSynchronizationClosesMissingCurrentSharedCase(t *testing.T) {
	s, r, _ := caseSyncFixture()
	if err := s.syncCasesContext(context.Background(), "test", "10m"); err != nil {
		t.Fatal(err)
	}
	r.shared = nil
	if err := s.syncCasesContext(context.Background(), "test", "10m"); err != nil {
		t.Fatal(err)
	}
	for _, item := range s.operations.doc.Cases {
		if item.Status != "closed" || item.AssessmentCurrent {
			t.Fatalf("negative current generation did not close case: %+v", item)
		}
	}
}

func TestCaseSynchronizationIncludesNonAmbiguousRouterCandidates(t *testing.T) {
	s, base, _ := caseSyncFixture()
	base.shared = nil
	r := &routerCaseSyncReader{caseSyncReader: base, routers: []evidence.RouterAssessment{
		{AssessmentID: "router-candidate", IP: "192.0.2.1", Role: "router", Status: "candidate", Confidence: 25, RuleVersion: "router-rules-v1", FirstSeen: time.Now().Add(-time.Hour).Format(time.RFC3339Nano), LastSeen: time.Now().Format(time.RFC3339Nano)},
		{AssessmentID: "ambiguous", IP: "192.0.2.2", Role: "router", Status: "candidate", Confidence: 25, Ambiguous: true, RuleVersion: "router-rules-v1"},
	}}
	s.reader = r
	if err := s.syncCasesContext(context.Background(), "test", "10m"); err != nil {
		t.Fatal(err)
	}
	if len(s.operations.doc.Cases) != 1 {
		t.Fatalf("router candidate filtering produced %d cases", len(s.operations.doc.Cases))
	}
	for _, item := range s.operations.doc.Cases {
		if item.RiskKind != "router_observation" || item.AssessmentLevel != "candidate" || item.Priority != "low" {
			t.Fatalf("router candidate semantics changed: %+v", item)
		}
	}
}

func TestCaseSynchronizationPrefersExactCaseAndKeepsMergedDedupeKey(t *testing.T) {
	now := time.Now().UTC()
	assessment := evidence.RouterAssessment{
		AssessmentID: "router-exact",
		IP:           "192.0.2.1",
		Role:         "router",
		Status:       "candidate",
		Confidence:   25,
		RuleVersion:  "router-rules-v1",
		FirstSeen:    now.Add(-time.Hour).Format(time.RFC3339Nano),
		LastSeen:     now.Format(time.RFC3339Nano),
	}
	item := proxyReviewCaseForRouterAssessment(assessment)
	reader := &routerCaseSyncReader{caseSyncReader: &caseSyncReader{}, routers: []evidence.RouterAssessment{assessment}}
	s := &Server{reader: reader, operations: &operationsState{doc: emptyOperationsDocument()}, exceptions: newExceptionManager(nil)}
	other := RiskCase{CaseID: "router-other", SubjectType: "ip", SubjectID: assessment.IP, IP: assessment.IP, Status: "new", DedupeKey: "router-observation:router-other", RulesetVersion: "router-observation/router-rules-v1", FirstSeen: assessment.FirstSeen, LastSeen: assessment.LastSeen}
	exact := RiskCase{CaseID: item.CaseID, SubjectType: "ip", SubjectID: assessment.IP, IP: assessment.IP, Status: "new", DedupeKey: "router-observation:merged-history", RulesetVersion: "router-observation/router-rules-v1", FirstSeen: assessment.FirstSeen, LastSeen: assessment.LastSeen}
	s.operations.doc.Cases[other.CaseID] = other
	s.operations.doc.Cases[exact.CaseID] = exact

	if err := s.syncCasesContext(context.Background(), "test", "10m"); err != nil {
		t.Fatal(err)
	}
	got := s.operations.doc.Cases[item.CaseID]
	if got.DedupeKey != exact.DedupeKey {
		t.Fatalf("exact case changed its durable dedupe key: got=%q want=%q", got.DedupeKey, exact.DedupeKey)
	}
	if s.operations.doc.Cases[other.CaseID].Status != "closed" {
		t.Fatalf("unmatched duplicate case remained open: %+v", s.operations.doc.Cases[other.CaseID])
	}
}

func TestCaseSynchronizationReadFailureDoesNotCloseCurrentCase(t *testing.T) {
	s, r, _ := caseSyncFixture()
	if err := s.syncCasesContext(context.Background(), "test", "10m"); err != nil {
		t.Fatal(err)
	}
	r.sharedErr = errors.New("coverage generation unavailable")
	if err := s.syncCasesContext(context.Background(), "test", "10m"); err == nil {
		t.Fatal("expected generation read error")
	}
	for _, item := range s.operations.doc.Cases {
		if item.Status == "closed" {
			t.Fatal("failed generation closed the last verified case")
		}
	}
}

func TestCaseSynchronizationHealthSurvivesUnrelatedTransaction(t *testing.T) {
	s := &operationsState{}
	want := errors.New("automatic synchronization failed")
	s.setCaseSyncHealthError(want)
	s.setHealthError(nil)
	if err := s.health(context.Background()); !errors.Is(err, want) {
		t.Fatalf("unrelated successful transaction hid sync failure: %v", err)
	}
}
