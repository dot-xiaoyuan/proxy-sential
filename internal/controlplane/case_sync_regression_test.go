package controlplane

import (
	"context"
	"errors"
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
		Current: true, ObservationID: "shared-observation", GenerationID: "generation-1", SensorID: "test",
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
