package discovery

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRecognitionBindingSaturationDoesNotPublishPartialOwners(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	dirty := newStreamRecognitionDirty()
	dirty.add(nil, streamDiscoveryFact{IP: "192.0.2.1", RecognitionFields: map[string]string{"mdns_model": "Mac14,15"}})
	mock.ExpectQuery("WITH scopes AS").WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"mac", "saturated"}).AddRow("02:00:00:00:00:01", true))
	if err := dirty.mark(context.Background(), tx); err == nil || !strings.Contains(err.Error(), "budget exceeded") {
		t.Fatalf("partial binding result was silently published: %v", err)
	}
	mock.ExpectRollback()
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRepeatObservationDefersRecognitionInsteadOfDroppingIt(t *testing.T) {
	observed := time.Date(2026, 11, 4, 1, 0, 0, 0, time.UTC)
	prior := streamDiscoveryFact{
		Event: "e1", Revision: 1, Observed: observed, SemanticHash: "hash-a",
		Protocol: "dhcp", MAC: "02:00:00:00:00:01", IP: "10.0.0.5",
		Sensor: "s", Site: "site", Domain: "access", VLAN: "992", Interface: "bond0",
		RecognitionFields: map[string]string{"dhcp_vendor_class": "MSFT 5.0"},
	}
	repeat := prior
	repeat.Event, repeat.Observed = "e2", observed.Add(time.Minute)
	decision := mergeStreamDiscoveryFact(&prior, repeat)
	if decision.Result != "repeat_observation" || decision.VisibleChanged {
		t.Fatalf("repeat observation decision = %+v", decision)
	}
	immediate, deferred := newStreamRecognitionDirty(), newStreamRecognitionDirty()
	routeRecognitionWake(immediate, deferred, &prior, repeat, decision)
	if len(immediate.macs) != 0 || len(immediate.ips) != 0 {
		t.Fatalf("repeat observation woke the immediate path: macs=%v ips=%v", immediate.macs, immediate.ips)
	}
	if !deferred.macs[prior.MAC] || len(deferred.ips) == 0 {
		t.Fatalf("repeat observation lost its deferred wake: macs=%v ips=%v", deferred.macs, deferred.ips)
	}

	corrected := repeat
	corrected.SemanticHash = "hash-b"
	decision = mergeStreamDiscoveryFact(&prior, corrected)
	immediate, deferred = newStreamRecognitionDirty(), newStreamRecognitionDirty()
	routeRecognitionWake(immediate, deferred, &prior, corrected, decision)
	if !immediate.macs[prior.MAC] || len(deferred.macs) != 0 {
		t.Fatalf("corrected observation must wake immediately: macs=%v deferred=%v", immediate.macs, deferred.macs)
	}

	withdrawn := corrected
	withdrawn.Withdrawn = true
	decision = mergeStreamDiscoveryFact(&prior, withdrawn)
	immediate, deferred = newStreamRecognitionDirty(), newStreamRecognitionDirty()
	routeRecognitionWake(immediate, deferred, &prior, withdrawn, decision)
	if !immediate.macs[prior.MAC] || len(deferred.macs) != 0 {
		t.Fatalf("withdrawal must wake immediately: macs=%v deferred=%v", immediate.macs, deferred.macs)
	}
}

// A same-content renewal after expiry keeps the semantic hash but changes
// valid_until, which the recognition query uses to decide whether the binding
// is live. Its wake must be deferred, not dropped.
func TestRenewalAfterExpirySchedulesRecognition(t *testing.T) {
	now := time.Date(2026, 11, 4, 1, 0, 0, 0, time.UTC)
	expired := streamDiscoveryFact{
		Event: "e1", Revision: 1, Observed: now.Add(-2 * time.Hour), SemanticHash: "hash-a",
		ValidUntil: now.Add(-time.Minute), Protocol: "dhcp", MAC: "02:00:00:00:00:01", IP: "10.0.0.5",
		RecognitionFields: map[string]string{"dhcp_vendor_class": "MSFT 5.0"},
	}
	renewed := expired
	renewed.Event, renewed.Observed, renewed.ValidUntil = "e2", now, now.Add(2*time.Hour)
	decision := mergeStreamDiscoveryFact(&expired, renewed)
	if decision.Result != "repeat_observation" || decision.VisibleChanged {
		t.Fatalf("renewal decision = %+v", decision)
	}
	immediate, deferred := newStreamRecognitionDirty(), newStreamRecognitionDirty()
	routeRecognitionWake(immediate, deferred, &expired, renewed, decision)
	if len(immediate.macs) != 0 {
		t.Fatalf("renewal unexpectedly woke the immediate path: %v", immediate.macs)
	}
	if !deferred.macs[expired.MAC] {
		t.Fatalf("renewal wake was dropped: deferred=%v", deferred.macs)
	}
}

func TestDropImmediateOverlapKeepsImmediateWake(t *testing.T) {
	immediate := map[string]bool{"02:00:00:00:00:01": true}
	deferred := map[string]bool{"02:00:00:00:00:01": true, "02:00:00:00:00:02": true}
	dropImmediateOverlap(immediate, deferred)
	if deferred["02:00:00:00:00:01"] {
		t.Fatal("deferred wake for the immediately changed endpoint was not dropped")
	}
	if !deferred["02:00:00:00:00:02"] {
		t.Fatal("unrelated deferred wake was dropped")
	}
}

func TestMarkStreamRecognitionDirtyDeferredKeepsBoundedDelay(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(`INSERT INTO endpoint_recognition_jobs`).
		WithArgs("{02:00:00:00:00:01}", 60).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err = markStreamRecognitionDirtyDeferred(context.Background(), tx, map[string]bool{"02:00:00:00:00:01": true}, time.Minute); err != nil {
		t.Fatal(err)
	}
	mock.ExpectCommit()
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
