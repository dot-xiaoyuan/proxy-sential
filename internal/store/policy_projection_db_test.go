package store

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// Policy reads take the snapshot timeline from the log and membership from the projection; they never
// read stored snapshot documents.
func TestPolicyInputsReadLogAndProjection(t *testing.T) {
	db, mock := newReconcileMock(t)
	at := reconcileObserved
	mock.ExpectQuery(regexp.QuoteMeta(policySnapshotLogSQL)).
		WithArgs(at.Add(-policyIdentityWindow), at, "", "").
		WillReturnRows(sqlmock.NewRows([]string{"source", "sensor_id", "campus_id", "access_domain", "snapshot_id", "observed_at", "interval_seconds"}).
			AddRow(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, "s1", at.Add(-time.Hour), 1800))
	first := at.Add(-2 * time.Hour)
	mock.ExpectQuery(regexp.QuoteMeta(policyProjectionMembersSQL)).
		WithArgs("", "", at.Add(-policyIdentityWindow)).
		WillReturnRows(sqlmock.NewRows([]string{"source", "sensor_id", "campus_id", "access_domain", "confirmed_at", "document"}).
			AddRow(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, at.Add(-time.Hour),
				[]byte(`{"session_id":"open","account_id":"a1","ip":"10.0.0.1","first_confirmed_at":"`+first.Format(time.RFC3339Nano)+`"}`)).
			AddRow(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, at.Add(-30*time.Minute),
				[]byte(`{"session_id":"ended","account_id":"a2","ip":"10.0.0.2","ended_at":"x","first_confirmed_at":"`+first.Format(time.RFC3339Nano)+`"}`)).
			AddRow(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, at.Add(-45*time.Minute),
				[]byte(`{"session_id":"legacy","account_id":"a3","ip":"10.0.0.3"}`)))
	log, members, err := projectionPolicyInputs(context.Background(), db, at, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	if len(log) != 1 || log[0].SnapshotID != "s1" || log[0].Scope != reconcileScope {
		t.Fatalf("log=%+v", log)
	}
	byID := map[string]projectionMember{}
	for _, m := range members {
		byID[m.Session.ID] = m
	}
	if m := byID["open"]; !m.First.Equal(first) || !m.End.IsZero() || m.Session.AccountID != "a1" || m.Scope != reconcileScope {
		t.Fatalf("open member=%+v", m)
	}
	if m := byID["ended"]; !m.First.Equal(first) || !m.End.Equal(at.Add(-30*time.Minute)) {
		t.Fatalf("ended member=%+v", m)
	}
	// A row written before first_confirmed_at existed is confirmed no earlier than its stored time.
	if m := byID["legacy"]; !m.First.Equal(at.Add(-45 * time.Minute)) {
		t.Fatalf("legacy member=%+v", m)
	}
}

// The scoped reader passes its campus and access domain to both reads.
func TestScopedPolicyInputsFilterBothReads(t *testing.T) {
	db, mock := newReconcileMock(t)
	at := reconcileObserved
	mock.ExpectQuery(regexp.QuoteMeta(policySnapshotLogSQL)).WithArgs(at.Add(-policyIdentityWindow), at, "ncu", "campus-auth").
		WillReturnRows(sqlmock.NewRows([]string{"source", "sensor_id", "campus_id", "access_domain", "snapshot_id", "observed_at", "interval_seconds"}))
	mock.ExpectQuery(regexp.QuoteMeta(policyProjectionMembersSQL)).WithArgs("ncu", "campus-auth", at.Add(-policyIdentityWindow)).
		WillReturnRows(sqlmock.NewRows([]string{"source", "sensor_id", "campus_id", "access_domain", "confirmed_at", "document"}))
	if _, _, err := projectionPolicyInputs(context.Background(), db, at, "ncu", "campus-auth"); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// The open-member read must match the partial index predicate exactly, or the planner scans the
// whole projection.
func TestOpenMemberReadMatchesPartialIndex(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/postgres/150_projection_open_members.sql")
	if err != nil {
		t.Fatal(err)
	}
	predicate := "COALESCE(document->>'ended_at','')=''"
	if !strings.Contains(string(raw), "WHERE "+predicate) || !strings.Contains(policyProjectionMembersSQL, "COALESCE(p.document->>'ended_at','')=''") {
		t.Fatal("open member read and partial index predicate differ")
	}
}
