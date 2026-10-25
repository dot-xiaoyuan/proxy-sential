package store

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
)

func sharedMapping() sharedaccess.IdentityMapping {
	return sharedaccess.IdentityMapping{Source: reconcileScope.Source, IdentitySensorID: reconcileScope.SensorID, IdentityCampusID: reconcileScope.CampusID, IdentityAccessDomain: reconcileScope.AccessDomain}
}

func expectSharedIdentityReads(mock sqlmock.Sqlmock, from, to time.Time, log *sqlmock.Rows, members *sqlmock.Rows) {
	mock.ExpectQuery(`SELECT session_data FROM \(`).WillReturnRows(sqlmock.NewRows([]string{"session_data"}))
	mock.ExpectQuery(regexp.QuoteMeta(sharedSnapshotLogSQL)).
		WithArgs(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, from.Add(-90*time.Minute), to).
		WillReturnRows(log)
	if members != nil {
		mock.ExpectQuery(regexp.QuoteMeta(sharedProjectionMembersSQL)).
			WithArgs(reconcileScope.Source, reconcileScope.SensorID, reconcileScope.CampusID, reconcileScope.AccessDomain, "10.157.2.191", from.Add(-90*time.Minute)).
			WillReturnRows(members)
	}
	mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM identity_pipeline_scopes`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
}

// Shared observation reads the snapshot timeline from the log and the IP's members from the
// projection, so a long-online member is attributed without per-snapshot member copies.
func TestSharedIdentitySessionsReadProjection(t *testing.T) {
	db, mock := newReconcileMock(t)
	to := reconcileObserved
	from := to.Add(-10 * time.Minute)
	log := sqlmock.NewRows([]string{"snapshot_id", "observed_at", "projected"}).
		AddRow("s1", to.Add(-40*time.Minute), true).AddRow("s2", to.Add(-10*time.Minute), true)
	first := to.Add(-19 * 24 * time.Hour)
	members := sqlmock.NewRows([]string{"confirmed_at", "document"}).
		AddRow(first, []byte(`{"session_id":"sess","account_id":"acct","ip":"10.157.2.191","first_confirmed_at":"`+first.Format(time.RFC3339Nano)+`"}`))
	expectSharedIdentityReads(mock, from, to, log, members)
	out, err := (&DBStore{pg: &PostgresStore{db: db}}).SharedIdentitySessions(context.Background(), sharedMapping(), "10.157.2.191", from, to, 1800)
	if err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	a := policy.Attribute(out, reconcileScope.CampusID, reconcileScope.AccessDomain, "10.157.2.191", to.Add(-time.Minute))
	if a.State != "resolved" || a.AccountID != "acct" {
		t.Fatalf("attribution=%+v sessions=%+v", a, out)
	}
	for _, s := range out {
		if s.IdentityIssue != "" {
			t.Fatalf("unexpected issue %q", s.IdentityIssue)
		}
	}
}

// A newer snapshot the projection has not applied yet may still change the window's attribution;
// the window stays pending instead of deciding on stale membership.
func TestSharedIdentitySessionsWaitForProjection(t *testing.T) {
	db, mock := newReconcileMock(t)
	to := reconcileObserved
	from := to.Add(-10 * time.Minute)
	log := sqlmock.NewRows([]string{"snapshot_id", "observed_at", "projected"}).
		AddRow("s1", to.Add(-40*time.Minute), true).AddRow("s2", to.Add(-5*time.Minute), false)
	members := sqlmock.NewRows([]string{"confirmed_at", "document"})
	expectSharedIdentityReads(mock, from, to, log, members)
	out, err := (&DBStore{pg: &PostgresStore{db: db}}).SharedIdentitySessions(context.Background(), sharedMapping(), "10.157.2.191", from, to, 1800)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 || out[0].IdentityIssue != "identity_snapshot_index_pending" {
		t.Fatalf("pending projection not reported: %+v", out)
	}
}

// Projecting a snapshot now wakes the scope's shared observation jobs, which the removed index rows
// used to do.
func TestProjectedSnapshotWakesSharedObservation(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/postgres/151_shared_identity_from_projection.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"AFTER UPDATE OF projected ON identity_snapshot_log",
		"WHEN (NEW.projected AND NOT OLD.projected)",
		"EXECUTE FUNCTION shared_wake_snapshot_scope()",
		"ON account_identity_session_projection (ip, confirmed_at)",
	} {
		if !strings.Contains(string(raw), required) {
			t.Fatalf("migration lacks %q", required)
		}
	}
}
