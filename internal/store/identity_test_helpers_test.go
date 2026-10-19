package store

import (
	"database/sql"
	"database/sql/driver"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/policy"
)

var reconcileScope = IdentityScope{Source: "ncu-srun4k", SensorID: "ncu-auth-redis", CampusID: "ncu", AccessDomain: "campus-auth"}

var reconcileObserved = time.Date(2026, 10, 16, 7, 10, 0, 0, time.UTC)

// passthroughConverter keeps []string array arguments intact, as the pgx driver does at runtime.
type passthroughConverter struct{}

func (passthroughConverter) ConvertValue(v any) (driver.Value, error) { return v, nil }

func newReconcileMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp), sqlmock.ValueConverterOption(passthroughConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, mock
}

// snapshotMember is a complete-snapshot member as CommitIdentitySnapshot derives it.
func snapshotMember(id, account, ip string) policy.Session {
	return policy.Session{
		ID: id, AccountID: account, IP: ip, Source: reconcileScope.Source, SensorID: reconcileScope.SensorID,
		CampusID: reconcileScope.CampusID, AccessDomain: reconcileScope.AccessDomain,
		Status: "reconcile", StartedAt: time.Date(2026, 9, 30, 17, 20, 55, 0, time.UTC),
		ConfirmedAt: reconcileObserved, HeartbeatSeconds: 1800, ReconcileSeconds: 1800,
	}
}

func snapshotWith(members ...policy.Session) IdentitySnapshot {
	return IdentitySnapshot{IdentityScope: reconcileScope, SnapshotID: "snapshot-replay", ObservedAt: reconcileObserved, IntervalSeconds: 1800, Sessions: members}
}
