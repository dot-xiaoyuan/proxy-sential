package store

import (
	"context"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"testing"
)

func TestIdentityDeltaExpiredLeaseCannotAdvanceDiff(t *testing.T) {
	db, m := newReconcileMock(t)
	m.ExpectBegin()
	m.ExpectExec(`SELECT set_config`).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery(`SELECT lease_owner=.*FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(false))
	m.ExpectRollback()
	err := (&PostgresStore{db: db}).diffIdentityDelta(context.Background(), identityDeltaRun{ID: 1, Owner: "stale"})
	if !errors.Is(err, ErrIdentityLeaseExpired) {
		t.Fatalf("got %v", err)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestIdentityDeltaShadowDoesNotApply(t *testing.T) {
	db, m := newReconcileMock(t)
	if err := (&PostgresStore{db: db}).applyIdentityDelta(context.Background(), identityDeltaRun{Mode: "shadow"}); err != nil {
		t.Fatal(err)
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestIdentityDeltaDiffFailureRollsBackCursor(t *testing.T) {
	db, m := newReconcileMock(t)
	m.ExpectBegin()
	m.ExpectExec(`SELECT set_config`).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery(`SELECT lease_owner=.*FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(true))
	m.ExpectQuery(`SELECT session_id,ip FROM account_identity_session_projection`).WillReturnRows(sqlmock.NewRows([]string{"session", "ip"}).AddRow("s", "192.0.2.1"))
	m.ExpectExec(`INSERT INTO identity_delta_changes`).WillReturnError(errors.New("write interrupted"))
	m.ExpectRollback()
	if err := (&PostgresStore{db: db}).diffIdentityDelta(context.Background(), identityDeltaRun{ID: 1, Batch: 100}); err == nil {
		t.Fatal("failed write cannot publish cursor")
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityDeltaOldSnapshotCannotPublishCompletion(t *testing.T) {
	db, m := newReconcileMock(t)
	m.ExpectQuery(`SELECT member_key,session_id,ip,document,kind`).WillReturnRows(sqlmock.NewRows([]string{"key", "session", "ip", "document", "kind"}))
	m.ExpectBegin()
	m.ExpectExec(`SELECT set_config`).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery(`SELECT lease_owner=.*FOR UPDATE`).WillReturnRows(sqlmock.NewRows([]string{"valid"}).AddRow(true))
	m.ExpectQuery(`SELECT mode FROM identity_delta_settings`).WillReturnRows(sqlmock.NewRows([]string{"mode"}).AddRow("delta"))
	m.ExpectQuery(`SELECT capture_started_at FROM identity_delta_runs`).WillReturnRows(sqlmock.NewRows([]string{"capture"}).AddRow(reconcileObserved))
	m.ExpectQuery(`SELECT EXISTS.*account_identity_projection_sources`).WillReturnRows(sqlmock.NewRows([]string{"newer"}).AddRow(true))
	m.ExpectRollback()
	err := (&PostgresStore{db: db}).applyIdentityDelta(context.Background(), identityDeltaRun{ID: 1, Mode: "delta", ObservedAt: reconcileObserved})
	if !errors.Is(err, errIdentityDeltaStaleSnapshot) {
		t.Fatalf("got %v", err)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityDeltaNotificationFailureKeepsResponsibility(t *testing.T) {
	db, m := newReconcileMock(t)
	m.ExpectBegin()
	m.ExpectExec(`SELECT set_config`).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery(`SELECT n.notification_id,n.document,r.observed_at`).WillReturnRows(sqlmock.NewRows([]string{"id", "document", "at"}).AddRow(1, []byte(`[{"session_id":"s","endpoint_id":"e","ip":"192.0.2.1"}]`), reconcileObserved))
	m.ExpectExec(`INSERT INTO shared_device_profile_jobs`).WillReturnError(errors.New("downstream unavailable"))
	m.ExpectRollback()
	did, err := (&PostgresStore{db: db}).consumeIdentityDeltaNotification(context.Background())
	if !did || err == nil {
		t.Fatalf("did=%t err=%v", did, err)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
