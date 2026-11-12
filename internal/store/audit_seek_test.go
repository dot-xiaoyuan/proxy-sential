package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestAuditSeekReadsOnlyOnePageAndBindsCursorToSearch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	created := time.Date(2026, 11, 12, 3, 10, 0, 0, time.UTC)
	columns := []string{"audit_id", "actor", "action", "target", "outcome", "created_at"}
	mock.ExpectQuery("SELECT audit_id,actor,action,target,outcome,created_at FROM audit_logs").
		WithArgs(sqlmock.AnyArg(), "warn", "%warn%", 2).
		WillReturnRows(sqlmock.NewRows(columns).AddRow("id-2", "system", "action", "target", "warn", created).
			AddRow("id-1", "system", "action", "target", "warn", created.Add(-time.Minute)))
	store := &PostgresStore{db: db}
	first, err := store.ListAuditLogsSeek(context.Background(), 1, "", "WARN")
	if err != nil || len(first.Logs) != 1 || first.Logs[0].AuditID != "id-2" || !first.HasMore || first.NextCursor == "" {
		t.Fatalf("unexpected first audit page: %+v, err=%v", first, err)
	}
	if _, err := store.ListAuditLogsSeek(context.Background(), 1, first.NextCursor, "other"); err == nil {
		t.Fatal("cursor from another search was accepted")
	}
	mock.ExpectQuery("SELECT audit_id,actor,action,target,outcome,created_at FROM audit_logs").
		WithArgs(first.Snapshot, "warn", "%warn%", created, "id-2", 2).
		WillReturnRows(sqlmock.NewRows(columns).AddRow("id-1", "system", "action", "target", "warn", created.Add(-time.Minute)))
	second, err := store.ListAuditLogsSeek(context.Background(), 1, first.NextCursor, "warn")
	if err != nil || len(second.Logs) != 1 || second.Logs[0].AuditID != "id-1" || second.HasMore {
		t.Fatalf("unexpected next audit page: %+v, err=%v", second, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestAuditDetailUsesUniqueID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC()
	mock.ExpectQuery("SELECT audit_id,actor,action,target,outcome,created_at FROM audit_logs WHERE audit_id").WithArgs("old-audit").
		WillReturnRows(sqlmock.NewRows([]string{"audit_id", "actor", "action", "target", "outcome", "created_at"}).AddRow("old-audit", "system", "action", "target", "recorded", at))
	got, found, err := (&PostgresStore{db: db}).GetAuditLog(context.Background(), "old-audit")
	if err != nil || !found || got.AuditID != "old-audit" {
		t.Fatalf("audit ID lookup failed: %+v, found=%t, err=%v", got, found, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
