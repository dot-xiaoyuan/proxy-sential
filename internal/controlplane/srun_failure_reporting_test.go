package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/store"
)

type srunFailureAudit struct {
	store.Reader
	entries   []store.AuditLog
	deadlines []time.Time
	errors    []error
}

func (r *srunFailureAudit) AppendAuditLog(ctx context.Context, entry store.AuditLog) error {
	r.entries = append(r.entries, entry)
	deadline, _ := ctx.Deadline()
	r.deadlines = append(r.deadlines, deadline)
	r.errors = append(r.errors, ctx.Err())
	return nil
}

func TestSRunFailureReportingSurvivesCancelledRequestWithBound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reader := &srunFailureAudit{}
	s := &Server{operations: &operationsState{db: db}, reader: reader}
	mock.ExpectExec(`UPDATE srun4k_integrations SET connection_state='failed'`).WithArgs("one", "redis: interrupted", int64(1)).WillReturnResult(sqlmock.NewResult(0, 1))
	parent := context.WithValue(context.Background(), sessionContextKey{}, Session{User: User{ID: "operator"}})
	parent = context.WithValue(parent, srunOperationOrderKey{}, int64(1))
	ctx, cancel := context.WithCancel(parent)
	cancel()
	started := time.Now()
	s.recordSRunFailure(ctx, "one", "redis: interrupted")
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal("cancelled request discarded failure state:", err)
	}
	if len(reader.entries) != 1 || reader.entries[0].Actor != "operator" || reader.entries[0].Action != "integration.srun4k.test" || reader.entries[0].Outcome != "failed" {
		t.Fatalf("audit=%+v", reader.entries)
	}
	if reader.errors[0] != nil || reader.deadlines[0].IsZero() || reader.deadlines[0].After(started.Add(4*time.Second)) {
		t.Fatalf("reporting context cancelled or unbounded: error=%v deadline=%s", reader.errors[0], reader.deadlines[0])
	}
}

func TestSRunFailureReportingBackgroundHasBound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reader := &srunFailureAudit{}
	s := &Server{operations: &operationsState{db: db}, reader: reader}
	mock.ExpectExec(`UPDATE srun4k_integrations SET connection_state='failed'`).WillReturnResult(sqlmock.NewResult(0, 1))
	started := time.Now()
	s.recordSRunFailure(context.WithValue(context.Background(), srunOperationOrderKey{}, int64(1)), "one", "failed")
	if len(reader.deadlines) != 1 || reader.deadlines[0].IsZero() || reader.deadlines[0].After(started.Add(4*time.Second)) {
		t.Fatalf("background failure context is unbounded: %+v", reader.deadlines)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestManualSRunSyncFailureIsAuditedAsSync(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reader := &srunFailureAudit{}
	s := &Server{operations: &operationsState{db: db}, reader: reader}
	for i := 0; i < 2; i++ {
		mock.ExpectQuery(`SELECT connector_id,host,authorization_database_host`).WithArgs("one").WillReturnRows(srun4KTestIntegrationRow(true))
		if i == 0 {
			mock.ExpectQuery(`SELECT nextval`).WillReturnRows(sqlmock.NewRows([]string{"nextval"}).AddRow(int64(1)))
		}
	}
	mock.ExpectQuery(`SELECT northbound_app_id,encrypted_northbound_app_secret`).WithArgs("one").WillReturnError(errors.New("stored credential unavailable"))
	mock.ExpectExec(`UPDATE srun4k_integrations SET connection_state='failed',last_error=\$2,last_tested_at=now\(\)`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE srun4k_integrations SET connection_state='failed',last_error=\$2,last_health_result_order=\$3,updated_at=now\(\)`).WillReturnResult(sqlmock.NewResult(0, 1))
	result, err := s.syncSRun4K(context.Background(), "one")
	if err == nil || result != nil || err.Error() != "4K北向授权不可用" {
		t.Fatalf("original sync error changed: result=%v err=%v", result, err)
	}
	if len(reader.entries) != 2 || reader.entries[0].Action != "integration.srun4k.test" || reader.entries[1].Action != "integration.srun4k.sync" || reader.entries[1].Outcome != "failed" {
		t.Fatalf("manual sync failure audit=%+v pending=%v", reader.entries, mock.ExpectationsWereMet())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
