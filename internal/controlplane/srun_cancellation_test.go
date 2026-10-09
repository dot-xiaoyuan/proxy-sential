package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSRunCancelledSyncRetainsConnectionAndAuditsCancellation(t *testing.T) {
	for _, failure := range []error{context.Canceled, fmt.Errorf("catalog read: %w", context.Canceled)} {
		t.Run(failure.Error(), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			reader := &srunFailureAudit{}
			s := &Server{operations: &operationsState{db: db}, reader: reader}
			parent := context.WithValue(context.Background(), sessionContextKey{}, Session{User: User{ID: "operator"}})
			parent = context.WithValue(parent, srunOperationOrderKey{}, int64(7))
			ctx, cancel := context.WithCancel(parent)
			cancel()
			started := time.Now()
			s.recordSRunSyncFailure(ctx, "one", failure)
			if len(reader.entries) != 1 || reader.entries[0].Outcome != "cancelled" || reader.entries[0].Action != "integration.srun4k.sync" || reader.entries[0].Actor != "operator" {
				t.Fatalf("cancellation reported as a connection failure: %+v", reader.entries)
			}
			if reader.errors[0] != nil || reader.deadlines[0].IsZero() || reader.deadlines[0].After(started.Add(4*time.Second)) {
				t.Fatal("cancellation audit is cancelled or unbounded")
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
			if got := srunOperationFailureStatus(failure); got != http.StatusRequestTimeout {
				t.Fatalf("cancel status=%d", got)
			}
		})
	}
}

func TestSRunReadProbeCancellationRetainsCause(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reader := &srunFailureAudit{}
	s := &Server{operations: &operationsState{db: db}, reader: reader}
	columns := []string{"connector_id", "host", "source", "sensor_id", "reconcile_interval_hours", "event_channel_state", "connection_state", "last_error", "last_tested_at", "last_synced_at", "identity_accounts", "identity_sessions", "products", "groups_count", "controls", "last_identity_poll_at", "last_identity_event_at"}
	mock.ExpectQuery(`SELECT connector_id,host,source,sensor_id`).WithArgs("one").WillReturnRows(sqlmock.NewRows(columns).AddRow("one", "192.0.2.1", "srun4k:one", "one", 6, "waiting", "healthy", "", nil, nil, 0, 0, 0, 0, 0, nil, nil))
	mock.ExpectQuery(`SELECT nextval`).WillReturnRows(sqlmock.NewRows([]string{"nextval"}).AddRow(int64(7)))
	mock.ExpectQuery(`SELECT public_config,encrypted_password`).WithArgs("192.0.2.1").WillReturnError(fmt.Errorf("authorization read: %w", context.Canceled))
	result, err := s.testSRun4K(context.Background(), "one")
	if result != nil || !errors.Is(err, context.Canceled) || err.Error() != "4K操作已取消，请重试" {
		t.Fatalf("cancellation cause/public message lost: %v %v", result, err)
	}
	if len(reader.entries) != 1 || reader.entries[0].Outcome != "cancelled" || reader.entries[0].Action != "integration.srun4k.test" {
		t.Fatalf("probe cancellation audit=%+v", reader.entries)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSRunRealSyncFailureAfterRequestCancellationStillReportsFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reader := &srunFailureAudit{}
	s := &Server{operations: &operationsState{db: db}, reader: reader}
	mock.ExpectExec(`UPDATE srun4k_integrations SET connection_state='failed'`).WithArgs("one", "redis: connection refused", int64(7)).WillReturnResult(sqlmock.NewResult(0, 1))
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), srunOperationOrderKey{}, int64(7)))
	cancel()
	s.recordSRunSyncFailure(ctx, "one", errors.New("redis: connection refused"))
	if len(reader.entries) != 1 || reader.entries[0].Outcome != "failed" {
		t.Fatalf("actual failure suppressed: %+v", reader.entries)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSRunCancellationClassificationKeepsRealTimeoutAndPublicMessage(t *testing.T) {
	for _, cause := range []error{context.DeadlineExceeded, errors.New("context canceled"), errors.New("connection refused")} {
		if got := srunOperationFailureStatus(cause); got != http.StatusBadGateway {
			t.Fatalf("real timeout/failure reclassified: %v status=%d", cause, got)
		}
	}
	if got := srunOperationFailureMessage(fmt.Errorf("private connection details: %w", context.Canceled)); got != "4K操作已取消，请重试" {
		t.Fatalf("unsafe cancellation message=%q", got)
	}
}

func TestSRunLocalTimeoutDoesNotOverwriteConnectionHealth(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reader := &srunFailureAudit{}
	s := &Server{operations: &operationsState{db: db}, reader: reader}
	parent := context.WithValue(context.Background(), sessionContextKey{}, Session{User: User{ID: "local-operator"}})
	ctx, cancel := context.WithDeadline(parent, time.Now().Add(-time.Second))
	defer cancel()
	failure := identityLocalWorkError(ctx.Err())
	if !errors.Is(failure, context.DeadlineExceeded) || !errors.Is(failure, errIdentityLocalWorkInterrupted) {
		t.Fatal("local deadline cause lost")
	}
	s.recordSRunSyncFailure(ctx, "one", failure)
	if len(reader.entries) != 1 || reader.entries[0].Outcome != "local_processing_timeout" || reader.entries[0].Actor != "local-operator" {
		t.Fatalf("local deadline misreported %+v", reader.entries)
	}
	if reader.errors[0] != nil || reader.deadlines[0].IsZero() {
		t.Fatal("deadline audit has cancelled or unbounded context")
	}
	if srunOperationFailureStatus(failure) != http.StatusRequestTimeout || srunOperationFailureMessage(failure) != "4K身份清单处理超时，请重试" {
		t.Fatal("local timeout public response changed")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
	actual := errors.New("redis: actual connection refused")
	if identityLocalWorkError(actual) != actual || srunOperationFailureStatus(actual) != http.StatusBadGateway {
		t.Fatal("real source failure reclassified")
	}
}
