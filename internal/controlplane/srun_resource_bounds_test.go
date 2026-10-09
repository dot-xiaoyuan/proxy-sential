package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/productpolicy"
)

func TestSRunOperationFailureStatusKeepsResourceRejectionDistinct(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
	}{
		{fmt.Errorf("catalog read: %w", productpolicy.ErrCatalogResourceLimit), http.StatusUnprocessableEntity},
		{fmt.Errorf("online read: %w", legacy4k.ErrOnlineResourceLimit), http.StatusUnprocessableEntity},
		{fmt.Errorf("catalog read: %w", productpolicy.ErrRedisCatalogChanged), http.StatusConflict},
		{errSRunSyncResultCommit, http.StatusServiceUnavailable},
		{errSRunTestResultCommit, http.StatusServiceUnavailable},
		{errSRunGroupSnapshotConflict, http.StatusConflict},
		{errors.New("upstream connection refused"), http.StatusBadGateway},
	} {
		if got := srunOperationFailureStatus(test.err); got != test.status {
			t.Fatalf("status=%d want=%d", got, test.status)
		}
	}
}

func TestSRunReadProbeResourceRejectionKeepsConnection(t *testing.T) {
	for _, tc := range []struct {
		cause   error
		outcome string
	}{{legacy4k.ErrOnlineResourceLimit, "online_resource_limit"}, {productpolicy.ErrCatalogResourceLimit, "catalog_resource_limit"}} {
		t.Run(tc.outcome, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			reader := &srunFailureAudit{}
			s := &Server{operations: &operationsState{db: db}, reader: reader}
			failure := s.recordSRunReadTestFailure(context.Background(), "one", "connection failed", "private upstream detail", fmt.Errorf("private detail: %w", tc.cause))
			if !errors.Is(failure, tc.cause) || failure.Error() != tc.cause.Error() {
				t.Fatal("typed rejection or safe explanation lost", failure)
			}
			if len(reader.entries) != 1 || reader.entries[0].Outcome != tc.outcome {
				t.Fatalf("resource rejection reported as connection failure: %+v", reader.entries)
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
