package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/evidence"
)

func TestActionPrecheckCancelledReleaseDoesNotAuthorize(t *testing.T) {
	s := &Server{operations: &operationsState{doc: emptyOperationsDocument()}}
	for _, cause := range []string{"cancelled", "expired"} {
		t.Run(cause, func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			expected := context.Canceled
			if cause == "cancelled" {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			} else {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				expected = context.DeadlineExceeded
			}
			defer cancel()
			if err := s.validatePolicyDeliveryContext(ctx, EnforcementAction{ActionType: "release"}); !errors.Is(err, expected) {
				t.Fatalf("cancelled release passed precheck: %v", err)
			}
		})
	}
}

type cancelPrecheckEvidenceReader struct {
	*riskActionReplayReader
	cancel context.CancelFunc
}

func (r cancelPrecheckEvidenceReader) GetIPEvidence(context.Context, string, int) ([]evidence.Evidence, error) {
	r.cancel()
	return r.evidence, nil
}

func TestActionPrecheckRiskEvidenceCancellationCannotAuthorize(t *testing.T) {
	s, reader, a := riskActionReplay(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.reader = cancelPrecheckEvidenceReader{riskActionReplayReader: reader, cancel: cancel}
	if err := s.validatePolicyDeliveryContext(ctx, a); !errors.Is(err, context.Canceled) {
		t.Fatalf("risk validation lost parent cancellation: %v", err)
	}
}

func TestActionPrecheckLocalLockWaitHonorsDeadline(t *testing.T) {
	for _, stage := range []string{"precheck", "native_final_guard"} {
		t.Run(stage, func(t *testing.T) {
			s := &Server{operations: &operationsState{doc: emptyOperationsDocument()}}
			s.operations.mu.Mutex.Lock()
			defer s.operations.mu.Mutex.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			started := time.Now()
			var err error
			if stage == "precheck" {
				err = s.validatePolicyDeliveryContext(ctx, EnforcementAction{ActionType: "release"})
			} else {
				err = s.nativeAuthorization(ctx, EnforcementAction{ActionID: "owned"})
			}
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 250*time.Millisecond {
				t.Fatalf("lock ignored deadline: elapsed=%s err=%v", time.Since(started), err)
			}
		})
	}
}

func TestActionPrecheckEventChannelQueryRetainsCancellation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mock.ExpectQuery(`SELECT event_channel_state`).WithArgs(cancelAuthorityArgument{value: "owned", cancel: cancel}).WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("healthy"))
	healthy, err := s.srunEventChannelStatusContext(ctx, "owned")
	if healthy || !errors.Is(err, context.Canceled) {
		t.Fatalf("channel cancellation lost: healthy=%v err=%v", healthy, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestActionPrecheckEventChannelFailureIsSanitized(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}}
	private := errors.New("private-event-channel-driver-detail")
	mock.ExpectQuery(`SELECT event_channel_state`).WillReturnError(private)
	healthy, err := s.srunEventChannelStatusContext(context.Background(), "owned")
	if healthy || !errors.Is(err, private) || strings.Contains(err.Error(), private.Error()) {
		t.Fatalf("channel error hidden/leaked: healthy=%v err=%v", healthy, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
