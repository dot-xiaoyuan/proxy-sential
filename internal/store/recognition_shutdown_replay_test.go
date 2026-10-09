package store

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/fingerprint"
)

// Replay a signal-query failure followed by a stalled PostgreSQL status write.
// Shutdown must still join the worker; the failed write cannot detach it from
// the service lifetime and block an upgrade or the next recovery cycle.
func TestRecognitionFailureWriteShutdownReplay(t *testing.T) {
	for _, worker := range []string{"shared", "router"} {
		t.Run(worker, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var once sync.Once
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				// Give the worker time to start its failed-run status write.
				once.Do(func() { time.AfterFunc(100*time.Millisecond, cancel) })
				http.Error(w, "fixture signal query failed", http.StatusServiceUnavailable)
			}))
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			model := &DBStore{pg: &PostgresStore{db: db}, ch: ch}
			var run func()
			if worker == "shared" {
				mock.ExpectExec("INSERT INTO read_model_runtime_state").
					WillDelayFor(2 * time.Second).WillReturnResult(sqlmock.NewResult(0, 1))
				run = func() { model.runSharedBehaviorMaterializer(ctx, "fixture") }
			} else {
				mock.ExpectBegin()
				mock.ExpectExec("INSERT INTO router_recognition_state").WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectQuery("SELECT cursor_timestamp").WillReturnRows(sqlmock.NewRows([]string{"cursor_timestamp", "cursor_event_id", "leased", "rule_version"}).AddRow(time.Now(), "previous-event", false, fingerprint.DefaultRouterRuleSet().Version))
				mock.ExpectExec("UPDATE router_recognition_state SET lease_owner").WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
				// A failed signal read may release its lease and report an error,
				// but must never advance the old cursor.
				mock.ExpectExec("UPDATE router_recognition_state SET lease_owner=''\\,lease_until").
					WillDelayFor(2 * time.Second).WillReturnResult(sqlmock.NewResult(0, 1))
				run = func() { model.runRouterRecognitionMaterializer(ctx, "fixture") }
			}
			started := time.Now()
			run()
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Errorf("failure status write blocked worker shutdown: %s", elapsed)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecognitionFailureWriteBudgetReplay(t *testing.T) {
	for _, worker := range []string{"shared", "router"} {
		t.Run(worker, func(t *testing.T) {
			t.Parallel()
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			model := &DBStore{pg: &PostgresStore{db: db}}
			started := time.Now()
			if worker == "shared" {
				mock.ExpectExec("INSERT INTO read_model_runtime_state").
					WillDelayFor(6 * time.Second).WillReturnResult(sqlmock.NewResult(0, 1))
				err = model.recordSharedBehaviorFailure(context.Background(), context.DeadlineExceeded)
			} else {
				mock.ExpectExec("UPDATE router_recognition_state SET lease_owner=''\\,lease_until").
					WillDelayFor(6 * time.Second).WillReturnResult(sqlmock.NewResult(0, 1))
				err = model.finishRouterRecognition(context.Background(), routerRecognitionCursor{Owner: "fixture"}, 0, context.DeadlineExceeded)
			}
			if !errors.Is(err, sqlmock.ErrCancelled) || time.Since(started) > 5500*time.Millisecond {
				t.Fatalf("failed-run write did not release within its five-second budget: %v, %s", err, time.Since(started))
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedBehaviorExpiredWorkReportsOriginalError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	model := &DBStore{pg: &PostgresStore{db: db}}
	mock.ExpectExec("INSERT INTO read_model_runtime_state").
		WithArgs([]byte(`{"error":"context deadline exceeded"}`)).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := model.recordSharedBehaviorFailure(context.Background(), context.DeadlineExceeded); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
