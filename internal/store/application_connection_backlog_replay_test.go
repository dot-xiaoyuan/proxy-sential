package store

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestApplicationConnectionBacklogReplay(t *testing.T) {
	for _, lag := range []float64{0, 48 * 3600} {
		t.Run(fmt.Sprintf("upstream_lag_%g", lag), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			written := "2026-10-05T10:40:00Z"
			var published atomic.Bool
			var lookups atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				q := string(b)
				switch {
				case strings.Contains(q, "FROM application_recognized_connection_dirty_log"):
					lookups.Add(1)
					fmt.Fprintf(w, `{"written_at":%q,"sensor_id":"fixture","campus_id":"main","connection_id":"already-classified"}`+"\n", written)
				case strings.HasPrefix(q, "INSERT INTO application_connection_summaries_v2"):
					if !strings.Contains(q, "already-classified") {
						t.Error("available connection omitted")
					}
					published.Store(true)
				default:
					t.Errorf("unexpected read model query: %s", q)
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			mock.ExpectQuery("SELECT EXTRACT").WillReturnRows(sqlmock.NewRows([]string{"lag"}).AddRow(lag))
			mock.ExpectBegin()
			mock.ExpectExec("INSERT INTO application_connection_read_model_v2_cursor").WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery("SELECT cursor_document").WillReturnRows(sqlmock.NewRows([]string{"cursor_document"}).AddRow([]byte("{}")))
			mock.ExpectQuery("SELECT nextval").WillReturnRows(sqlmock.NewRows([]string{"revision"}).AddRow(42))
			mock.ExpectExec("UPDATE application_connection_read_model_v2_cursor").WithArgs(sqlmock.AnyArg(), written).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()
			model := &DBStore{pg: &PostgresStore{db: db}, ch: ch}
			var delay time.Duration
			model.runApplicationConnectionReadModel(context.Background(), func(_ context.Context, d time.Duration) bool { delay = d; return false })
			if !published.Load() || lookups.Load() != 1 {
				t.Fatalf("classified data starved behind upstream backlog: published=%t lookups=%d", published.Load(), lookups.Load())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
			if lag > 90 && delay < 10*time.Second {
				t.Fatalf("backlog recovery must retain a bounded admission gap: %s", delay)
			}
		})
	}
}
