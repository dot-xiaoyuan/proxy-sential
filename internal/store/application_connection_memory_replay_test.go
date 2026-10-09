package store

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestApplicationConnectionMemoryRetryPreservesCursor(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var attempts atomic.Int32
	var committed atomic.Bool
	var reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		query := string(b)
		if strings.Contains(query, "FROM application_recognized_connection_dirty_log") {
			n := reads.Add(1)
			limit := "256"
			if n == 2 {
				limit = "128"
			}
			if !strings.Contains(query, "LIMIT "+limit+" SETTINGS") || !strings.Contains(query, "WHERE 1 ORDER BY") {
				t.Errorf("retry changed cursor or exceeded admitted batch: %s", query)
			}
			io.WriteString(w, "{\"written_at\":\"2026-10-05T11:00:00Z\",\"sensor_id\":\"fixture\",\"campus_id\":\"main\",\"connection_id\":\"retained\"}\n")
			return
		}
		if strings.HasPrefix(query, "INSERT INTO application_connection_summaries_v2") {
			if attempts.Add(1) == 1 {
				w.WriteHeader(500)
				io.WriteString(w, "Code: 241. MEMORY_LIMIT_EXCEEDED")
				return
			}
			committed.Store(true)
			return
		}
		t.Errorf("unexpected query: %s", query)
		w.WriteHeader(500)
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		mock.ExpectBegin()
		mock.ExpectExec("INSERT INTO application_connection_read_model_v2_cursor").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT cursor_document").WillReturnRows(sqlmock.NewRows([]string{"cursor_document"}).AddRow([]byte("{}")))
		mock.ExpectQuery("SELECT nextval").WillReturnRows(sqlmock.NewRows([]string{"revision"}).AddRow(42 + i))
		if i == 0 {
			mock.ExpectRollback()
		} else {
			mock.ExpectExec("UPDATE application_connection_read_model_v2_cursor").WithArgs(sqlmock.AnyArg(), "2026-10-05T11:00:00Z").WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()
		}
	}
	model := &DBStore{pg: &PostgresStore{db: db}, ch: ch}
	more, err := model.updateApplicationConnectionReadModel(context.Background())
	if err != nil || !more || !committed.Load() || reads.Load() != 2 {
		t.Fatalf("memory retry lost progress: more=%t err=%v reads=%d", more, err, reads.Load())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
