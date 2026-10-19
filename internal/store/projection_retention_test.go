package store

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// fakeArchive is a minimal ClickHouse: it stores archive inserts and answers the verification read.
type fakeArchive struct {
	mu      sync.Mutex
	rows    []map[string]any
	inserts int
	fail    bool
	corrupt bool
}

func (f *fakeArchive) serve(t *testing.T) *ClickHouseStore {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		text := string(body) + r.URL.Query().Get("query")
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case strings.Contains(text, "INSERT INTO identity_projection_history_archive"):
			if f.fail {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			f.inserts++
			scanner := bufio.NewScanner(strings.NewReader(text))
			scanner.Buffer(make([]byte, 1<<20), 1<<24)
			for scanner.Scan() {
				line := scanner.Text()
				if !strings.HasPrefix(line, "{") {
					continue
				}
				var row map[string]any
				if err := json.Unmarshal([]byte(line), &row); err != nil {
					t.Errorf("bad archive row: %v", err)
				}
				f.rows = append(f.rows, row)
			}
		case strings.Contains(text, "FROM identity_projection_history_archive"):
			batch := regexp.MustCompile(`batch_id='([^']+)'`).FindStringSubmatch(text)
			for _, row := range f.rows {
				if batch == nil || row["batch_id"] != batch[1] {
					continue
				}
				hash := row["content_hash"]
				if f.corrupt {
					hash = strings.Repeat("0", 64)
				}
				line, _ := json.Marshal(map[string]any{"ordinal": row["ordinal"], "content_hash": hash})
				w.Write(append(line, '\n'))
			}
		}
	}))
	t.Cleanup(server.Close)
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func endedProjectionRows() []projectionArchiveRow {
	at := reconcileObserved.Add(-40 * 24 * time.Hour)
	return []projectionArchiveRow{
		{Source: reconcileScope.Source, SensorID: reconcileScope.SensorID, CampusID: reconcileScope.CampusID, AccessDomain: reconcileScope.AccessDomain, SessionID: "s1", IP: "10.0.0.1", AccountID: "a1", ConfirmedAt: at, Document: json.RawMessage(`{"session_id":"s1","ended_at":"x"}`)},
		{Source: reconcileScope.Source, SensorID: reconcileScope.SensorID, CampusID: reconcileScope.CampusID, AccessDomain: reconcileScope.AccessDomain, SessionID: "s2", IP: "10.0.0.2", AccountID: "a2", ConfirmedAt: at.Add(time.Second), Document: json.RawMessage(`{"session_id":"s2","ended_at":"y"}`)},
	}
}

// The archive is verified by ordinal and content hash after the insert, and a replay of the same
// batch writes nothing: a crash between archive and delete must not duplicate history.
func TestProjectionArchiveVerifiesAndReplaysIdempotently(t *testing.T) {
	fake := &fakeArchive{}
	ch := fake.serve(t)
	rows := endedProjectionRows()
	if err := ch.WriteIdentityProjectionArchive(context.Background(), "batch-1", rows); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteIdentityProjectionArchive(context.Background(), "batch-1", rows); err != nil {
		t.Fatal(err)
	}
	if fake.inserts != 1 || len(fake.rows) != 2 {
		t.Fatalf("inserts=%d rows=%d want 1 and 2", fake.inserts, len(fake.rows))
	}
	if fake.rows[0]["confirmed_at"] == "" || fake.rows[0]["document"] == "" {
		t.Fatalf("archive row lacks content: %+v", fake.rows[0])
	}
}

func TestProjectionArchiveRejectsConflictingContent(t *testing.T) {
	fake := &fakeArchive{}
	ch := fake.serve(t)
	if err := ch.WriteIdentityProjectionArchive(context.Background(), "batch-1", endedProjectionRows()); err != nil {
		t.Fatal(err)
	}
	fake.corrupt = true
	if err := ch.WriteIdentityProjectionArchive(context.Background(), "batch-1", endedProjectionRows()); err == nil {
		t.Fatal("conflicting archive content accepted")
	}
}

func projectionCandidateRows(rows []projectionArchiveRow) *sqlmock.Rows {
	out := sqlmock.NewRows([]string{"source", "sensor_id", "campus_id", "access_domain", "session_id", "ip", "account_id", "confirmed_at", "document"})
	for _, r := range rows {
		out.AddRow(r.Source, r.SensorID, r.CampusID, r.AccessDomain, r.SessionID, r.IP, r.AccountID, r.ConfirmedAt, []byte(r.Document))
	}
	return out
}

// Ended members leave the hot table only after the archive holds them, and the delete rechecks that
// each row is still the archived, ended, unprotected version.
func TestProjectionRetentionArchivesBeforeDeleting(t *testing.T) {
	db, mock := newReconcileMock(t)
	fake := &fakeArchive{}
	store := &DBStore{pg: &PostgresStore{db: db}, ch: fake.serve(t)}
	now := reconcileObserved
	mock.ExpectQuery(regexp.QuoteMeta(projectionRetentionCandidatesSQL)).
		WithArgs(now.Add(-projectionHotRetention), projectionArchiveBatch).
		WillReturnRows(projectionCandidateRows(endedProjectionRows()))
	mock.ExpectExec(regexp.QuoteMeta(projectionRetentionDeleteSQL)).WillReturnResult(sqlmock.NewResult(0, 2))
	deleted, err := store.archiveEndedProjectionBatch(context.Background(), now)
	if err != nil || deleted != 2 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
	if len(fake.rows) != 2 {
		t.Fatalf("archived=%d want 2 before delete", len(fake.rows))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// If the archive is unavailable nothing is deleted: the hot row is the only copy.
func TestProjectionRetentionKeepsRowsWhenArchiveFails(t *testing.T) {
	db, mock := newReconcileMock(t)
	fake := &fakeArchive{fail: true}
	store := &DBStore{pg: &PostgresStore{db: db}, ch: fake.serve(t)}
	mock.ExpectQuery(regexp.QuoteMeta(projectionRetentionCandidatesSQL)).WillReturnRows(projectionCandidateRows(endedProjectionRows()))
	if _, err := store.archiveEndedProjectionBatch(context.Background(), reconcileObserved); err == nil {
		t.Fatal("archive failure was not reported")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// Only ended members past the 30-day hot window are candidates; case-referenced IPs are kept, and a
// case without an IP keeps everything (fail closed), as device retention does.
func TestProjectionRetentionSelectsOnlyExpiredUnprotectedEndedMembers(t *testing.T) {
	if projectionHotRetention != 30*24*time.Hour {
		t.Fatalf("hot retention=%s want 30 days", projectionHotRetention)
	}
	for name, query := range map[string]string{"candidates": projectionRetentionCandidatesSQL, "delete": projectionRetentionDeleteSQL} {
		for _, required := range []string{
			"COALESCE(p.document->>'ended_at','')<>''",
			"NOT EXISTS (SELECT 1 FROM protected_ips c WHERE c.ip IS NULL)",
			"NOT EXISTS (SELECT 1 FROM protected_ips c WHERE host(c.ip)=p.ip)",
		} {
			if !strings.Contains(query, required) {
				t.Fatalf("%s lacks %q", name, required)
			}
		}
	}
	if !strings.Contains(projectionRetentionCandidatesSQL, "p.confirmed_at<$1") || !strings.Contains(projectionRetentionCandidatesSQL, "ORDER BY p.confirmed_at LIMIT $2") {
		t.Fatalf("candidates not bounded by cutoff and index order: %s", projectionRetentionCandidatesSQL)
	}
	if !strings.Contains(projectionRetentionDeleteSQL, "p.confirmed_at=r.confirmed_at") {
		t.Fatal("delete does not recheck the archived version")
	}
}

// The archive keeps each member at least one year after it entered the hot table: an ended member's
// confirmed_at is when it ended, which is never before its first ingest.
func TestProjectionArchiveKeepsOneYear(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/clickhouse/045_identity_projection_history_archive.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "TTL toDateTime(confirmed_at)+INTERVAL 1 YEAR DELETE") {
		t.Fatalf("archive TTL is not one year:\n%s", raw)
	}
}
