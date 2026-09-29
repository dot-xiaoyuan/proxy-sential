package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"proxy-sentinel/internal/store"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCaseHistoryPostgresBoundedAndDiscoveryEvidencePreserved(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id := fmt.Sprintf("case-page-%d", time.Now().UnixNano())
	defer func() {
		for _, table := range []string{"risk_case_evidence_snapshots", "risk_case_comments", "risk_case_timeline", "risk_cases"} {
			db.ExecContext(ctx, "DELETE FROM "+table+" WHERE case_id=$1", id)
		}
	}()
	_, err = db.ExecContext(ctx, `INSERT INTO risk_cases(case_id,dedupe_key,subject_type,subject_id,status,priority,risk_score,risk_confidence,assessment_level,first_seen,last_seen) VALUES($1,$1,'ip',$1,'new','high',90,.9,'high',now(),now())`, id)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO risk_case_evidence_snapshots(snapshot_id,case_id,evidence,created_at) SELECT $1||'-'||n,$1,jsonb_build_object('case_id',$1,'event_count',n),now()+n*interval '1 second' FROM generate_series(1,45)n`, id)
	if err != nil {
		t.Fatal(err)
	}
	ops := &operationsState{db: db}
	ops.mu.owner = ops
	s := &Server{operations: ops}
	lock, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err = lock.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext('proxy-sentinel-operations'))"); err != nil {
		t.Fatal(err)
	}
	ops.mu.Mutex.Lock()
	defer ops.mu.Mutex.Unlock()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/cases/"+id, nil)
	s.getCasePostgres(w, r, id)
	if w.Code != 200 {
		t.Fatalf("detail: %d %s", w.Code, w.Body.String())
	}
	var item RiskCase
	if err = json.Unmarshal(w.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if len(item.EvidenceHistory) != 20 || item.HistoryPage["evidence"].Total != 45 || item.EvidenceSnapshot.EventCount != 1 {
		t.Fatalf("bounded/discovery invariant: history=%d page=%+v evidence=%+v", len(item.EvidenceHistory), item.HistoryPage, item.EvidenceSnapshot)
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "/api/v1/cases/"+id+"/history/evidence?limit=20&cursor=20", nil)
	s.caseHistoryPostgres(w, r, id, "evidence")
	var page struct {
		Items []CaseEvidenceSnapshot
		Page  store.Page
	}
	if err = json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(page.Items) != 20 || page.Page.NextCursor == nil || *page.Page.NextCursor != "40" {
		t.Fatalf("second page: %d %s", w.Code, w.Body.String())
	}
	// Twenty successful saves on the same case must append all histories even
	// while the unrelated legacy/global lock remains held.
	var wg sync.WaitGroup
	failures := make(chan string, 20)
	for n := 0; n < 20; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			request := httptest.NewRequest("POST", "/api/v1/cases/"+id+"/comments", strings.NewReader(fmt.Sprintf(`{"comment":"parallel comment %d"}`, n)))
			response := httptest.NewRecorder()
			s.mutateCase(response, request, id, "comments")
			if response.Code != 200 {
				failures <- fmt.Sprintf("%d %s", response.Code, response.Body.String())
			}
		}(n)
	}
	wg.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	var count int
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM risk_case_comments WHERE case_id=$1", id).Scan(&count); err != nil || count != 20 {
		t.Fatalf("successful responses must commit immediately: comments=%d err=%v", count, err)
	}

	if summary, err := s.operationsSummary(ctx); err != nil || summary["open"] < 1 {
		t.Fatalf("independent summary: %v %v", summary, err)
	}
	if _, err = s.operationsReadView(ctx); err != nil {
		t.Fatalf("independent action read: %v", err)
	}
}
