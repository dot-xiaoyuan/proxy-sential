package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"proxy-sentinel/internal/store"
	"testing"
	"time"
)

func TestPostgresCaseQueueIsIndependentOfSynchronization(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	prefix := fmt.Sprintf("queue-test-%d", time.Now().UnixNano())
	defer db.ExecContext(context.Background(), `DELETE FROM risk_cases WHERE campus_id=$1`, prefix)
	_, err = db.ExecContext(ctx, `INSERT INTO risk_cases(case_id,dedupe_key,subject_type,subject_id,ip,campus_id,department,person_type,ssid,vlan,ap,nas_ip,status,priority,assignee_id,risk_score,risk_confidence,assessment_level,first_seen,last_seen,created_at,updated_at) SELECT $1||'-'||lpad(n::text,5,'0'),$1||'-'||n,'ip',$1||'-'||n,'192.0.2.1'::inet,$1,'computing','student','wifi','310','ap-1','192.0.2.254'::inet,CASE WHEN n%2=0 THEN 'assigned' ELSE 'new' END,'high','operator',90,0.9,'high',now(),now(),now(),now() FROM generate_series(1,10000) n`, prefix)
	if err != nil {
		t.Fatal(err)
	}
	operations := &operationsState{db: db}
	operations.mu.owner = operations
	// Hold both synchronization locks and the evidence-history table; queue reads
	// must need none of them, including the hidden reload inside operations.mu.
	lock, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err = lock.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('proxy-sentinel-operations')); LOCK risk_case_evidence_snapshots IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	operations.mu.Mutex.Lock()
	defer operations.mu.Mutex.Unlock()
	server := &Server{reader: forbiddenCaseAggregation{}, operations: operations}
	fetch := func(query string) ([]RiskCase, Page) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/cases?campus_id="+url.QueryEscape(prefix)+query, nil)
		reqCtx, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		req = req.WithContext(reqCtx)
		response := httptest.NewRecorder()
		started := time.Now()
		server.handleCases(response, req)
		if response.Code != 200 {
			t.Fatalf("queue blocked or failed: %d %s", response.Code, response.Body.String())
		}
		var body struct {
			Items []RiskCase `json:"items"`
			Page  Page       `json:"page"`
		}
		if err = json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		t.Logf("10000 cases, %d rows, query %s", len(body.Items), time.Since(started))
		return body.Items, body.Page
	}
	items, page := fetch("&limit=20")
	if len(items) != 20 || page.Total != 10000 || page.NextCursor == nil || *page.NextCursor != "20" || items[0].IP != "192.0.2.1" || len(items[0].EvidenceHistory) != 0 {
		t.Fatalf("incorrect queue page %+v %+v", page, items[0])
	}
	second, _ := fetch("&limit=20&cursor=20")
	if second[0].CaseID == items[0].CaseID {
		t.Fatal("unstable pagination")
	}
	filtered, filteredPage := fetch("&status=assigned&department=computing&person_type=student&ssid=wifi&vlan=310&ap=ap-1&nas_ip=192.0.2.254&assignee_id=operator&q=" + url.QueryEscape(prefix))
	if len(filtered) != 20 || filteredPage.Total != 5000 {
		t.Fatalf("filters changed %+v", filteredPage)
	}
	empty, last := fetch("&cursor=10001&limit=20")
	if len(empty) != 0 || last.Total != 10000 || last.NextCursor != nil {
		t.Fatalf("out-of-range page %+v", last)
	}
}
