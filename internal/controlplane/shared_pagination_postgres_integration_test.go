package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// All fixtures live only in the explicitly supplied isolated database. No
// worker is started, and the execution fixtures are record-only shadow rows.
func TestSharedNumberedPaginationPostgres(t *testing.T) {
	s, _ := taskIntegrationServer(t)
	s.productPolicies = &productPolicyState{db: s.operations.db}
	prefix := "numbered-shared-" + shortToken(12)
	stamp := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	snapshot := stamp.Add(time.Second)
	t.Cleanup(func() {
		for _, statement := range []string{
			`DELETE FROM shared_access_review_executions WHERE review_id LIKE $1`,
			`DELETE FROM shared_access_review_evidence WHERE review_id LIKE $1`,
			`DELETE FROM shared_access_reviews WHERE review_id LIKE $1`,
			`DELETE FROM enforcement_actions WHERE action_id LIKE $1`,
			`DELETE FROM policy_decision_records WHERE decision_id LIKE $1`,
		} {
			if _, err := s.operations.db.Exec(statement, prefix+"%"); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
	})
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := s.operations.db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	var baseline int
	if err := s.operations.db.QueryRow(`SELECT count(*) FROM shared_access_reviews WHERE created_at<=$1`, snapshot).Scan(&baseline); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("%s-%d", prefix, i)
		at := stamp
		if i == 5 {
			at = snapshot.Add(time.Second)
		}
		exec(`INSERT INTO shared_access_reviews(review_id,account_id,campus_id,access_domain,session_generation,latest_result,created_at) VALUES($1,$1,$1,'test',$1,'{}',$2)`, id, at)
		exec(`INSERT INTO policy_decision_records(decision_id,execution_id,policy_id,policy_revision,account_id,known,violated,evaluated_at,document,trigger_type,result) VALUES($1,$1,$1,1,$2,true,false,$3,jsonb_build_object('decision_id',$1::text),'shared_access','matched')`, id, prefix, at)
		exec(`INSERT INTO shared_access_review_evidence(review_id,version,evidence_key,evidence,created_at) VALUES($1,$2,$3,'{}',$4)`, prefix+"-1", i, id, at)
		exec(`INSERT INTO enforcement_actions(action_id,idempotency_key,action_type,subject_type,subject_id,status,mode,created_by,created_at) VALUES($1,$1,'disconnect','account',$1,'recorded','shadow','isolated-replay',$2)`, id, at)
		exec(`INSERT INTO shared_access_review_executions(review_id,action_id,evidence_version,created_at) VALUES($1,$2,$3,$4)`, prefix+"-1", id, i, at)
	}
	call := func(path string, status int) map[string]json.RawMessage {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		route := strings.Split(path, "?")[0]
		switch route {
		case "/policy-decisions":
			s.queryPolicyDecisions(w, r)
		case "/policy-decisions/metadata":
			s.queryPolicyDecisionMetadata(w, r)
		case "/policy-decisions/position":
			s.queryPolicyDecisionPosition(w, r)
		default:
			s.handleSharedReviews(w, r, route)
		}
		if w.Code != status {
			t.Fatalf("%s: status=%d want=%d %s", path, w.Code, status, w.Body.String())
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	for _, tc := range []struct {
		path, key, extra string
		total            int
	}{
		{"/policy-decisions", "decision_id", "&trigger=shared_access&result=matched&account_id=" + prefix, 4},
		{"/shared-access/reviews", "review_id", "", baseline + 4},
		{"/shared-access/reviews/" + prefix + "-1/evidence", "version", "", 4},
		{"/shared-access/reviews/" + prefix + "-1/executions", "action_id", "", 4},
	} {
		t.Run(tc.key, func(t *testing.T) {
			query := "snapshot=" + url.QueryEscape(snapshot.Format(time.RFC3339Nano)) + tc.extra
			meta := call(tc.path+"/metadata?"+query, 200)
			var total int
			if err := json.Unmarshal(meta["total"], &total); err != nil || total != tc.total {
				t.Fatalf("metadata=%s wanted=%d", meta["total"], tc.total)
			}
			position := call(tc.path+"/position?"+query+"&page=1&limit=2", 200)
			if string(position["cursor"]) != `""` {
				t.Fatal("page one must use empty cursor")
			}
			position = call(tc.path+"/position?"+query+"&page=2&limit=2", 200)
			var cursor string
			_ = json.Unmarshal(position["cursor"], &cursor)
			if cursor == "" {
				t.Fatal("missing page boundary")
			}
			page := call(tc.path+"?"+query+"&limit=2&cursor="+url.QueryEscape(cursor), 200)
			var items []map[string]json.RawMessage
			_ = json.Unmarshal(page["items"], &items)
			if len(items) != 2 {
				t.Fatalf("wrong target page %s", page["items"])
			}
			for i, item := range items {
				if tc.key == "version" {
					if string(item[tc.key]) != fmt.Sprint(2-i) {
						t.Fatalf("wrong version page %s", page["items"])
					}
				} else if string(item[tc.key]) != fmt.Sprintf("%q", fmt.Sprintf("%s-%d", prefix, 2-i)) {
					t.Fatalf("wrong ID page %s", page["items"])
				}
			}
			beyond := tc.total/2 + 2
			call(fmt.Sprintf("%s/position?%s&page=%d&limit=2", tc.path, query, beyond), 400)
			call(tc.path+"/position?page=0", 400)
			call(tc.path+"/metadata?snapshot=broken", 400)
			if tc.key != "review_id" { // exact-full last page must not imply a third page.
				call(tc.path+"/position?"+query+"&page=3&limit=2", 400)
			}
		})
	}
	call("/shared-access/reviews/absent-"+prefix+"/evidence/metadata", 404)
	// The new append is visible only after refreshing the snapshot.
	latest := call("/shared-access/reviews/"+prefix+"-1/evidence/metadata?snapshot="+url.QueryEscape(snapshot.Add(2*time.Second).Format(time.RFC3339Nano)), 200)
	if string(latest["total"]) != "5" {
		t.Fatal("refresh did not expose appended evidence")
	}
}
