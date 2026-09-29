package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Opt-in isolated read-handler measurement. This is not full OpenAPI/onsite
// acceptance, authentication latency, cold database cache or external execution.
func TestSharedAccessNormalReadPerformance(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_SHARED_PERFORMANCE") != "isolated-read-handlers" {
		t.Skip("explicit isolated performance run required")
	}
	s, actor := taskIntegrationServer(t)
	s.operations.db.SetMaxOpenConns(20)
	s.operations.db.SetMaxIdleConns(5)
	prefix := "shared-perf-" + shortToken(12)
	t.Cleanup(func() {
		s.operations.db.Exec(`DELETE FROM shared_access_review_executions WHERE review_id LIKE $1`, prefix+"%")
		s.operations.db.Exec(`DELETE FROM shared_access_review_evidence WHERE review_id LIKE $1`, prefix+"%")
		s.operations.db.Exec(`DELETE FROM shared_access_reviews WHERE review_id LIKE $1`, prefix+"%")
		s.operations.db.Exec(`DELETE FROM enforcement_actions WHERE action_id=$1`, prefix)
		s.operations.db.Exec(`DELETE FROM enforcement_identity_sources WHERE connector_id=$1`, prefix)
		s.operations.db.Exec(`DELETE FROM enforcement_connectors WHERE connector_id=$1`, prefix)
	})
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.operations.db.Exec(`INSERT INTO enforcement_connectors(connector_id,name,endpoint_url,encrypted_secret,updated_by,connector_type) VALUES($1,$1,'https://192.0.2.190:8001','','isolated','srun4k')`, prefix)
	must(err)
	cfg := map[string]any{"kind": "complete_inventory", "source": prefix, "sensor_id": "isolated", "campus_id": prefix, "access_domain": "office", "user_cidrs": []string{"192.0.2.0/24"}, "max_records": 10000, "enabled": true, "inventory_url": "https://192.0.2.190:8001/existing-inventory"}
	raw, _ := json.Marshal(cfg)
	_, err = s.operations.db.Exec(`INSERT INTO enforcement_identity_sources(connector_id,public_config,state,blocker,observed_at,last_success_at,record_count) VALUES($1,$2,'healthy','',now(),now(),10000)`, prefix, raw)
	must(err)
	result, _ := json.Marshal(map[string]any{"state": "basis_present", "account_id": prefix, "quantity_known": false, "signal_groups": []string{"ua_os", "ttl_path", "tls_stack"}, "observed_at": time.Now().UTC()})
	_, err = s.operations.db.Exec(`INSERT INTO shared_access_reviews(review_id,account_id,campus_id,access_domain,session_generation,latest_version,latest_result) SELECT $1||'-'||g,$1,$1,'office',$1||'-gen-'||g,24,$2::jsonb FROM generate_series(1,1000) g`, prefix, result)
	must(err)
	_, err = s.operations.db.Exec(`INSERT INTO shared_access_review_evidence(review_id,version,evidence_key,evidence) SELECT $1||'-'||g,v,$1||'-'||g||'-e-'||v,jsonb_build_object('result',$2::jsonb,'window',jsonb_build_object('id',$1||'-e-'||v)) FROM generate_series(1,1000) g CROSS JOIN generate_series(1,24) v`, prefix, result)
	must(err)
	_, err = s.operations.db.Exec(`INSERT INTO enforcement_actions(action_id,idempotency_key,connector_id,action_type,subject_type,subject_id,account_id,campus_id,status,mode,created_by) VALUES($1,$1,$1,'disconnect','account',$1,$1,$1,'pending','shadow','isolated')`, prefix)
	must(err)
	_, err = s.operations.db.Exec(`INSERT INTO shared_access_review_executions(review_id,action_id,evidence_version) VALUES($1||'-1',$1,24)`, prefix)
	must(err)
	paths := []string{"/actions/connectors/" + prefix + "/identity-source", "/shared-access/status", "/shared-access/reviews", "/shared-access/reviews/" + prefix + "-1", "/shared-access/reviews/" + prefix + "-1/evidence", "/shared-access/reviews/" + prefix + "-1/executions"}
	type measurement struct {
		MS    float64
		Bytes int
		Valid bool
	}
	for _, path := range paths {
		call := func() measurement {
			r := httptest.NewRequest("GET", "/api/v1"+path, nil)
			r = r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, actor))
			w := httptest.NewRecorder()
			start := time.Now()
			s.dispatchAPI(w, r, path)
			elapsed := float64(time.Since(start).Nanoseconds()) / 1e6
			valid := w.Code == 200 && strings.Contains(w.Body.String(), prefix)
			if path == "/shared-access/status" {
				var body struct {
					Identity []struct {
						ID    string `json:"connector_id"`
						Fresh bool   `json:"fresh"`
						Count int    `json:"record_count"`
					}
				}
				if json.Unmarshal(w.Body.Bytes(), &body) != nil {
					valid = false
				}
				matched := false
				for _, source := range body.Identity {
					if source.ID == prefix && source.Fresh && source.Count == 10000 {
						matched = true
					}
				}
				valid = valid && matched
			}
			return measurement{elapsed, w.Body.Len(), valid}
		}
		first := call()
		if !first.Valid {
			t.Fatalf("normal fixture failed: %s", path)
		}
		for _, concurrency := range []int{1, 20} {
			jobs := make(chan struct{})
			results := make(chan measurement, 200)
			var wg sync.WaitGroup
			for worker := 0; worker < concurrency; worker++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for range jobs {
						results <- call()
					}
				}()
			}
			for sample := 0; sample < 200; sample++ {
				jobs <- struct{}{}
			}
			close(jobs)
			wg.Wait()
			close(results)
			values := []float64{}
			size, errors := 0, 0
			for result := range results {
				values = append(values, result.MS)
				size += result.Bytes
				if !result.Valid {
					errors++
				}
			}
			sort.Float64s(values)
			t.Logf("path=%s concurrency=%d samples=%d first_handler_ms=%.3f p50_ms=%.3f p95_ms=%.3f p99_ms=%.3f error_rate=%.4f mean_response_bytes=%d", strings.ReplaceAll(path, prefix, "{fixture}"), concurrency, len(values), first.MS, values[99], values[189], values[197], float64(errors)/200, size/200)
			if errors != 0 || values[189] > 500 || values[197] >= 1000 {
				t.Errorf("read handler threshold failed: %s", path)
			}
		}
	}
	for _, query := range []string{
		fmt.Sprintf(`SELECT version FROM shared_access_review_evidence WHERE review_id='%s-1' ORDER BY version DESC LIMIT 21`, prefix),
		`SELECT review_id FROM shared_access_reviews ORDER BY created_at DESC,review_id DESC LIMIT 21`,
	} {
		var plan json.RawMessage
		must(s.operations.db.QueryRow(`EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON) ` + query).Scan(&plan))
		t.Logf("sql_plan=%s", plan)
	}
	t.Log("scope=isolated read handlers; fixtures=1000 reviews/24000 evidence versions; 10M application load, invalidation, cold-process/cache, authentication, lock-wait sampling, writes and full OpenAPI remain unverified")
}
