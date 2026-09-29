package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/srunapi"
	"proxy-sentinel/internal/store"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestSharedDisconnectPersistedNormalAndChangingTargets(t *testing.T) {
	for _, scenario := range []string{"normal", "restart", "cancelled_task", "new_session", "conclusion_changed", "config_changed", "revoked", "expired", "evidence_changed", "coverage_unknown", "source_failed", "partial_failure"} {
		t.Run(scenario, func(t *testing.T) { runSharedDisconnectFixture(t, scenario) })
	}
}
func runSharedDisconnectFixture(t *testing.T, scenario string, sample ...*time.Duration) {
	s, actor := taskIntegrationServer(t)
	s.actionMasterKey = []byte("01234567890123456789012345678901")
	s.exceptions = newExceptionManager(nil)
	id := "manual-review-" + shortToken(12)
	now := time.Now().UTC().Truncate(time.Microsecond)
	rows := []map[string]string{{"session_id": "radius-one", "rad_online_id": "171", "user_name": "yuantong", "ip": "192.0.2.93", "add_time": "1750000000"}, {"session_id": "radius-two", "rad_online_id": "172", "user_name": "yuantong", "ip": "192.0.2.94", "add_time": "1750000000"}}
	var mutex sync.Mutex
	sends := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		switch r.URL.Path {
		case "/inventory":
			if r.Header.Get("Authorization") != "Bearer fixture-token" {
				t.Error("missing inventory credential")
			}
			json.NewEncoder(w).Encode(map[string]any{"schema_version": "online-inventory/v1", "instance_id": "fixture", "observed_at": time.Now().UTC().Truncate(time.Microsecond), "campus_id": id, "access_domain": "office", "complete": true, "expected_count": len(rows), "rows": rows})
		case "/api/v2/auth/get-access-token":
			w.Write([]byte(`{"code":0,"data":{"access_token":"fixture","lifetime":60}}`))
		case "/api/v2/base/online-drop":
			r.ParseForm()
			if r.Form.Get("user_name") != "yuantong" || r.Form.Get("drop_type") != "radius" {
				t.Error("wrong target")
			}
			sends++
			if scenario == "partial_failure" && r.Form.Get("rad_online_id") == "172" {
				w.Write([]byte(`{"code":1,"data":{}}`))
				return
			}
			next := []map[string]string{}
			for _, row := range rows {
				if row["rad_online_id"] != r.Form.Get("rad_online_id") {
					next = append(next, row)
				}
			}
			rows = next
			w.Write([]byte(`{"code":0,"data":{}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	_, err := s.operations.db.Exec(`INSERT INTO enforcement_connectors(connector_id,name,endpoint_url,certificate_pem,encrypted_secret,updated_by,connector_type,enabled,mode) VALUES($1,'fixture',$2,$3,'','fixture','srun4k',true,'shadow')`, id, server.URL, cert)
	if err != nil {
		t.Fatal(err)
	}
	cfg := managedIdentityConfig{Kind: "complete_inventory", Enabled: true, MaxRecords: 10000, InventoryURL: server.URL + "/inventory", UserCIDRs: []string{"192.0.2.0/24"}, IdentityScope: store.IdentityScope{Source: id, SensorID: id, CampusID: id, AccessDomain: "office"}}
	raw, _ := json.Marshal(cfg)
	token, _ := s.encryptConnectorSecret("fixture-token")
	_, err = s.operations.db.Exec(`INSERT INTO enforcement_identity_sources(connector_id,public_config,encrypted_token,state,observed_at,last_success_at) VALUES($1,$2,$3,'healthy',$4,$4)`, id, raw, []byte(token), now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db := s.operations.db
		db.Exec(`DELETE FROM native_action_observations WHERE idempotency_key IN (SELECT idempotency_key FROM enforcement_actions WHERE connector_id=$1)`, id)
		db.Exec(`DELETE FROM native_action_dispatch WHERE idempotency_key IN (SELECT idempotency_key FROM enforcement_actions WHERE connector_id=$1)`, id)
		db.Exec(`DELETE FROM audit_logs WHERE target IN (SELECT review_id FROM shared_access_reviews WHERE campus_id=$1) OR audit_id IN (SELECT grant_id FROM shared_manual_disconnect_grants WHERE connector_id=$1) OR target IN (SELECT action_id FROM enforcement_actions WHERE connector_id=$1) OR actor=$2`, id, actor.User.ID)
		db.Exec(`DELETE FROM shared_access_review_executions WHERE review_id IN (SELECT review_id FROM shared_access_reviews WHERE campus_id=$1)`, id)
		db.Exec(`DELETE FROM enforcement_actions WHERE connector_id=$1`, id)
		db.Exec(`DELETE FROM shared_manual_disconnect_grants WHERE connector_id=$1`, id)
		db.Exec(`DELETE FROM shared_access_review_conclusions WHERE review_id IN (SELECT review_id FROM shared_access_reviews WHERE campus_id=$1)`, id)
		db.Exec(`DELETE FROM shared_access_review_evidence WHERE review_id IN (SELECT review_id FROM shared_access_reviews WHERE campus_id=$1)`, id)
		db.Exec(`DELETE FROM shared_access_reviews WHERE campus_id=$1`, id)
		db.Exec(`DELETE FROM enforcement_identity_sources WHERE connector_id=$1`, id)
		db.Exec(`DELETE FROM enforcement_connectors WHERE connector_id=$1`, id)
	})
	inventory := legacy4k.OnlineInventory{InstanceID: fmt.Sprintf("4k:%s:config-1:fixture", id), ObservedAt: now, Rows: rows}
	records, err := inventory.IdentityRecords()
	if err != nil {
		t.Fatal(err)
	}
	sessions := []policy.Session{}
	for _, record := range records {
		sessions = append(sessions, policy.Session{ID: record["session_id"], AccountID: "yuantong", IP: record["ip"], Source: id, SensorID: id, CampusID: id, AccessDomain: "office", StartedAt: time.Unix(1750000000, 0).UTC(), ConfirmedAt: now, Confirmations: []time.Time{now.Add(-30 * time.Second), now.Add(-20 * time.Second), now.Add(-10 * time.Second), now}, HeartbeatSeconds: 5})
	}
	window := sharedaccess.Window{ID: id + "-window", RuleVersion: sharedaccess.RuleVersion, IP: "192.0.2.93", SensorID: id, CampusID: id, AccessDomain: "office", Sources: []string{"suricata"}, From: now.Add(-30 * time.Second), To: now, LastObservedAt: now, Complete: true, EventIDs: []string{"event"}, UAOS: []string{"Android", "Windows"}, TTLPaths: []string{"63", "127"}, TLSStacks: []string{"a", "b"}}
	addSharedRepeatedSamples(&window)
	s.sharedConfig = sharedaccess.Config{Version: id, FreshnessSeconds: 180, Sources: []sharedaccess.Source{{SensorID: id, Source: "suricata", CampusID: id, AccessDomain: "office"}}}
	s.reader = sharedTestReader{policySandboxReader: policySandboxReader{sessions: sessions}, windows: []sharedaccess.Window{window}}
	evaluated, err := s.sharedWindows(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	result := sharedaccess.Evaluate(evaluated[0], s.sharedConfig, sessions, now, 10*time.Minute)
	if result.State != "basis_present" {
		t.Fatal(result)
	}
	if err = s.persistSharedReview(context.Background(), result, evaluated[0], reviewGeneration(result, sessions)); err != nil {
		t.Fatal(err)
	}
	var review string
	s.operations.db.QueryRow(`SELECT review_id FROM shared_access_reviews WHERE campus_id=$1`, id).Scan(&review)
	_, err = s.operations.db.Exec(`INSERT INTO shared_access_review_conclusions(review_id,evidence_version,operator_id,conclusion,reason) VALUES($1,1,$2,'shared','isolated fixture')`, review, actor.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.buildSharedDisconnectPreview(context.Background(), review)
	if err != nil || !p.Ready || len(p.Plan.Sessions) != 2 {
		t.Fatal(p, err)
	}
	// Production uses the dynamic DB credential provider. This isolated controller
	// uses fixture credentials; inventory still goes through the managed HTTPS reader.
	runtime, _, err := s.managedDisconnectRuntime(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := srunapi.New(server.URL, "fixture", "fixture", server.Client())
	runtime.Client = client
	s.nativeActions = map[string]NativeActionRuntime{id: runtime}
	s.operations.mu.owner = s.operations
	if scenario == "performance" {
		runSharedPreviewPerformance(t, s, actor, review, id)
		return
	}
	if scenario == "confirm_performance" {
		s.reader = sharedContinuousFixtureReader{s.reader.(sharedTestReader)}
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					s.operations.db.Exec(`UPDATE enforcement_identity_sources SET observed_at=now()-interval '1 second',last_success_at=now()-interval '1 second' WHERE connector_id=$1`, id)
				}
			}
		}()
	}
	body, _ := json.Marshal(map[string]any{"fingerprint": p.Fingerprint, "evidence_version": p.EvidenceVersion, "identity_version": p.IdentityVersion, "config_version": p.ConfigVersion, "authorize_designated_test": true})
	submit := func() operationTask {
		r := httptest.NewRequest("POST", "/api/v1/shared-access/reviews/"+review+"/disconnect", bytes.NewReader(body))
		r.Header.Set("Idempotency-Key", id)
		r = r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, actor))
		w := httptest.NewRecorder()
		begin := time.Now()
		s.submitOperationTask(w, r, "/shared-access/reviews/"+review+"/disconnect")
		if len(sample) > 0 && *sample[0] == 0 {
			*sample[0] = time.Since(begin)
		}
		if w.Code != 202 {
			t.Fatal(w.Code, w.Body.String())
		}
		var task operationTask
		json.Unmarshal(w.Body.Bytes(), &task)
		return task
	}
	task := submit()
	if duplicate := submit(); duplicate.TaskID != task.TaskID {
		t.Fatal("duplicate task")
	}
	if scenario == "cancelled_task" {
		if err := s.cancelOperationTask(context.Background(), task.TaskID); err != nil {
			t.Fatal(err)
		}
		if s.runNextOperationTask("fixture-worker") {
			t.Fatal("cancelled confirmation was claimed")
		}
		var grants int
		s.operations.db.QueryRow(`SELECT count(*) FROM shared_manual_disconnect_grants WHERE connector_id=$1`, id).Scan(&grants)
		if grants != 0 {
			t.Fatal("cancelled task granted control")
		}
		return
	}
	if scenario == "confirm_performance" {
		// Fixture servers have different replay readers. Serialize test claims
		// by queue order so each persisted request is handled by its own fixture.
		deadline := time.Now().Add(30 * time.Second)
		for {
			sharedConfirmFixtureClaim.Lock()
			var next string
			s.operations.db.QueryRow(`SELECT task_id FROM control_plane_tasks WHERE status='queued' ORDER BY created_at,task_id LIMIT 1`).Scan(&next)
			if next == task.TaskID {
				break
			}
			sharedConfirmFixtureClaim.Unlock()
			if time.Now().After(deadline) {
				t.Fatal("fixture claim deadline exceeded")
			}
			time.Sleep(time.Millisecond)
		}
	}
	claimed := s.runNextOperationTask("fixture-worker")
	if scenario == "confirm_performance" {
		sharedConfirmFixtureClaim.Unlock()
	}
	if !claimed {
		t.Fatal("task not claimed")
	}
	job, err := s.readOperationTask(context.Background(), task.TaskID, actor)
	if err != nil || job.Status != "completed" {
		t.Fatal(job, string(job.Result), err)
	}
	var queued struct {
		Grant   string   `json:"grant_id"`
		Actions []string `json:"action_ids"`
	}
	json.Unmarshal(job.Result, &queued)
	if len(queued.Actions) != 2 {
		t.Fatal(string(job.Result))
	}
	if followup, e := s.buildSharedDisconnectPreview(context.Background(), review); e != nil || followup.Ready || !sharedFixtureContains(followup.Blockers, "subject_cooldown_active") {
		t.Fatalf("cooldown missing: %+v %v", followup, e)
	}
	switch scenario {
	case "new_session":
		mutex.Lock()
		rows = append(rows, map[string]string{"session_id": "new", "rad_online_id": "173", "user_name": "yuantong", "ip": "192.0.2.95", "add_time": "1750000001"})
		mutex.Unlock()
	case "conclusion_changed":
		s.operations.db.Exec(`INSERT INTO shared_access_review_conclusions(review_id,evidence_version,operator_id,conclusion,reason) VALUES($1,1,$2,'normal','changed')`, review, actor.User.ID)
	case "config_changed":
		s.operations.db.Exec(`UPDATE enforcement_identity_sources SET config_version=config_version+1 WHERE connector_id=$1`, id)
	case "expired":
		s.operations.db.Exec(`UPDATE shared_manual_disconnect_grants SET expires_at=now()-interval '1 second' WHERE grant_id=$1`, queued.Grant)
	case "evidence_changed":
		s.operations.db.Exec(`UPDATE shared_access_reviews SET latest_version=latest_version+1 WHERE review_id=$1`, review)
	case "source_failed":
		s.operations.db.Exec(`UPDATE enforcement_identity_sources SET state='unavailable' WHERE connector_id=$1`, id)
	case "coverage_unknown":
		s.reader = policySandboxReader{sessions: sessions}
	case "revoked":
		s.operations.db.Exec(`UPDATE shared_manual_disconnect_grants SET revoked=true WHERE grant_id=$1`, queued.Grant)
	}
	if err = s.operations.reloadPostgres(context.Background(), s.operations.db); err != nil {
		t.Fatal(err)
	}
	var restarted *Server
	if scenario == "restart" {
		ops, err := newOperationsState("", os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
		if err != nil {
			t.Fatal(err)
		}
		defer ops.db.Close()
		view := *s
		view.operations = ops
		restarted = &view
	}
	for _, action := range queued.Actions {
		if scenario == "normal" || scenario == "restart" || scenario == "confirm_performance" || scenario == "partial_failure" {
			a := s.operations.doc.Actions[action]
			if e := s.validateSharedDisconnectDelivery(context.Background(), a); e != nil {
				t.Fatalf("preflight grant guard: %v", e)
			}
		}
		delivery := s
		if restarted != nil {
			delivery = restarted
		}
		if !delivery.deliverNativeAction(action, false) {
			t.Fatal("not native")
		}
	}
	mutex.Lock()
	sent := sends
	mutex.Unlock()
	if scenario == "normal" || scenario == "restart" || scenario == "confirm_performance" || scenario == "partial_failure" {
		if sent != 2 {
			t.Fatal("wrong sends", sent)
		}
	} else if sent != 0 {
		t.Fatal("changed approval sent", sent)
	}
	succeeded, failed := 0, 0
	for _, action := range queued.Actions {
		var status string
		s.operations.db.QueryRow(`SELECT status FROM enforcement_actions WHERE action_id=$1`, action).Scan(&status)
		if status == "succeeded" {
			succeeded++
		}
		if status == "failed" {
			failed++
		}
		if (scenario == "normal" || scenario == "restart" || scenario == "confirm_performance") && status != "succeeded" {
			t.Fatal("accepted was not independently verified", status)
		}
	}
	if scenario == "partial_failure" && (succeeded != 1 || failed != 1) {
		t.Fatalf("partial results lost: succeeded=%d failed=%d", succeeded, failed)
	}
}

func sharedFixtureContains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func TestSharedDisconnectTaskNormalPerformance(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_SHARED_MANUAL_PERFORMANCE") != "isolated-tasks" {
		t.Skip("explicit isolated benchmark opt-in required")
	}
	runSharedDisconnectFixture(t, "performance")
}

// The isolated simulator emits ongoing coverage heartbeats for the fixed replay
// interval. No production health fact is inferred from the evidence window.
type sharedContinuousFixtureReader struct{ sharedTestReader }

func (r sharedContinuousFixtureReader) ListIngestDiagnostics(ctx context.Context, q store.Query) ([]ingest.Diagnostic, error) {
	items, err := r.sharedTestReader.ListIngestDiagnostics(ctx, q)
	for i := range items {
		at := time.Now().UTC().Add(-time.Second)
		old, _ := time.Parse(time.RFC3339Nano, items[i].Timestamp)
		if old.After(at) {
			at = old
		}
		items[i].Timestamp = at.Format(time.RFC3339Nano)
	}
	return items, err
}
func runSharedPreviewPerformance(t *testing.T, s *Server, actor Session, review, connector string) {
	s.reader = sharedContinuousFixtureReader{s.reader.(sharedTestReader)}
	for _, concurrency := range []int{1, 20} {
		const count = 200
		submitted := make([]operationTask, count)
		durations := make([]time.Duration, count)
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for i := 0; i < count; i++ {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int) {
				defer wg.Done()
				defer func() { <-sem }()
				r := httptest.NewRequest("POST", "/api/v1/shared-access/reviews/"+review+"/disconnect-preview", bytes.NewBufferString("{}"))
				r.Header.Set("Idempotency-Key", fmt.Sprintf("%s-%d-%d", connector, concurrency, i))
				r = r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, actor))
				w := httptest.NewRecorder()
				begin := time.Now()
				s.submitOperationTask(w, r, "/shared-access/reviews/"+review+"/disconnect-preview")
				durations[i] = time.Since(begin)
				if w.Code != 202 {
					t.Errorf("normal task submission: %d %s", w.Code, w.Body.String())
					return
				}
				if err := json.Unmarshal(w.Body.Bytes(), &submitted[i]); err != nil {
					t.Error(err)
				}
			}(i)
		}
		wg.Wait()
		// Two bounded workers validate every business result, not merely response headers.
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					s.operations.db.Exec(`UPDATE enforcement_identity_sources SET observed_at=now(),last_success_at=now() WHERE connector_id=$1`, connector)
					if !s.runNextOperationTask("isolated-preview-worker") {
						return
					}
				}
			}()
		}
		wg.Wait()
		sharedTaskDistribution(t, "preview-submit", concurrency, durations)
		statusTimes := make([]time.Duration, count)
		for i := 0; i < count; i++ {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int) {
				defer wg.Done()
				defer func() { <-sem }()
				begin := time.Now()
				job, err := s.readOperationTask(context.Background(), submitted[i].TaskID, actor)
				statusTimes[i] = time.Since(begin)
				var p sharedDisconnectPreview
				if err != nil || job.Status != "completed" || json.Unmarshal(job.Result, &p) != nil || !p.Ready || len(p.Plan.Sessions) != 2 {
					t.Errorf("invalid normal preview result: %s %s %v", job.Status, job.Result, err)
				}
			}(i)
		}
		wg.Wait()
		sharedTaskDistribution(t, "task-status", concurrency, statusTimes)
	}
}
func sharedTaskDistribution(t *testing.T, name string, concurrency int, values []time.Duration) {
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	p50, p95, p99 := values[99], values[189], values[197]
	t.Logf("%s concurrency=%d samples=200 p50=%s p95=%s p99=%s", name, concurrency, p50, p95, p99)
	if p95 > 500*time.Millisecond || p99 >= time.Second {
		t.Errorf("%s response threshold exceeded", name)
	}
}

var sharedConfirmFixtureClaim sync.Mutex

func TestSharedDisconnectConfirmNormalPerformance(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_SHARED_MANUAL_PERFORMANCE") != "isolated-tasks" {
		t.Skip("explicit isolated benchmark opt-in required")
	}
	for _, concurrency := range []int{1, 20} {
		t.Run(fmt.Sprintf("concurrency-%d", concurrency), func(t *testing.T) {
			values := make([]time.Duration, 200)
			sem := make(chan struct{}, concurrency)
			var wg sync.WaitGroup
			for i := 0; i < 200; i++ {
				wg.Add(1)
				sem <- struct{}{}
				go func(i int) {
					defer wg.Done()
					defer func() { <-sem }()
					t.Run(fmt.Sprintf("normal-%03d", i), func(t *testing.T) { runSharedDisconnectFixture(t, "confirm_performance", &values[i]) })
				}(i)
			}
			wg.Wait()
			sharedTaskDistribution(t, "disconnect-confirm-submit", concurrency, values)
		})
	}
}
func (r sharedContinuousFixtureReader) ListPolicySessions(ctx context.Context, at time.Time) ([]policy.Session, error) {
	original, err := r.policySandboxReader.ListPolicySessions(ctx, at)
	items := append([]policy.Session(nil), original...)
	for i := range items {
		items[i].ConfirmedAt = time.Now().UTC()
		items[i].Confirmations = append(append([]time.Time(nil), items[i].Confirmations...), items[i].ConfirmedAt)
	}
	return items, err
}
