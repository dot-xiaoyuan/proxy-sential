package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recoveryTransportTestScope struct {
	key   string
	lease string
}

func TestRecoveryTransportNativeManualRetryRetainsActualAttemptSequence(t *testing.T) {
	for _, retrySucceeds := range []bool{true, false} {
		name := "recovered"
		if !retrySucceeds {
			name = "failed_again"
		}
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			var completed atomic.Bool
			completed.Store(retrySucceeds)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			var expected atomic.Pointer[recoveryTransportTestScope]
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				call := calls.Add(1)
				var body struct {
					Action string                 `json:"action"`
					Revoke bool                   `json:"revoke"`
					Policy PolicyActionParameters `json:"policy"`
				}
				scope := expected.Load()
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || scope == nil || !body.Revoke || body.Action != "release" || r.Header.Get("Idempotency-Key") != scope.key || body.Policy.LeaseID != scope.lease {
					t.Error("manual transport retry changed the original recovery payload")
				}
				if call == 4 {
					close(entered)
					<-release
				}
				if call <= 3 || !completed.Load() {
					w.WriteHeader(http.StatusServiceUnavailable)
					w.Write([]byte(`{"error":"owned temporary transport failure"}`))
					return
				}
				w.Write([]byte(`{"action_id":"owned-recovery-receipt","status":"completed"}`))
			}))
			defer remote.Close()
			defer unblock()
			s, parent, child := actionRecoveryNativeFixture(t, remote.URL, "manual-revoke")
			expectedKey := child.IdempotencyKey
			expected.Store(&recoveryTransportTestScope{key: expectedKey, lease: child.PolicyParameters.LeaseID})
			db := s.operations.db
			if _, err := db.Exec(`UPDATE enforcement_connectors SET consecutive_failures=0 WHERE connector_id=$1`, child.ConnectorID); err != nil {
				t.Fatal(err)
			}
			for attempt := 1; attempt <= 3; attempt++ {
				if attempt > 1 {
					// Advance only the owned fixture's retry clock; all three failed
					// requests and attempt rows are produced by the real delivery path.
					if _, err := db.Exec(`UPDATE enforcement_actions SET next_attempt_at=now()-interval '1 second' WHERE action_id=$1`, child.ActionID); err != nil {
						t.Fatal(err)
					}
				}
				s.deliverAction(child.ActionID, true)
			}
			var status, parentStatus, key, numbers string
			var retryCount, attempts, audits, actionRows, failures int
			var due sql.NullTime
			read := func() {
				t.Helper()
				if err := db.QueryRow(`SELECT a.status,a.retry_count,a.next_attempt_at,a.idempotency_key,p.status,c.consecutive_failures,(SELECT count(*) FROM enforcement_actions WHERE connector_id=a.connector_id),(SELECT count(*) FROM enforcement_action_attempts WHERE action_id=a.action_id),(SELECT string_agg(attempt_number::text,',' ORDER BY attempt_number) FROM enforcement_action_attempts WHERE action_id=a.action_id),(SELECT count(*) FROM audit_logs WHERE target=p.action_id AND action='enforcement.revoke.retry' AND actor='owned-transport-operator') FROM enforcement_actions a JOIN enforcement_actions p ON p.action_id=a.parent_action_id JOIN enforcement_connectors c ON c.connector_id=a.connector_id WHERE a.action_id=$1`, child.ActionID).Scan(&status, &retryCount, &due, &key, &parentStatus, &failures, &actionRows, &attempts, &numbers, &audits); err != nil {
					t.Fatal(err)
				}
			}
			read()
			if status != "failed" || retryCount != 3 || due.Valid || attempts != 3 || numbers != "1,2,3" || failures != 1 || calls.Load() != 3 {
				t.Fatal("owned delivery did not actually exhaust the original transport budget")
			}
			request := func() *httptest.ResponseRecorder {
				ctx := context.WithValue(context.Background(), sessionContextKey{}, Session{User: User{ID: "owned-transport-operator"}})
				w := httptest.NewRecorder()
				s.handleRevokeAction(w, httptest.NewRequest(http.MethodPost, "/revoke", nil).WithContext(ctx), parent.ActionID)
				return w
			}
			// A restart reloads the exhausted record before the operator retries it.
			restarted, err := newOperationsState("", os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.db.Close()
			s.operations = restarted
			done := make(chan struct{}, 2)
			s.actionDeliveries = newActionDeliveryQueue(func(id string, revoke bool) {
				if id == child.ActionID {
					s.deliverAction(id, revoke)
					done <- struct{}{}
				}
			})
			first := request()
			if first.Code != http.StatusAccepted {
				t.Fatalf("exhausted recovery did not accept explicit retry: http=%d", first.Code)
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("explicit retry did not reach controlled transport")
			}
			duplicate := request()
			if duplicate.Code != http.StatusOK {
				t.Fatal("duplicate revoke did not return the existing running recovery")
			}
			unblock()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("explicit recovery retry did not finish")
			}
			read()
			if attempts != 4 || numbers != "1,2,3,4" || calls.Load() != 4 || key != expectedKey || actionRows != 2 || audits != 1 {
				t.Fatal("explicit retry lost attempt sequence, key, lineage, or actor audit")
			}
			if retrySucceeds {
				if status != "revoked" || parentStatus != "revoked" || retryCount != 3 || failures != 0 || due.Valid {
					t.Fatal("confirmed recovery reset historical attempts or failed to restore its parent")
				}
				return
			}
			if status != "failed" || retryCount != 4 || failures != 2 || due.Valid || parentStatus != "succeeded" {
				t.Fatal("failed manual retry received a fresh automatic budget")
			}
			s.processDueActions(time.Now().UTC().Add(time.Hour))
			if calls.Load() != 4 {
				t.Fatal("scheduler automatically resumed an exhausted manual recovery")
			}
			// Use a fresh process/queue view for the next explicit operation. This
			// also verifies the retained failed count survives another restart.
			next, err := newOperationsState("", os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
			if err != nil {
				t.Fatal(err)
			}
			defer next.db.Close()
			s.operations, s.actionDeliveries = next, nil
			completed.Store(true)
			if w := request(); w.Code != http.StatusAccepted {
				t.Fatal("second explicit operator retry did not reuse the failed recovery")
			}
			s.deliverAction(child.ActionID, true)
			read()
			if status != "revoked" || parentStatus != "revoked" || retryCount != 4 || failures != 0 || attempts != 5 || numbers != "1,2,3,4,5" || calls.Load() != 5 || audits != 2 || key != expectedKey || actionRows != 2 {
				t.Fatal("second explicit retry lost cumulative attempt accounting or same-lease recovery")
			}
		})
	}
}
