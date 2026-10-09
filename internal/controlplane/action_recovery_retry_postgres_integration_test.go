package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

type actionRecoveryAuditReader struct {
	store.Reader
	appender store.AuditAppender
}

func (r actionRecoveryAuditReader) AppendAuditLog(ctx context.Context, item store.AuditLog) error {
	return r.appender.AppendAuditLog(ctx, item)
}

func actionRecoveryNativeFixture(t *testing.T, remote string, actor string) (*Server, EnforcementAction, EnforcementAction) {
	t.Helper()
	srunIsolatedReplayServer(t)
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	ops, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ops.db.Close() })
	s, _ := actionReceiptReplay(t)
	s.operations = ops
	reader, err := store.NewPostgresStore(store.PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	s.reader = actionRecoveryAuditReader{appender: reader}
	id := "recovery-retry-" + shortToken(12)
	stamp := formatDBTime(time.Now().UTC())
	parent := EnforcementAction{ActionID: id, IdempotencyKey: id, ConnectorID: id, ActionType: "account.rate_limit", SubjectType: "account", SubjectID: "fixture", AccountID: "fixture", Mode: "active", Status: "succeeded", CreatedAt: stamp, UpdatedAt: stamp, PolicyParameters: PolicyActionParameters{ExecutionID: id + "-episode", LeaseID: id + ":lease", Operation: "rate_limit"}}
	ops.mu.Lock()
	ops.doc.Connectors[id] = ActionConnector{ConnectorID: id, Name: "owned recovery", Mode: "active", Enabled: true, ShadowReady: true, ConsecutiveFailures: 4, EndpointURL: remote, UpdatedAt: stamp}
	encrypted, err := s.encryptConnectorSecret("isolated-receipt-secret")
	if err != nil {
		t.Fatal(err)
	}
	connector := ops.doc.Connectors[id]
	connector.EncryptedSecret = encrypted
	ops.doc.Connectors[id] = connector
	ops.doc.Actions[id] = parent
	err = ops.saveLocked()
	ops.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	child := s.newReleaseAction(parent, actor, time.Now().UTC())
	ops.mu.Lock()
	ops.doc.Actions[child.ActionID] = child
	err = ops.saveLocked()
	ops.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return s, parent, child
}

func TestActionRecoveryNativeDeadlineRetrySurvivesRestartAndRestores(t *testing.T) {
	var calls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var payload struct {
			Action string                 `json:"action"`
			Revoke bool                   `json:"revoke"`
			Policy PolicyActionParameters `json:"policy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Action != "release" || !payload.Revoke || payload.Policy.LeaseID != strings.TrimSuffix(r.Header.Get("Idempotency-Key"), ":release")+":lease" {
			t.Error("recovery did not send the original release payload")
		}
		w.Write([]byte(`{"action_id":"recovered-receipt","status":"completed"}`))
	}))
	defer remote.Close()
	s, _, child := actionRecoveryNativeFixture(t, remote.URL, "system-expiry")
	db := s.operations.db
	doc := emptyOperationsDocument()
	if err := loadActionsScoped(context.Background(), db, &doc, ` WHERE action_id=$1`, []any{child.ActionID}); err != nil {
		t.Fatal(err)
	}
	preview := doc.Actions[child.ActionID]
	lock, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback()
	if _, err := lock.Exec(`LOCK enforcement_connectors IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	cause := s.validatePolicyDeliveryContext(ctx, preview)
	cancel()
	if !errors.Is(cause, context.DeadlineExceeded) {
		t.Fatalf("scoped SQL read did not time out: %v", cause)
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := s.recordActionPrecheckFailure(preview, cause); err != nil {
		t.Fatal(err)
	}
	var status string
	var count, retries, attempts, failures, audits int
	var retryable bool
	var due sql.NullTime
	if err := db.QueryRow(`SELECT a.status,a.precheck_retry_count,a.precheck_retryable,a.retry_count,a.next_attempt_at,c.consecutive_failures,(SELECT count(*) FROM enforcement_action_attempts WHERE action_id=a.action_id),(SELECT count(*) FROM audit_logs WHERE action='enforcement.precheck_retry' AND target=a.action_id) FROM enforcement_actions a JOIN enforcement_connectors c USING(connector_id) WHERE action_id=$1`, child.ActionID).Scan(&status, &count, &retryable, &retries, &due, &failures, &attempts, &audits); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || count != 1 || !retryable || !due.Valid || retries != 0 || attempts != 0 || failures != 4 || calls.Load() != 0 || audits != 1 {
		t.Fatalf("temporary precheck was not durably separated from transport: status=%s prechecks=%d retries=%d attempts=%d failures=%d calls=%d", status, count, retries, attempts, failures, calls.Load())
	}
	ops, err := newOperationsState("", os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer ops.db.Close()
	s.operations = ops
	if current := ops.doc.Actions[child.ActionID]; current.PrecheckRetryCount != 1 || !current.PrecheckRetryable || current.IdempotencyKey != child.IdempotencyKey {
		t.Fatal("restart lost retry or immutable recovery key")
	}
	// Replay the elapsed retry interval using only this fixture's scheduling
	// field. An early duplicate wakeup must not shorten the stored backoff.
	s.deliverAction(child.ActionID, true)
	if calls.Load() != 0 {
		t.Fatal("early wakeup bypassed persisted backoff")
	}
	if _, err := db.Exec(`UPDATE enforcement_actions SET next_attempt_at=now()-interval '1 second' WHERE action_id=$1`, child.ActionID); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{}, 1)
	s.actionDeliveries = newActionDeliveryQueue(func(id string, revoke bool) {
		if id == child.ActionID {
			s.deliverAction(id, revoke)
			done <- struct{}{}
		}
	})
	s.processDueActions(time.Now().UTC())
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("due recovery was not delivered")
	}
	var parentStatus, key string
	if err := db.QueryRow(`SELECT ch.status,ch.idempotency_key,ch.precheck_retry_count,ch.precheck_retryable,p.status,(SELECT count(*) FROM enforcement_action_attempts WHERE action_id=ch.action_id) FROM enforcement_actions ch JOIN enforcement_actions p ON p.action_id=ch.parent_action_id WHERE ch.action_id=$1`, child.ActionID).Scan(&status, &key, &count, &retryable, &parentStatus, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "revoked" || parentStatus != "expired" || key != child.IdempotencyKey || count != 1 || retryable || attempts != 1 || calls.Load() != 1 {
		t.Fatalf("recovery retry did not complete same intent: status=%s parent=%s attempts=%d calls=%d", status, parentStatus, attempts, calls.Load())
	}
}

func TestActionRecoveryNativeManualRetryReusesIntentAndWritesAudit(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var calls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		close(entered)
		<-release
		w.Write([]byte(`{"action_id":"manual-recovery-receipt","status":"completed"}`))
	}))
	defer remote.Close()
	defer unblock()
	s, parent, child := actionRecoveryNativeFixture(t, remote.URL, "manual-revoke")
	db := s.operations.db
	if _, err := db.Exec(`UPDATE enforcement_actions SET status='blocked',precheck_retry_count=5,precheck_retryable=true,last_error='动作投递前校验暂不可用' WHERE action_id=$1`, child.ActionID); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{}, 1)
	s.actionDeliveries = newActionDeliveryQueue(func(id string, revoke bool) {
		if id == child.ActionID {
			s.deliverAction(id, revoke)
			done <- struct{}{}
		}
	})
	request := func() *httptest.ResponseRecorder {
		ctx := context.WithValue(context.Background(), sessionContextKey{}, Session{User: User{ID: "owned-recovery-operator"}})
		w := httptest.NewRecorder()
		s.handleRevokeAction(w, httptest.NewRequest(http.MethodPost, "/api/v1/actions/"+parent.ActionID+"/revoke", nil).WithContext(ctx), parent.ActionID)
		return w
	}
	first := request()
	if first.Code != http.StatusAccepted {
		t.Fatalf("manual recovery retry rejected: http=%d body=%s", first.Code, first.Body.String())
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("manual retry never reached controlled transport")
	}
	second := request()
	if second.Code != http.StatusOK {
		t.Fatalf("duplicate request rejected: http=%d", second.Code)
	}
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("manual recovery did not finish")
	}
	var actionCount, audits, attempts, prechecks, retries int
	var status, parentStatus, key string
	if err := db.QueryRow(`SELECT ch.status,ch.idempotency_key,ch.precheck_retry_count,ch.retry_count,p.status,(SELECT count(*) FROM enforcement_actions WHERE connector_id=ch.connector_id),(SELECT count(*) FROM enforcement_action_attempts WHERE action_id=ch.action_id),(SELECT count(*) FROM audit_logs WHERE action='enforcement.revoke.retry' AND target=p.action_id AND actor='owned-recovery-operator') FROM enforcement_actions ch JOIN enforcement_actions p ON p.action_id=ch.parent_action_id WHERE ch.action_id=$1`, child.ActionID).Scan(&status, &key, &prechecks, &retries, &parentStatus, &actionCount, &attempts, &audits); err != nil {
		t.Fatal(err)
	}
	if status != "revoked" || parentStatus != "revoked" || key != child.IdempotencyKey || actionCount != 2 || attempts != 1 || audits != 1 || prechecks != 0 || retries != 0 || calls.Load() != 1 {
		t.Fatalf("manual retry lost accounting or duplicated recovery: status=%s parent=%s rows=%d attempts=%d audits=%d calls=%d", status, parentStatus, actionCount, attempts, audits, calls.Load())
	}
}
