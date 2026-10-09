package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestActionReceiptNativeCallbacksKeepResultsAndCircuit(t *testing.T) {
	srunIsolatedReplayServer(t)
	ops, err := newOperationsState("", os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer ops.db.Close()
	s, secret := actionReceiptReplay(t)
	s.operations = ops
	for _, status := range []string{"succeeded", "revoked", "expired", "cancelled", "blocked", "shadow"} {
		t.Run(status, func(t *testing.T) {
			id := "receipt-state-" + shortToken(12)
			stamp := formatDBTime(time.Now().UTC())
			a := EnforcementAction{ActionID: id, ConnectorID: id, IdempotencyKey: id, Status: status, AccountID: "fixture", RemoteActionID: "existing-receipt", CreatedAt: stamp, UpdatedAt: stamp}
			encrypted, err := s.encryptConnectorSecret(secret)
			if err != nil {
				t.Fatal(err)
			}
			ops.mu.Lock()
			ops.doc.Actions[id] = a
			ops.doc.Connectors[id] = ActionConnector{ConnectorID: id, Name: "owned receipt", Mode: "active", Enabled: true, EncryptedSecret: encrypted, ConsecutiveFailures: 4, CircuitOpenUntil: stamp, UpdatedAt: stamp}
			err = ops.saveLocked()
			ops.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			row := func() string {
				var result string
				if err := ops.db.QueryRow(`SELECT jsonb_build_object('action',to_jsonb(a),'connector',to_jsonb(c))::text FROM enforcement_actions a JOIN enforcement_connectors c USING(connector_id) WHERE action_id=$1`, id).Scan(&result); err != nil {
					t.Fatal(err)
				}
				return result
			}
			before := row()
			w := signedReceiptCallback(s, secret, a, "failed", "late-receipt", "late failure")
			if w.Code != http.StatusConflict || row() != before {
				t.Fatalf("late callback changed SQL result/circuit: http=%d", w.Code)
			}
		})
	}
}

func TestActionReceiptNativeLateHTTPKeepsCompletedRecovery(t *testing.T) {
	srunIsolatedReplayServer(t)
	ops, err := newOperationsState("", os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer ops.db.Close()
	s, secret := actionReceiptReplay(t)
	s.operations = ops
	id := "receipt-recovery-" + shortToken(12)
	stamp := formatDBTime(time.Now().UTC())
	a := EnforcementAction{ActionID: id, ConnectorID: id, IdempotencyKey: id, ActionType: "disconnect", AccountID: "fixture", Status: "pending", Mode: "active", CreatedAt: stamp, UpdatedAt: stamp}
	var before string
	row := func() string {
		var result string
		if err := ops.db.QueryRow(`SELECT jsonb_build_object('action',to_jsonb(a),'connector',to_jsonb(c),'child',(SELECT to_jsonb(ch) FROM enforcement_actions ch WHERE ch.parent_action_id=a.action_id))::text FROM enforcement_actions a JOIN enforcement_connectors c USING(connector_id) WHERE action_id=$1`, id).Scan(&result); err != nil {
			t.Error(err)
		}
		return result
	}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.finishAction(id, "succeeded", "callback-receipt", ""); err != nil {
			t.Error(err)
			return
		}
		if err := s.finishAction(id+"-release", "revoked", "recovery-receipt", ""); err != nil {
			t.Error(err)
			return
		}
		before = row()
		w.Write([]byte(`{"action_id":"late-http-receipt","status":"completed"}`))
	}))
	defer remote.Close()
	encrypted, err := s.encryptConnectorSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	ops.mu.Lock()
	ops.doc.Actions[id] = a
	ops.doc.Connectors[id] = ActionConnector{ConnectorID: id, Name: "owned receipt recovery", Mode: "active", Enabled: true, EncryptedSecret: encrypted, EndpointURL: remote.URL, UpdatedAt: stamp}
	err = ops.saveLocked()
	ops.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// The fixture, like the real revoke path, creates the child only after its
	// parent is durable. Map iteration is not a foreign-key insertion order.
	ops.mu.Lock()
	release := s.newReleaseAction(a, "manual-revoke", time.Now().UTC())
	release.ActionID = id + "-release"
	release.Status = "running"
	ops.doc.Actions[release.ActionID] = release
	err = ops.saveLocked()
	ops.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	s.deliverAction(id, false)
	if before == "" || before != row() {
		t.Fatal("late HTTP completion changed a committed recovery or connector")
	}
	var attempts int
	if err := ops.db.QueryRowContext(context.Background(), `SELECT count(*) FROM enforcement_action_attempts WHERE action_id=$1 AND response_body->>'action_id'='late-http-receipt' AND http_status=200`, id).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("late actual transport receipt was lost: attempts=%d err=%v", attempts, err)
	}
}

func TestActionReceiptNativeCurrentHTTPAndCallbacksRemainUsable(t *testing.T) {
	srunIsolatedReplayServer(t)
	ops, err := newOperationsState("", os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer ops.db.Close()
	s, secret := actionReceiptReplay(t)
	s.operations = ops
	id := "receipt-current-" + shortToken(12)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	a := EnforcementAction{ActionID: id, ConnectorID: id, IdempotencyKey: id, ActionType: "disconnect", AccountID: "fixture", Status: "pending", Mode: "active", CreatedAt: stamp, UpdatedAt: stamp}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"action_id":"current-receipt","status":"completed"}`))
	}))
	defer remote.Close()
	encrypted, err := s.encryptConnectorSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	ops.mu.Lock()
	ops.doc.Actions[id] = a
	ops.doc.Connectors[id] = ActionConnector{ConnectorID: id, Name: "owned current receipt", Mode: "active", Enabled: true, EncryptedSecret: encrypted, EndpointURL: remote.URL, ConsecutiveFailures: 4, UpdatedAt: stamp}
	err = ops.saveLocked()
	ops.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	s.deliverAction(id, false)
	var status, receipt, before, after string
	var failures int
	if err := ops.db.QueryRow(`SELECT a.status,coalesce(a.remote_action_id,''),c.consecutive_failures,to_jsonb(a)::text FROM enforcement_actions a JOIN enforcement_connectors c USING(connector_id) WHERE action_id=$1`, id).Scan(&status, &receipt, &failures, &before); err != nil || status != "succeeded" || receipt != "current-receipt" || failures != 0 {
		t.Fatalf("current SQL completion rejected: status=%s receipt=%s failures=%d err=%v", status, receipt, failures, err)
	}
	w := signedReceiptCallback(s, secret, a, "succeeded", "current-receipt", "")
	if err := ops.db.QueryRow(`SELECT to_jsonb(a)::text FROM enforcement_actions a WHERE action_id=$1`, id).Scan(&after); err != nil || w.Code != http.StatusOK || before != after {
		t.Fatalf("duplicate SQL callback changed result: http=%d err=%v", w.Code, err)
	}
	// The existing transport model may exhaust retries without a remote receipt.
	// A subsequently signed completion must still be able to resolve it.
	if _, err := ops.db.Exec(`UPDATE enforcement_actions SET status='failed',remote_action_id=NULL,last_error='transport exhausted' WHERE action_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	w = signedReceiptCallback(s, secret, a, "succeeded", "confirmed-late-receipt", "")
	if err := ops.db.QueryRow(`SELECT status,coalesce(remote_action_id,'') FROM enforcement_actions WHERE action_id=$1`, id).Scan(&status, &receipt); err != nil || w.Code != http.StatusOK || status != "succeeded" || receipt != "confirmed-late-receipt" {
		t.Fatalf("signed completion did not resolve failed SQL transport: http=%d status=%s err=%v", w.Code, status, err)
	}
}

type lateDisableReceiptClient struct {
	nativeQueueSandbox
	afterDispatch func()
	result        error
}

func (c *lateDisableReceiptClient) RequestSafeDisableChecked(ctx context.Context, account string, duration int, guard func(context.Context) error) error {
	if err := guard(ctx); err != nil {
		return err
	}
	c.calls.Add(1)
	c.afterDispatch()
	return c.result
}

func TestActionReceiptNativeDisableLateResultKeepsStopRequest(t *testing.T) {
	srunIsolatedReplayServer(t)
	for index, result := range []string{"current", "accepted", "error"} {
		t.Run(result, func(t *testing.T) {
			ops, err := newOperationsState("", os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
			if err != nil {
				t.Fatal(err)
			}
			defer ops.db.Close()
			id := "disable-late-" + shortToken(12)
			stamp := formatDBTime(time.Now().UTC())
			a := EnforcementAction{ActionID: id, IdempotencyKey: id, ConnectorID: id, ActionType: "account.disable_account", AccountID: "owned-fixture", DurationSeconds: 10, Status: "pending", Mode: "active", CreatedAt: stamp, UpdatedAt: stamp}
			ops.mu.Lock()
			ops.doc.Actions[id] = a
			ops.doc.Connectors[id] = ActionConnector{ConnectorID: id, Name: "owned late disable", ConnectorType: "srun4k", Mode: "active", Enabled: true, ShadowReady: true, EndpointURL: "http://127.0.0.1:1/must-not-send", UpdatedAt: stamp}
			err = ops.saveLocked()
			ops.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ops.db.ExecContext(context.Background(), `INSERT INTO srun4k_integrations(connector_id,host,source,sensor_id,event_channel_state) VALUES($1,$2,$3,$4,'healthy')`, id, "192.0.2."+strconv.Itoa(110+index), "srun4k:"+id, "sensor:"+id); err != nil {
				t.Fatal(err)
			}
			s := &Server{operations: ops}
			var before string
			row := func() string {
				var raw string
				if err := ops.db.QueryRow(`SELECT jsonb_build_object('action',to_jsonb(a),'connector',to_jsonb(c))::text FROM enforcement_actions a JOIN enforcement_connectors c USING(connector_id) WHERE action_id=$1`, id).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				return raw
			}
			client := &lateDisableReceiptClient{afterDispatch: func() {
				if result == "current" {
					return
				}
				w := httptest.NewRecorder()
				if !s.handleNativeCancel(w, httptest.NewRequest(http.MethodPost, "/api/v1/actions/"+id+"/revoke", nil), id) || w.Code != http.StatusAccepted {
					t.Fatalf("owned stop request failed: %d %s", w.Code, w.Body.String())
				}
				before = row()
			}}
			if result == "error" {
				client.result = errors.New("simulated late transport error")
			}
			s.nativeActions = map[string]NativeActionRuntime{id: {Client: client}}
			s.deliverAction(id, false)
			if result == "current" {
				var status, receipt string
				if err := ops.db.QueryRow(`SELECT status,coalesce(remote_action_id,'') FROM enforcement_actions WHERE action_id=$1`, id).Scan(&status, &receipt); err != nil || status != "succeeded" || receipt != "safe-disable:"+id || client.calls.Load() != 1 {
					t.Fatalf("current native result rejected: status=%s receipt=%s simulated_calls=%d err=%v", status, receipt, client.calls.Load(), err)
				}
				return
			}
			if before == "" || row() != before || client.calls.Load() != 1 {
				t.Fatalf("late disable %s overwrote stop request: simulated_calls=%d", result, client.calls.Load())
			}
		})
	}
}
