package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/srunapi"
	"proxy-sentinel/internal/store"
	"sync/atomic"
	"testing"
	"time"
)

type nativeQueueSandbox struct {
	calls       atomic.Int32
	beforeGuard func()
}

func (n *nativeQueueSandbox) RequestDisconnectChecked(ctx context.Context, a, id, kind string, guard func(context.Context) error) error {
	if n.beforeGuard != nil {
		n.beforeGuard()
	}
	if err := guard(ctx); err != nil {
		return errors.Join(srunapi.ErrDispatchPrevented, err)
	}
	n.calls.Add(1)
	return nil
}

func TestNativeMainQueuePostgresReconcilesWithoutResend(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	if _, err := store.ApplyPostgresMigrations(context.Background(), dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	ops, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer ops.db.Close()
	suffix := time.Now().UTC().Format("150405.000000000")
	id := "native-test-" + suffix
	connectorID := "native-connector-" + suffix
	native := &nativeQueueSandbox{}
	online := true
	labNow := func() time.Time {
		var at time.Time
		if err := ops.db.QueryRow(`SELECT clock_timestamp()`).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at.UTC()
	}
	runtime := NativeActionRuntime{Now: labNow, Client: native, CampusID: "lab", AccessDomain: "lab-nas", DropType: "radius", Read: func(context.Context) (legacy4k.OnlineInventory, error) {
		in := legacy4k.OnlineInventory{InstanceID: "boot", ObservedAt: labNow(), Rows: []map[string]string{}}
		if online {
			in.Rows = append(in.Rows, map[string]string{"rad_online_id": "7", "session_id": "acct-7", "user_name": "test", "ip": "192.0.2.7", "add_time": "1"})
		}
		return in, nil
	}}
	now := formatDBTime(time.Now().UTC())
	ops.mu.Lock()
	ops.doc.Connectors[connectorID] = ActionConnector{ConnectorID: connectorID, Name: "native sandbox", EndpointURL: "http://127.0.0.1:1/must-not-send", Mode: "active", Enabled: true, ShadowReady: true, UpdatedAt: now}
	ops.doc.Actions[id] = EnforcementAction{ActionID: id, IdempotencyKey: id, ConnectorID: connectorID, ActionType: "disconnect", SubjectType: "session", SubjectID: legacy4k.OnlineSessionID("boot", "acct-7", "1"), AccountID: "test", SessionID: legacy4k.OnlineSessionID("boot", "acct-7", "1"), CampusID: "lab", IP: "192.0.2.7", Status: "pending", Mode: "active", CreatedAt: now, UpdatedAt: now, CreatedBy: "lab-test", PolicyParameters: PolicyActionParameters{AccessDomain: "lab-nas"}}
	if err = ops.saveLocked(); err != nil {
		ops.mu.Unlock()
		t.Fatal(err)
	}
	ops.mu.Unlock()
	s := &Server{operations: ops, nativeActions: map[string]NativeActionRuntime{connectorID: runtime}}
	// Cancelling before a worker binds an intent must survive a later dispatch.
	before := ops.doc.Actions[id]
	before.ActionID = id + "-cancel-before"
	before.IdempotencyKey = before.ActionID
	ops.mu.Lock()
	ops.doc.Actions[before.ActionID] = before
	if err := ops.saveLocked(); err != nil {
		ops.mu.Unlock()
		t.Fatal(err)
	}
	ops.mu.Unlock()
	cancelResponse := httptest.NewRecorder()
	s.handleRevokeAction(cancelResponse, httptest.NewRequest(http.MethodPost, "/revoke", nil), before.ActionID)
	if cancelResponse.Code != http.StatusAccepted {
		t.Fatalf("cancel before: %d %s", cancelResponse.Code, cancelResponse.Body.String())
	}
	s.deliverAction(before.ActionID, false)
	if native.calls.Load() != 0 {
		t.Fatal("cancelled action sent")
	}
	s.deliverAction(id, false)
	first := ops.doc.Actions[id]
	if first.Status != "pending" || native.calls.Load() != 1 || first.PolicyParameters.NativeIntent == nil || first.RetryCount != 0 {
		t.Fatalf("native main send: %+v calls=%d", first, native.calls.Load())
	}
	restarted, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.db.Close()
	online = false
	s.operations = restarted
	s.deliverAction(id, false)
	final := restarted.doc.Actions[id]
	if final.Status != "succeeded" || native.calls.Load() != 1 {
		t.Fatalf("restart resend or failed reconcile: %+v calls=%d", final, native.calls.Load())
	}
	// A marked action with removed configuration must never fall back to HTTP.
	marked := final
	marked.Status = "pending"
	restarted.mu.Lock()
	restarted.doc.Actions[id] = marked
	if err := restarted.saveLocked(); err != nil {
		restarted.mu.Unlock()
		t.Fatal(err)
	}
	restarted.mu.Unlock()
	s.nativeActions = nil
	s.deliverAction(id, false)
	// Targeted PostgreSQL writes are authoritative; the process document may
	// remain unchanged until its next legacy transaction reload.
	storedAction := func(actionID string) EnforcementAction {
		doc := emptyOperationsDocument()
		if err := loadActionsScoped(context.Background(), restarted.db, &doc, " WHERE action_id=$1", []any{actionID}); err != nil {
			t.Fatal(err)
		}
		return doc.Actions[actionID]
	}
	if got := storedAction(id); got.Status != "blocked" || got.RetryCount != 0 {
		t.Fatalf("missing config fell back: %+v", got)
	}
	// Cancellation after sending is not reported as undoing the remote action.
	for i := 0; i < 2; i++ {
		response := httptest.NewRecorder()
		s.handleRevokeAction(response, httptest.NewRequest(http.MethodPost, "/revoke", nil), id)
		if response.Code != http.StatusAccepted {
			t.Fatalf("cancel sent: %d %s", response.Code, response.Body.String())
		}
	}
	cancelled, err := (srunapi.Journal{DB: restarted.db}).Cancelled(context.Background(), *final.PolicyParameters.NativeIntent)
	if err != nil || !cancelled {
		t.Fatalf("missing durable cancellation: %v %v", cancelled, err)
	}
	s.deliverAction(id, false)
	if native.calls.Load() != 1 || storedAction(id).Status != "blocked" {
		t.Fatal("cancelled action resent or reported restored")
	}

	// A cancellation during token acquisition must stop the final network send.
	during := before
	during.ActionID = id + "-cancel-during"
	during.IdempotencyKey = during.ActionID
	restarted.mu.Lock()
	restarted.doc.Actions[during.ActionID] = during
	if err := restarted.saveLocked(); err != nil {
		restarted.mu.Unlock()
		t.Fatal(err)
	}
	restarted.mu.Unlock()
	online = true
	s.nativeActions = map[string]NativeActionRuntime{connectorID: runtime}
	native.beforeGuard = func() {
		response := httptest.NewRecorder()
		s.handleRevokeAction(response, httptest.NewRequest(http.MethodPost, "/revoke", nil), during.ActionID)
		if response.Code != http.StatusAccepted {
			t.Fatalf("cancel during: %d %s", response.Code, response.Body.String())
		}
	}
	s.deliverAction(during.ActionID, false)
	if native.calls.Load() != 1 || storedAction(during.ActionID).Status != "blocked" {
		t.Fatal("final guard ignored cancellation")
	}

}
