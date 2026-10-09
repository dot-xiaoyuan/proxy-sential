package controlplane

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/risk"
	"proxy-sentinel/internal/srunapi"
)

type failAfterActionResultReader struct {
	*riskActionReplayReader
	result func()
}

func (r failAfterActionResultReader) GetIPRisk(context.Context, string) (risk.Snapshot, error) {
	r.result()
	return risk.Snapshot{}, context.DeadlineExceeded
}

func TestActionFailureNativeDeliveryPreservesConcurrentResult(t *testing.T) {
	srunIsolatedReplayServer(t)
	for _, result := range []string{"succeeded", "cancelled", "revoked"} {
		t.Run(result, func(t *testing.T) {
			s, reader, a := riskActionReplay(t)
			ops, err := newOperationsState("", os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
			if err != nil {
				t.Fatal(err)
			}
			defer ops.db.Close()
			id := "precheck-result-" + shortToken(12)
			defer func() {
				if _, err := ops.db.ExecContext(context.Background(), `UPDATE risk_cases SET status='closed' WHERE case_id=$1`, id+"-case"); err != nil {
					t.Error(err)
				}
			}()
			item := s.operations.doc.Cases[a.CaseID]
			item.CaseID = id + "-case"
			item.SubjectType = "ip"
			item.SubjectID = item.IP
			item.Priority = "high"
			stamp := formatDBTime(time.Now().UTC())
			item.FirstSeen = stamp
			item.LastSeen = stamp
			item.CreatedAt = stamp
			item.UpdatedAt = stamp
			a.ActionID = id
			a.IdempotencyKey = id
			a.CaseID = item.CaseID
			a.ConnectorID = id
			a.CreatedAt = stamp
			a.UpdatedAt = stamp
			ops.mu.Lock()
			ops.doc.Cases[item.CaseID] = item
			ops.doc.Actions[a.ActionID] = a
			ops.doc.Connectors[id] = ActionConnector{ConnectorID: id, Name: "owned controller", Mode: "active", Enabled: true, ShadowReady: true, EndpointURL: "http://127.0.0.1:1/must-not-send", UpdatedAt: stamp}
			err = ops.saveLocked()
			ops.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			s.operations = ops
			var before string
			s.reader = failAfterActionResultReader{riskActionReplayReader: reader, result: func() {
				if err := s.finishAction(a.ActionID, result, "receipt-"+result, "new result"); err != nil {
					t.Fatal(err)
				}
				if err := ops.db.QueryRow(`SELECT to_jsonb(a)::text FROM enforcement_actions a WHERE action_id=$1`, a.ActionID).Scan(&before); err != nil {
					t.Fatal(err)
				}
			}}
			s.deliverAction(a.ActionID, false)
			var after string
			if err := ops.db.QueryRow(`SELECT to_jsonb(a)::text FROM enforcement_actions a WHERE action_id=$1`, a.ActionID).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if before == "" || before != after {
				t.Fatalf("stale precheck changed newer %s result", result)
			}
			var attempts int
			if err := ops.db.QueryRow(`SELECT count(*) FROM enforcement_action_attempts WHERE action_id=$1`, a.ActionID).Scan(&attempts); err != nil {
				t.Fatal(err)
			}
			if attempts != 0 {
				t.Fatal("failed precheck manufactured a transport attempt")
			}
		})
	}
}

type cancelBeforeDisableClient struct {
	nativeQueueSandbox
	cancel func()
}

func (c *cancelBeforeDisableClient) RequestSafeDisableChecked(ctx context.Context, account string, seconds int, guard func(context.Context) error) error {
	c.cancel()
	if err := guard(ctx); err != nil {
		return errors.Join(srunapi.ErrDispatchPrevented, err)
	}
	c.calls.Add(1)
	return nil
}

func TestActionFailureNativeDisableFinalGuardKeepsCancellation(t *testing.T) {
	srunIsolatedReplayServer(t)
	ops, err := newOperationsState("", os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer ops.db.Close()
	id := "disable-guard-" + shortToken(12)
	stamp := formatDBTime(time.Now().UTC())
	a := EnforcementAction{ActionID: id, IdempotencyKey: id, ConnectorID: id, ActionType: "account.disable_account", AccountID: "owned-fixture", DurationSeconds: 10, Status: "pending", Mode: "active", CreatedAt: stamp, UpdatedAt: stamp}
	ops.mu.Lock()
	ops.doc.Actions[id] = a
	ops.doc.Connectors[id] = ActionConnector{ConnectorID: id, Name: "isolated native guard", ConnectorType: "srun4k", Mode: "active", Enabled: true, ShadowReady: true, EndpointURL: "http://127.0.0.1:1/must-not-send", UpdatedAt: stamp}
	err = ops.saveLocked()
	ops.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ops.db.ExecContext(context.Background(), `INSERT INTO srun4k_integrations(connector_id,host,source,sensor_id,event_channel_state) VALUES($1,'192.0.2.1',$2,$3,'healthy')`, id, "srun4k:"+id, "sensor:"+id); err != nil {
		t.Fatal(err)
	}
	s := &Server{operations: ops}
	client := &cancelBeforeDisableClient{cancel: func() {
		if err := s.finishAction(id, "cancelled", "", "owned cancellation"); err != nil {
			t.Fatal(err)
		}
	}}
	s.nativeActions = map[string]NativeActionRuntime{id: {Client: client}}
	s.deliverAction(id, false)
	var status, lastError string
	if err := ops.db.QueryRow(`SELECT status,coalesce(last_error,'') FROM enforcement_actions WHERE action_id=$1`, id).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != "cancelled" || lastError != "owned cancellation" || client.calls.Load() != 0 {
		t.Fatalf("prevented disable lost cancellation: status=%s error=%s guarded_calls=%d", status, lastError, client.calls.Load())
	}
}
