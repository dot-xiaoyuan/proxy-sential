package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/srunapi"
	"proxy-sentinel/internal/store"
)

type nativeGenerationClient struct {
	calls         atomic.Int32
	beforeGuard   func()
	afterDispatch func()
}

func (c *nativeGenerationClient) RequestDisconnectChecked(ctx context.Context, account, id, kind string, guard func(context.Context) error) error {
	if c.beforeGuard != nil {
		c.beforeGuard()
	}
	if err := guard(ctx); err != nil {
		return errors.Join(srunapi.ErrDispatchPrevented, err)
	}
	c.calls.Add(1)
	if c.afterDispatch != nil {
		c.afterDispatch()
	}
	return nil
}

func nativeGenerationFixture(t *testing.T) (*Server, EnforcementAction, *nativeGenerationClient) {
	t.Helper()
	srunIsolatedReplayServer(t)
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	ops, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ops.db.Close() })
	reader, err := store.NewPostgresStore(store.PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	id := "native-generation-" + shortToken(12)
	stamp := formatDBTime(time.Now().UTC())
	session := legacy4k.OnlineSessionID("owned-boot", "owned-session", "1")
	a := EnforcementAction{ActionID: id, IdempotencyKey: id, ConnectorID: id, ActionType: "session.disconnect", SubjectType: "session", SubjectID: session, AccountID: "owned-account", SessionID: session, IP: "192.0.2.7", CampusID: "owned-campus", Mode: "active", Status: "pending", CreatedAt: stamp, UpdatedAt: stamp, PolicyParameters: PolicyActionParameters{AccessDomain: "owned-nas"}}
	ops.mu.Lock()
	ops.doc.Connectors[id] = ActionConnector{ConnectorID: id, Name: "owned native generation", Mode: "active", Enabled: true, ShadowReady: true, ConsecutiveFailures: 4, EndpointURL: "http://127.0.0.1:1/must-not-send", UpdatedAt: stamp}
	ops.doc.Actions[id] = a
	err = ops.saveLocked()
	ops.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	client := &nativeGenerationClient{}
	runtime := NativeActionRuntime{Client: client, CampusID: a.CampusID, AccessDomain: a.PolicyParameters.AccessDomain, DropType: "radius", Now: time.Now, Read: func(context.Context) (legacy4k.OnlineInventory, error) {
		in := legacy4k.OnlineInventory{InstanceID: "owned-boot", ObservedAt: time.Now().UTC(), Rows: []map[string]string{}}
		if client.calls.Load() == 0 {
			in.Rows = append(in.Rows, map[string]string{"rad_online_id": "7", "session_id": "owned-session", "user_name": a.AccountID, "ip": a.IP, "add_time": "1"})
		}
		return in, nil
	}}
	s := &Server{operations: ops, reader: actionRecoveryAuditReader{appender: reader}, nativeActions: map[string]NativeActionRuntime{id: runtime}}
	return s, a, client
}

func nativeGenerationRow(t *testing.T, s *Server, id string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var row string
	if err := s.operations.db.QueryRowContext(ctx, `SELECT jsonb_build_object('action',to_jsonb(a),'connector',to_jsonb(c))::text FROM enforcement_actions a JOIN enforcement_connectors c USING(connector_id) WHERE action_id=$1`, id).Scan(&row); err != nil {
		t.Fatal(err)
	}
	return row
}

func nativeGenerationEdit(t *testing.T, s *Server, id string, edit func(*EnforcementAction)) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	doc := emptyOperationsDocument()
	if err := loadActionsScoped(ctx, s.operations.db, &doc, ` WHERE action_id=$1`, []any{id}); err != nil {
		t.Fatal(err)
	}
	// An independent SQL read keeps the admitted attempt's nested snapshot
	// immutable. Direct edits belong only to this disposable acceptance DB;
	// normal action persistence intentionally keeps identity/evidence immutable.
	a := doc.Actions[id]
	edit(&a)
	parameters, err := json.Marshal(a.PolicyParameters)
	if err == nil {
		evidenceJSON, marshalErr := json.Marshal(a.EvidenceIDs)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		_, err = s.operations.db.ExecContext(ctx, `UPDATE enforcement_actions SET account_id=$2,evidence_ids=$3,duration_seconds=$4,retry_count=$5,status=$6,last_error=$7,policy_parameters=$8,updated_at=greatest(clock_timestamp(),updated_at+interval '1 microsecond') WHERE action_id=$1`, id, a.AccountID, evidenceJSON, a.DurationSeconds, a.RetryCount, a.Status, a.LastError, parameters)
	}
	if err != nil {
		t.Fatal(err)
	}
	return nativeGenerationRow(t, s, id)
}

func TestNativeGenerationBindingCannotBorrowNewRunningSnapshot(t *testing.T) {
	for _, field := range []string{"generation", "account", "evidence", "lease"} {
		t.Run(field, func(t *testing.T) {
			s, a, client := nativeGenerationFixture(t)
			runtime := s.nativeActions[a.ConnectorID]
			read := runtime.Read
			var before string
			runtime.Read = func(ctx context.Context) (legacy4k.OnlineInventory, error) {
				if before == "" {
					before = nativeGenerationEdit(t, s, a.ActionID, func(current *EnforcementAction) {
						switch field {
						case "account":
							current.AccountID = "owned-new-account"
						case "evidence":
							current.EvidenceIDs = []string{"owned-new-evidence"}
						case "lease":
							current.PolicyParameters.LeaseID = "owned-new-lease"
						}
					})
				}
				return read(ctx)
			}
			s.setNativeRuntime(a.ConnectorID, runtime)
			s.deliverAction(a.ActionID, false)
			if before == "" || nativeGenerationRow(t, s, a.ActionID) != before || client.calls.Load() != 0 {
				t.Fatal("old binding changed or sent a newer running action")
			}
			var reservations, conflicts int
			if err := s.operations.db.QueryRow(`SELECT (SELECT count(*) FROM native_action_dispatch WHERE idempotency_key=$1),(SELECT count(*) FROM audit_logs WHERE target=$1 AND action='enforcement.delivery_receipt' AND outcome='receipt_conflict:native_binding')`, a.ActionID).Scan(&reservations, &conflicts); err != nil || reservations != 0 || conflicts != 1 {
				t.Fatalf("binding conflict was not retained without reservation: reservations=%d conflicts=%d err=%v", reservations, conflicts, err)
			}
		})
	}
}

func TestNativeGenerationFinalGuardStopsChangedRunningSnapshot(t *testing.T) {
	for _, field := range []string{"generation", "evidence", "lease", "duration", "retry"} {
		t.Run(field, func(t *testing.T) {
			s, a, client := nativeGenerationFixture(t)
			var before string
			client.beforeGuard = func() {
				before = nativeGenerationEdit(t, s, a.ActionID, func(current *EnforcementAction) {
					switch field {
					case "evidence":
						current.EvidenceIDs = []string{"owned-new-evidence"}
					case "lease":
						current.PolicyParameters.LeaseID = "owned-new-lease"
					case "duration":
						current.DurationSeconds = 120
					case "retry":
						current.RetryCount++
					}
				})
			}
			s.deliverAction(a.ActionID, false)
			if before == "" || nativeGenerationRow(t, s, a.ActionID) != before || client.calls.Load() != 0 {
				t.Fatal("old native attempt authorized or overwrote a changed running snapshot")
			}
			var reservations, observations, conflicts int
			if err := s.operations.db.QueryRow(`SELECT (SELECT count(*) FROM native_action_dispatch WHERE idempotency_key=$1),(SELECT count(*) FROM native_action_observations WHERE idempotency_key=$1),(SELECT count(*) FROM audit_logs WHERE target=$1 AND action='enforcement.delivery_receipt' AND outcome='receipt_conflict:native_observed')`, a.ActionID).Scan(&reservations, &observations, &conflicts); err != nil || reservations != 1 || observations != 1 || conflicts != 1 {
				t.Fatalf("prevented send lost durable journal or conflict: reservations=%d observations=%d conflicts=%d err=%v", reservations, observations, conflicts, err)
			}
		})
	}
}

func TestNativeGenerationLateObservationKeepsNewerRecord(t *testing.T) {
	for _, field := range []string{"current", "generation", "account", "evidence", "lease", "retry", "cancelled", "succeeded"} {
		t.Run(field, func(t *testing.T) {
			s, a, client := nativeGenerationFixture(t)
			var before string
			client.afterDispatch = func() {
				if field == "current" {
					return
				}
				before = nativeGenerationEdit(t, s, a.ActionID, func(current *EnforcementAction) {
					switch field {
					case "account":
						current.AccountID = "owned-new-account"
					case "evidence":
						current.EvidenceIDs = []string{"owned-new-evidence"}
					case "lease":
						current.PolicyParameters.LeaseID = "owned-new-lease"
					case "retry":
						current.RetryCount++
					case "cancelled", "succeeded":
						current.Status = field
						current.LastError = "owned-new-result"
					}
				})
			}
			s.deliverAction(a.ActionID, false)
			if client.calls.Load() != 1 {
				t.Fatal("native fixture did not send exactly once")
			}
			var status, receipt string
			var observations, conflicts, applied int
			if err := s.operations.db.QueryRow(`SELECT a.status,coalesce(a.remote_action_id,''),(SELECT count(*) FROM native_action_observations WHERE idempotency_key=a.idempotency_key),(SELECT count(*) FROM audit_logs WHERE target=a.action_id AND action='enforcement.delivery_receipt' AND outcome='receipt_conflict:native_observed'),(SELECT count(*) FROM audit_logs WHERE target=a.action_id AND action='enforcement.native_observed') FROM enforcement_actions a WHERE action_id=$1`, a.ActionID).Scan(&status, &receipt, &observations, &conflicts, &applied); err != nil {
				t.Fatal(err)
			}
			if field == "current" {
				if status != "succeeded" || receipt != "7" || observations != 1 || applied != 1 || conflicts != 0 {
					t.Fatal("current observation no longer completes the original native attempt")
				}
			} else if before == "" || nativeGenerationRow(t, s, a.ActionID) != before || observations != 1 || conflicts != 1 || applied != 0 {
				t.Fatal("late native observation changed a newer action or falsely audited completion")
			}
		})
	}
}
