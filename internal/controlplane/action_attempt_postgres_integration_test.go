package controlplane

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestActionAttemptNativeLockCannotHoldDeliveryResult(t *testing.T) {
	for _, completed := range []bool{true, false} {
		name := "completed"
		if !completed {
			name = "transport_rejected"
		}
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if completed {
					w.Write([]byte(`{"action_id":"owned-attempt-receipt","status":"completed"}`))
				} else {
					w.WriteHeader(http.StatusServiceUnavailable)
					w.Write([]byte(`{"detail":"owned-private-response"}`))
				}
			}))
			defer remote.Close()
			s, parent, child := actionRecoveryNativeFixture(t, remote.URL, "owned-attempt-operator")
			db := s.operations.db
			setup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			lock, err := db.BeginTx(setup, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Rollback()
			if _, err := lock.ExecContext(setup, `LOCK enforcement_action_attempts IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				s.deliverAction(child.ActionID, true)
				close(done)
			}()
			finishedUnderLock := false
			select {
			case <-done:
				finishedUnderLock = true
			case <-time.After(4500 * time.Millisecond):
			}
			if err := lock.Rollback(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("delivery did not finish after releasing the owned fixture lock")
			}
			if !finishedUnderLock {
				t.Fatal("attempt-table lock held the delivery worker and prevented receipt or retry persistence")
			}
			var status, parentStatus, key, remoteID string
			var retries, failures, attempts, audits int
			var due sql.NullTime
			if err := db.QueryRow(`SELECT a.status,a.retry_count,a.next_attempt_at,a.idempotency_key,coalesce(a.remote_action_id,''),p.status,c.consecutive_failures,(SELECT count(*) FROM enforcement_action_attempts WHERE action_id=a.action_id),(SELECT count(*) FROM audit_logs WHERE action='enforcement.delivery_attempt' AND target=a.action_id AND outcome='attempt_storage_timeout') FROM enforcement_actions a JOIN enforcement_actions p ON p.action_id=a.parent_action_id JOIN enforcement_connectors c ON c.connector_id=a.connector_id WHERE a.action_id=$1`, child.ActionID).Scan(&status, &retries, &due, &key, &remoteID, &parentStatus, &failures, &attempts, &audits); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 || key != child.IdempotencyKey || attempts != 0 || audits != 1 {
				t.Fatalf("attempt storage failure changed transport semantics: calls=%d attempts=%d audits=%d", calls.Load(), attempts, audits)
			}
			if completed {
				if status != "revoked" || parentStatus != "revoked" || retries != 0 || due.Valid || failures != 0 || remoteID != "owned-attempt-receipt" {
					t.Fatal("confirmed recovery was lost or retried because attempt storage timed out")
				}
			} else if status != "pending" || parentStatus != "succeeded" || retries != 1 || !due.Valid || failures != 4 || remoteID != "" {
				t.Fatal("attempt storage timeout changed the actual transport retry or connector circuit")
			}
			var outcome string
			if err := db.QueryRow(`SELECT outcome FROM audit_logs WHERE action='enforcement.delivery_attempt' AND target=$1`, child.ActionID).Scan(&outcome); err != nil || strings.Contains(outcome, "owned-private-response") {
				t.Fatal("storage audit is missing or exposes remote response details")
			}
			var parentID string
			if err := db.QueryRow(`SELECT parent_action_id FROM enforcement_actions WHERE action_id=$1`, child.ActionID).Scan(&parentID); err != nil || parentID != parent.ActionID {
				t.Fatal("attempt timeout changed the original recovery intent")
			}
		})
	}
}

func TestActionAttemptNativeStorageFailureDoesNotRetryConfirmedRecovery(t *testing.T) {
	var calls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"action_id":"owned-storage-receipt","status":"completed"}`))
	}))
	defer remote.Close()
	s, parent, child := actionRecoveryNativeFixture(t, remote.URL, "owned-attempt-operator")
	db := s.operations.db
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// This constraint exists only inside the disposable acceptance database.
	// It rejects this real attempt insert while leaving receipt storage usable.
	if _, err := db.ExecContext(ctx, `ALTER TABLE enforcement_action_attempts ADD CONSTRAINT owned_attempt_store_failure CHECK(http_status IS DISTINCT FROM 200) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := db.ExecContext(cleanup, `ALTER TABLE enforcement_action_attempts DROP CONSTRAINT owned_attempt_store_failure`); err != nil {
			t.Error(err)
		}
	}()
	s.deliverAction(child.ActionID, true)
	var status, parentStatus, remoteID string
	var retries, attempts, audits int
	if err := db.QueryRowContext(ctx, `SELECT a.status,p.status,a.remote_action_id,a.retry_count,(SELECT count(*) FROM enforcement_action_attempts WHERE action_id=a.action_id),(SELECT count(*) FROM audit_logs WHERE action='enforcement.delivery_attempt' AND target=a.action_id AND outcome='attempt_storage_failed') FROM enforcement_actions a JOIN enforcement_actions p ON p.action_id=a.parent_action_id WHERE a.action_id=$1 AND p.action_id=$2`, child.ActionID, parent.ActionID).Scan(&status, &parentStatus, &remoteID, &retries, &attempts, &audits); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || status != "revoked" || parentStatus != "revoked" || remoteID != "owned-storage-receipt" || retries != 0 || attempts != 0 || audits != 1 {
		t.Fatal("attempt insert error replaced or retried the confirmed recovery result")
	}
}
