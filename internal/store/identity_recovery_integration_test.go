package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestIdentityRecoveryKeepsLegacyLedgerAndDeduplicates(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "recovery", SensorID: fmt.Sprintf("recovery-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	key := IdentityScopeKey(scope)
	event := inboxEvent(scope, key+"-event", "session", "192.0.2.1", "start", time.Now().UTC())
	if _, err := pg.db.ExecContext(ctx, `INSERT INTO identity_pipeline_scopes(scope_key,source,sensor_id,campus_id,access_domain,enabled) VALUES($1,$2,$3,$4,$5,true)`, key, scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal([]normalized.Event{event})
	for i := 0; i < 12; i++ {
		suffix := fmt.Sprintf("duplicate-%02d", i)
		if _, err := pg.db.ExecContext(ctx, `INSERT INTO identity_ingest_batches(batch_id,source,sensor_id,status,records_read,records_emitted,received_at,normalized_events) VALUES($1,$2,$3,'failed',1,1,now(),$4)`, key+suffix, scope.Source, scope.SensorID, raw); err != nil {
			t.Fatal(err)
		}
	}
	report, err := pg.RecoverFailedIdentityBatches(ctx, scope.Source, scope.SensorID, true)
	if err != nil || report.UniqueEvents != 1 || report.ImportedEvents != 1 || report.Complete {
		t.Fatalf("recovery: %+v %v", report, err)
	}
	report, err = pg.RecoverFailedIdentityBatches(ctx, scope.Source, scope.SensorID, true)
	if err != nil || report.AlreadyImported != 1 || report.ImportedEvents != 0 {
		t.Fatalf("retry: %+v %v", report, err)
	}
	work, err := pg.claimIdentityInbox(ctx, scope.SensorID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.applyIdentityInbox(ctx, work); err != nil {
		t.Fatal(err)
	}
	report, err = pg.RecoverFailedIdentityBatches(ctx, scope.Source, scope.SensorID, false)
	if err != nil || report.AlreadyApplied != 1 || report.PendingIdentity != 0 || report.RawExportPending != 1 || report.Complete {
		t.Fatalf("separate identity/export: %+v %v", report, err)
	}
	var failed int
	if err = pg.db.QueryRowContext(ctx, `SELECT count(*) FROM identity_ingest_batches WHERE source=$1 AND sensor_id=$2 AND status='failed'`, scope.Source, scope.SensorID).Scan(&failed); err != nil || failed != 12 {
		t.Fatalf("legacy evidence changed %d %v", failed, err)
	}
	if _, err = pg.db.ExecContext(ctx, `INSERT INTO identity_ingest_batches(batch_id,source,sensor_id,status,records_read,received_at,normalized_events) VALUES($1,$2,$3,'failed',1,now(),'[]')`, key+"missing", scope.Source, scope.SensorID); err != nil {
		t.Fatal(err)
	}
	report, err = pg.RecoverFailedIdentityBatches(ctx, scope.Source, scope.SensorID, false)
	if err != nil || len(report.MissingEvidenceBatches) != 1 || report.Complete {
		t.Fatalf("missing evidence hidden: %+v %v", report, err)
	}
}

func TestIdentityRecoveryClassifiesUnacceptableAddressWithoutStoppingValidEvents(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "recovery-invalid", SensorID: fmt.Sprintf("recovery-invalid-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	key := IdentityScopeKey(scope)
	if _, err := pg.db.ExecContext(ctx, `INSERT INTO identity_pipeline_scopes(scope_key,source,sensor_id,campus_id,access_domain,enabled) VALUES($1,$2,$3,$4,$5,true)`, key, scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain); err != nil {
		t.Fatal(err)
	}
	valid := inboxEvent(scope, key+"valid", "valid-session", "192.0.2.1", "start", time.Now().UTC())
	invalid := inboxEvent(scope, key+"invalid", "invalid-session", "0.0.0.0", "start", time.Now().UTC())
	raw, _ := json.Marshal([]normalized.Event{invalid, valid})
	if _, err := pg.db.ExecContext(ctx, `INSERT INTO identity_ingest_batches(batch_id,source,sensor_id,status,records_read,records_emitted,received_at,normalized_events) VALUES($1,$2,$3,'failed',2,2,now(),$4)`, key+"legacy", scope.Source, scope.SensorID, raw); err != nil {
		t.Fatal(err)
	}
	report, err := pg.RecoverFailedIdentityBatches(ctx, scope.Source, scope.SensorID, true)
	if err != nil || report.InvalidEvents != 1 || report.ImportedEvents != 1 || report.Complete {
		t.Fatalf("invalid historical event stopped recovery or disappeared: %+v err=%v", report, err)
	}
	work, err := pg.claimIdentityInbox(ctx, scope.SensorID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.applyIdentityInbox(ctx, work); err != nil {
		t.Fatal(err)
	}
	summary, err := ReadIdentityPipelineSummary(ctx, pg.db, scope)
	if err != nil || summary.PendingRecords != 0 || summary.Sessions == nil || *summary.Sessions != 1 {
		t.Fatalf("valid event not applied: %+v err=%v", summary, err)
	}
}

func TestIdentityRecoveryWaitsForRawExportToCatchUp(t *testing.T) {
	pg := inboxTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	scope := IdentityScope{Source: "recovery-export-budget", SensorID: fmt.Sprintf("recovery-export-budget-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	key := IdentityScopeKey(scope)
	if _, err := pg.db.ExecContext(ctx, `INSERT INTO identity_pipeline_scopes(scope_key,source,sensor_id,campus_id,access_domain,enabled,export_pending_records) VALUES($1,$2,$3,$4,$5,true,$6)`, key, scope.Source, scope.SensorID, scope.CampusID, scope.AccessDomain, identityRecoveryExportBudget+1); err != nil {
		t.Fatal(err)
	}
	event := inboxEvent(scope, key+"event", "session", "192.0.2.1", "start", time.Now().UTC())
	raw, _ := json.Marshal([]normalized.Event{event})
	if _, err := pg.db.ExecContext(ctx, `INSERT INTO identity_ingest_batches(batch_id,source,sensor_id,status,records_read,records_emitted,received_at,normalized_events) VALUES($1,$2,$3,'failed',1,1,now(),$4)`, key+"legacy", scope.Source, scope.SensorID, raw); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := pg.RecoverFailedIdentityBatches(ctx, scope.Source, scope.SensorID, true)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("recovery bypassed export budget: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if _, err := pg.db.ExecContext(ctx, `UPDATE identity_pipeline_scopes SET export_pending_records=0 WHERE scope_key=$1`, key); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("recovery did not resume after export caught up")
	}
}

func TestIdentitySummaryDoesNotReadSessionDetails(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "summary", SensorID: fmt.Sprintf("summary-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	event := inboxEvent(scope, scope.SensorID, "session", "192.0.2.1", "start", time.Now())
	if _, err := pg.acceptIdentityBatch(ctx, scope.SensorID, "hash", scope, []normalized.Event{event}, 1); err != nil {
		t.Fatal(err)
	}
	tx, err := pg.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `LOCK TABLE identity_current_addresses,identity_session_refs,identity_account_refs,account_sessions,account_identity_session_projection,identity_ip_mac_history IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	work, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	summary, err := ReadIdentityPipelineSummary(work, pg.db, scope)
	if err != nil || summary.PendingRecords != 1 {
		t.Fatalf("summary touches details: %+v %v", summary, err)
	}
}

func TestIdentityPoisonedAddressIsNotAcknowledged(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "invalid", SensorID: fmt.Sprintf("invalid-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	for _, ip := range []string{"not-an-ip", "0.0.0.0", "224.0.0.1"} {
		event := inboxEvent(scope, scope.SensorID+ip, "session", ip, "start", time.Now())
		if _, err := pg.acceptIdentityBatch(ctx, scope.SensorID+ip, "hash", scope, []normalized.Event{event}, 1); !errors.Is(err, ErrInvalidIdentityBatch) {
			t.Fatalf("poison accepted %q: %v", ip, err)
		}
	}
}

func TestDurableIdentityCursorNeverSkipsBacklog(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	sensor := fmt.Sprintf("durable-cursor-%d", time.Now().UnixNano())
	scope := IdentityScope{Source: "radius", SensorID: sensor, CampusID: "c", AccessDomain: "d"}
	t.Setenv("PROXY_SENTINEL_MAX_BACKLOG", "1m")
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-24 * time.Hour)
	if _, err := pg.db.ExecContext(ctx, `INSERT INTO identity_materializer_cursors(sensor_id,phase,cursor_at,cutover_at) VALUES($1,'live',$2,$2)`, sensor, at); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.db.ExecContext(ctx, `INSERT INTO identity_pipeline_scopes(scope_key,source,sensor_id,campus_id,access_domain,enabled) VALUES($1,$2,$3,$4,$5,true)`, IdentityScopeKey(scope), scope.Source, sensor, scope.CampusID, scope.AccessDomain); err != nil {
		t.Fatal(err)
	}
	backend := &DBStore{pg: pg}
	cursor, _, _, ok, err := backend.claimIdentityCursor(ctx, sensor, "live")
	if err != nil || !ok || !cursor.Equal(at) {
		t.Fatalf("durable evidence skipped: %s %v", cursor, err)
	}
}

func TestIdentityProjectionCleanupPreservesCurrentAndEvidence(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "cleanup", SensorID: fmt.Sprintf("cleanup-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	key := IdentityScopeKey(scope)
	at := time.Now().UTC().Add(-time.Minute)
	snap := IdentitySnapshot{IdentityScope: scope, SnapshotID: "old", ObservedAt: at, Events: []normalized.Event{inboxEvent(scope, key, "session", "192.0.2.1", "reconcile", at)}}
	if err := pg.calibrateIdentitySnapshot(ctx, snap); err != nil {
		t.Fatal(err)
	}
	snap.SnapshotID = "new"
	snap.ObservedAt = at.Add(time.Second)
	if err := pg.calibrateIdentitySnapshot(ctx, snap); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := pg.cleanIdentityProjectionGeneration(ctx, scope.SensorID); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := pg.db.QueryRowContext(ctx, `SELECT count(*) FROM identity_current_addresses WHERE scope_key=$1`, key).Scan(&n); err != nil || n != 1 {
		t.Fatalf("cleanup lost current or retained obsolete: %d %v", n, err)
	}
	summary, err := ReadIdentityPipelineSummary(ctx, pg.db, scope)
	if err != nil || summary.Sessions == nil || *summary.Sessions != 1 {
		t.Fatalf("current changed: %+v %v", summary, err)
	}
}

func TestIdentityCalibrationCatchesConcurrentLoginAndCrash(t *testing.T) {
	for _, crash := range []bool{false, true} {
		t.Run(fmt.Sprint(crash), func(t *testing.T) {
			pg := inboxTestStore(t)
			ctx := context.Background()
			scope := IdentityScope{Source: "calibration-concurrent", SensorID: fmt.Sprintf("build-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
			key := IdentityScopeKey(scope)
			at := time.Now().UTC().Add(-time.Minute)
			snapshot := IdentitySnapshot{IdentityScope: scope, SnapshotID: "old", ObservedAt: at, Events: []normalized.Event{inboxEvent(scope, key+"old", "old-session", "192.0.2.1", "reconcile", at)}}
			if err := pg.calibrateIdentitySnapshot(ctx, snapshot); err != nil {
				t.Fatal(err)
			}
			blocker, err := pg.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback()
			var pid int
			if err = blocker.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if _, err = blocker.ExecContext(ctx, `INSERT INTO identity_account_refs VALUES($1,'snapshot-new-2','student',0)`, key); err != nil {
				t.Fatal(err)
			}
			snapshot.SnapshotID = "new"
			snapshot.ObservedAt = at.Add(time.Second)
			build, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- pg.calibrateIdentitySnapshot(build, snapshot) }()
			deadline := time.Now().Add(3 * time.Second)
			for {
				var blocked bool
				err = pg.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked)
				if err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("builder never reached blocked publication stage")
				}
				time.Sleep(10 * time.Millisecond)
			}
			event := inboxEvent(scope, key+"new", "new-session", "192.0.2.2", "start", at.Add(2*time.Second))
			if _, err = pg.acceptIdentityBatch(ctx, key, "hash", scope, []normalized.Event{event}, 1); err != nil {
				t.Fatal(err)
			}
			work, err := pg.claimIdentityInbox(ctx, scope.SensorID, 100)
			if err != nil {
				t.Fatal(err)
			}
			if err = pg.applyIdentityInbox(ctx, work); err != nil {
				t.Fatal(err)
			}
			if crash {
				cancel()
				if err = <-done; err == nil {
					t.Fatal("cancelled build published")
				}
				blocker.Rollback()
				var id string
				if err = pg.db.QueryRowContext(ctx, `SELECT snapshot_id FROM identity_pipeline_scopes WHERE scope_key=$1`, key).Scan(&id); err != nil || id != "old" {
					t.Fatalf("failed build replaced current: %s %v", id, err)
				}
				if err = pg.calibrateIdentitySnapshot(ctx, snapshot); err != nil {
					t.Fatal(err)
				}
			} else {
				blocker.Rollback()
				if err = <-done; err != nil {
					t.Fatal(err)
				}
			}
			summary, err := ReadIdentityPipelineSummary(ctx, pg.db, scope)
			if err != nil || summary.Sessions == nil || *summary.Sessions != 2 {
				t.Fatalf("concurrent login lost: %+v %v", summary, err)
			}
		})
	}
}

func TestDerivedIdentityDoesNotRewriteAuthority(t *testing.T) {
	pg := inboxTestStore(t)
	ctx := context.Background()
	scope := IdentityScope{Source: "ownership", SensorID: fmt.Sprintf("owner-%d", time.Now().UnixNano()), CampusID: "c", AccessDomain: "d"}
	key := IdentityScopeKey(scope)
	event := inboxEvent(scope, key+"one", scope.SensorID+"session", "192.0.2.1", "start", time.Now().UTC())
	if _, err := pg.acceptIdentityBatch(ctx, key, "hash", scope, []normalized.Event{event}, 1); err != nil {
		t.Fatal(err)
	}
	work, err := pg.claimIdentityInbox(ctx, scope.SensorID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = pg.applyIdentityInbox(ctx, work); err != nil {
		t.Fatal(err)
	}
	event.EventID = key + "derived-only"
	if err = pg.WriteIdentityEvents(ctx, []normalized.Event{event}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err = pg.db.QueryRowContext(ctx, `SELECT count(*) FROM policy_identity_observations WHERE event_id=$1`, event.EventID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("derived rewrote authoritative fact: %d %v", n, err)
	}
	summary, err := ReadIdentityPipelineSummary(ctx, pg.db, scope)
	if err != nil || *summary.Sessions != 1 || summary.ProcessedSequence != 1 {
		t.Fatalf("derived changed counters: %+v %v", summary, err)
	}
	if err = pg.db.QueryRowContext(ctx, `SELECT count(*) FROM account_sessions WHERE session_id=$1`, scope.SensorID+"session").Scan(&n); err != nil || n != 1 {
		t.Fatalf("compatibility display projection stale: %d %v", n, err)
	}
	if err = pg.writeLegacyIdentityEvents(ctx, []normalized.Event{event}); err == nil {
		t.Fatal("old synchronous writer took durable scope ownership")
	}
}
