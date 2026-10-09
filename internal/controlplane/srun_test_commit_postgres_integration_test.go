package controlplane

import (
	"context"
	"database/sql"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Only the success-finalization segment is exercised here; network probes are
// deliberately not invoked against a real controller. The same segment is
// called by testSRun4K after its read-only checks actually succeed.
func TestSRunTestResultNativeAtomicCommit(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var name string
	if err = db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(name) {
		t.Fatal("dedicated acceptance database required")
	}
	for _, stmt := range []string{
		`CREATE TABLE srun4k_integrations(connector_id text PRIMARY KEY,host text,source text,sensor_id text,reconcile_interval_hours integer,connection_state text,last_error text,last_tested_at timestamptz,last_synced_at timestamptz,event_channel_state text,updated_at timestamptz,last_test_result_order bigint NOT NULL DEFAULT 0,last_sync_result_order bigint NOT NULL DEFAULT 0,last_health_result_order bigint NOT NULL DEFAULT 0)`,
		`CREATE TABLE audit_logs(audit_id text PRIMARY KEY,actor text,action text,target text,outcome text,created_at timestamptz)`,
		`CREATE FUNCTION reject_result_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'isolated private result-write detail'; END $$`,
	} {
		if _, err = db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{operations: &operationsState{db: db}, reader: configuredProbeAudit{db: db}}
	ctx = context.WithValue(ctx, srunOperationOrderKey{}, int64(1))
	actorCtx := context.WithValue(ctx, sessionContextKey{}, Session{User: User{ID: "isolated-operator"}})
	for _, tc := range []string{"success", "update_rejected", "audit_rejected", "deferred_commit_rejected", "missing_target", "changed_configuration", "changed_event_channel", "newer_check_exists", "audit_timeout", "caller_cancelled"} {
		t.Run(tc, func(t *testing.T) {
			for _, stmt := range []string{
				`DELETE FROM audit_logs`,
				`DELETE FROM srun4k_integrations`,
				`INSERT INTO srun4k_integrations VALUES('one','192.0.2.1','srun4k:one','one',6,'failed','previous failure','2026-09-30 00:00:00Z','2026-09-30 01:00:00Z','healthy',now())`,
			} {
				if _, err = db.ExecContext(ctx, stmt); err != nil {
					t.Fatal(err)
				}
			}
			item := srun4KIntegration{ConnectorID: "one", Host: "192.0.2.1", Source: "srun4k:one", SensorID: "one", ReconcileIntervalHours: 6, EventChannelState: "healthy"}
			checked := time.Now().UTC().Truncate(time.Microsecond)
			testCtx := actorCtx
			var held *sql.Tx
			switch tc {
			case "update_rejected":
				if _, err = db.ExecContext(ctx, `CREATE TRIGGER reject_state BEFORE UPDATE ON srun4k_integrations FOR EACH ROW EXECUTE FUNCTION reject_result_write()`); err != nil {
					t.Fatal(err)
				}
				defer db.ExecContext(ctx, `DROP TRIGGER reject_state ON srun4k_integrations`)
			case "audit_rejected":
				if _, err = db.ExecContext(ctx, `CREATE TRIGGER reject_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION reject_result_write()`); err != nil {
					t.Fatal(err)
				}
				defer db.ExecContext(ctx, `DROP TRIGGER reject_audit ON audit_logs`)
			case "deferred_commit_rejected":
				if _, err = db.ExecContext(ctx, `CREATE CONSTRAINT TRIGGER reject_audit AFTER INSERT ON audit_logs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_result_write()`); err != nil {
					t.Fatal(err)
				}
				defer db.ExecContext(ctx, `DROP TRIGGER reject_audit ON audit_logs`)
			case "missing_target":
				if _, err = db.ExecContext(ctx, `DELETE FROM srun4k_integrations`); err != nil {
					t.Fatal(err)
				}
			case "changed_configuration":
				if _, err = db.ExecContext(ctx, `UPDATE srun4k_integrations SET host='198.51.100.1'`); err != nil {
					t.Fatal(err)
				}
			case "changed_event_channel":
				if _, err = db.ExecContext(ctx, `UPDATE srun4k_integrations SET event_channel_state='waiting'`); err != nil {
					t.Fatal(err)
				}
			case "newer_check_exists":
				if _, err = db.ExecContext(ctx, `UPDATE srun4k_integrations SET last_tested_at=$1,last_test_result_order=2,last_health_result_order=2`, checked.Add(time.Millisecond)); err != nil {
					t.Fatal(err)
				}
			case "audit_timeout":
				held, err = db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer held.Rollback()
				if _, err = held.ExecContext(ctx, `LOCK audit_logs IN ACCESS EXCLUSIVE MODE`); err != nil {
					t.Fatal(err)
				}
				short, stop := context.WithTimeout(actorCtx, 150*time.Millisecond)
				defer stop()
				testCtx = short
			case "caller_cancelled":
				cancelled, stop := context.WithCancel(actorCtx)
				stop()
				testCtx = cancelled
			}
			var previousTest time.Time
			if tc != "missing_target" {
				if err = db.QueryRowContext(ctx, `SELECT last_tested_at FROM srun4k_integrations WHERE connector_id='one'`).Scan(&previousTest); err != nil {
					t.Fatal(err)
				}
			}
			started := time.Now()
			result, callErr := s.completeSRun4KTest(testCtx, item, 81, checked)
			if held != nil {
				if err = held.Rollback(); err != nil {
					t.Fatal(err)
				}
				if time.Since(started) > time.Second {
					t.Fatal("audit timeout escaped caller budget")
				}
			}

			succeeds := tc == "success" || tc == "changed_event_channel"
			if succeeds {
				if callErr != nil || result == nil {
					t.Fatalf("valid commit failed: result=%v error=%v", result, callErr)
				}
				expectedEvent := "healthy"
				if tc == "changed_event_channel" {
					expectedEvent = "waiting"
				}
				if result["enforcement_ready"] != (expectedEvent == "healthy") || result["channels"].(map[string]string)["event_channel"] != expectedEvent {
					t.Fatalf("outdated event channel reported ready: result=%v", result)
				}
			} else {
				if callErr == nil || result != nil {
					t.Errorf("uncommitted result reported successful: result=%v error=%v", result, callErr)
				}
				if callErr != nil {
					s.recordSRunSyncFailure(testCtx, item.ConnectorID, callErr)
				}
				if callErr != nil && strings.Contains(callErr.Error(), "private result-write detail") {
					t.Error("private SQL error exposed")
				}
			}
			var audits int
			if err = db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE action='integration.srun4k.test' AND outcome='read_only_succeeded' AND actor='isolated-operator'`).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if succeeds && audits != 1 || !succeeds && audits != 0 {
				t.Errorf("audit/state not atomic: successful_audits=%d expected_success=%t", audits, succeeds)
			}
			if tc != "missing_target" {
				var state, message, eventState string
				var tested, synced time.Time
				if err = db.QueryRowContext(ctx, `SELECT connection_state,last_error,last_tested_at,last_synced_at,event_channel_state FROM srun4k_integrations WHERE connector_id='one'`).Scan(&state, &message, &tested, &synced, &eventState); err != nil {
					t.Fatal(err)
				}
				if succeeds && (state != "healthy" || message != "" || !tested.Equal(checked)) {
					t.Error("successful check metadata not durable")
				}
				if !succeeds && (state != "failed" || message != "previous failure" || !tested.Equal(previousTest)) {
					t.Error("failed commit changed metadata")
				}
				if !synced.Equal(time.Date(2026, 9, 30, 1, 0, 0, 0, time.UTC)) {
					t.Error("connection test changed successful sync time")
				}
			}
		})
	}
}
