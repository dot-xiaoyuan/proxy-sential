package store

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestPostgresOperationsUseDatabasePagination(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	postgres, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer postgres.Close()
	const sensorID = "t7-page-sensor"
	if _, err := postgres.db.ExecContext(ctx, `INSERT INTO sensors(sensor_id,display_name,collector_kind) VALUES($1,'T7 pagination','test') ON CONFLICT(sensor_id) DO NOTHING`, sensorID); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.db.ExecContext(ctx, `DELETE FROM collector_runs WHERE run_id LIKE 't7-page-run-%'; DELETE FROM audit_logs WHERE audit_id LIKE 't7-page-audit-%'`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = postgres.db.ExecContext(cleanup, `DELETE FROM collector_runs WHERE run_id LIKE 't7-page-run-%'; DELETE FROM audit_logs WHERE audit_id LIKE 't7-page-audit-%'; DELETE FROM sensors WHERE sensor_id=$1`, sensorID)
	})
	if _, err := postgres.db.ExecContext(ctx, `INSERT INTO collector_runs(run_id,sensor_id,started_at,finished_at,summary) SELECT 't7-page-run-'||value,$1,now()-value*interval '1 second',now()-value*interval '1 second','{"marker":"pagination"}'::jsonb FROM generate_series(1,65) value`, sensorID); err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.db.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) SELECT 't7-page-audit-'||value,'t7-user','case.update','case-'||value,'success',now()-value*interval '1 second' FROM generate_series(1,65) value`); err != nil {
		t.Fatal(err)
	}
	runs, runPage, err := postgres.ListRunsPage(ctx, Query{Limit: 20, Cursor: 20, Q: "pagination"})
	if err != nil || len(runs) != 20 || runPage.Total != 65 || runPage.NextCursor == nil || *runPage.NextCursor != "40" {
		t.Fatalf("collector run pagination failed: items=%d page=%+v err=%v", len(runs), runPage, err)
	}
	logs, auditPage, err := postgres.ListAuditLogsPage(ctx, Query{Limit: 20, Cursor: 40, Q: "case.update"})
	if err != nil || len(logs) != 20 || auditPage.Total != 65 || auditPage.NextCursor == nil || *auditPage.NextCursor != "60" {
		t.Fatalf("audit pagination failed: items=%d page=%+v err=%v", len(logs), auditPage, err)
	}
}
