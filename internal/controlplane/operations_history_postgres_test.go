package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"proxy-sentinel/internal/store"
	"testing"
	"time"
)

func TestOperationsSaveDoesNotResendImmutableHistory(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	ctx := context.Background()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	id := fmt.Sprintf("history-skip-%d", time.Now().UnixNano())
	defer db.ExecContext(ctx, "DELETE FROM risk_case_evidence_snapshots WHERE case_id=$1", id)
	defer func() {
		db.ExecContext(ctx, "DELETE FROM risk_case_evidence_snapshots WHERE case_id=$1", id)
		db.ExecContext(ctx, "DELETE FROM risk_cases WHERE case_id=$1", id)
	}()
	_, err = db.ExecContext(ctx, `INSERT INTO risk_cases(case_id,subject_type,subject_id,ip,status,priority,risk_score,risk_confidence,assessment_level,first_seen,last_seen,dedupe_key) VALUES($1,'ip',$1,'192.0.2.1','open','high',80,0.9,'high',now(),now(),$1)`, id)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO risk_case_evidence_snapshots(snapshot_id,case_id,evidence) VALUES($1,$1,'{"ip":"192.0.2.1"}')`, id)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `CREATE OR REPLACE FUNCTION test_reject_duplicate_history() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF EXISTS(SELECT 1 FROM risk_case_evidence_snapshots WHERE snapshot_id=NEW.snapshot_id) THEN RAISE EXCEPTION 'immutable history was resent'; END IF; RETURN NEW; END $$; CREATE TRIGGER test_no_history_resend BEFORE INSERT ON risk_case_evidence_snapshots FOR EACH ROW EXECUTE FUNCTION test_reject_duplicate_history()`)
	if err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(ctx, `DROP TRIGGER test_no_history_resend ON risk_case_evidence_snapshots;DROP FUNCTION test_reject_duplicate_history()`)
	ops, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer ops.db.Close()
	ops.mu.Lock()
	err = ops.saveLocked()
	ops.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	ops.mu.Lock()
	c := ops.doc.Cases[id]
	c.EvidenceHistory = append(c.EvidenceHistory, CaseEvidenceSnapshot{SnapshotID: id + "-new", Evidence: store.ProxyReviewCase{IP: "192.0.2.1"}, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	ops.doc.Cases[id] = c
	err = ops.saveLocked()
	ops.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM risk_case_evidence_snapshots WHERE case_id=$1`, id).Scan(&count); err != nil || count != 2 {
		t.Fatal(count, err)
	}
}
