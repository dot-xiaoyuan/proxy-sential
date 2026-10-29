package store

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"
)

// This opt-in check creates only transaction-local temporary tables. It never
// applies migrations or changes application rows, and rollback removes all
// fixtures. This permits SQL-semantic validation without a local database stack.
func TestAuthenticationTemporaryPostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_AUTH_TEMP_TEST_DSN")
	if dsn == "" {
		t.Skip("explicit temporary-table PostgreSQL validation DSN required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, table := range []string{"account_sessions", "endpoint_entities", "account_identity_session_projection", "account_identity_projection_sources", "shared_device_profiles", "shared_device_profile_jobs", "shared_device_profile_runtime", "identity_derived_fresh_starts", "identity_derived_ready"} {
		if _, err = tx.ExecContext(ctx, "CREATE TEMP TABLE "+table+" (LIKE public."+table+" INCLUDING DEFAULTS INCLUDING CONSTRAINTS INCLUDING INDEXES) ON COMMIT DROP"); err != nil {
			t.Fatal(err)
		}
		var temporary bool
		if err = tx.QueryRowContext(ctx, `SELECT relpersistence='t' FROM pg_class WHERE oid=$1::regclass`, table).Scan(&temporary); err != nil || !temporary {
			t.Fatalf("fixture is not isolated: %s %v", table, err)
		}
	}
	// Validate the candidate column before its real migration has been applied.
	if _, err = tx.ExecContext(ctx, `ALTER TABLE pg_temp.account_sessions ADD COLUMN IF NOT EXISTS last_confirmed_at timestamptz`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `CREATE TEMP TABLE identity_endpoint_invalidations(endpoint_id text PRIMARY KEY,revision bigint NOT NULL DEFAULT 1,completed_revision bigint NOT NULL DEFAULT 0,dirty_since timestamptz NOT NULL DEFAULT clock_timestamp()) ON COMMIT DROP; INSERT INTO pg_temp.endpoint_entities(endpoint_id,entity_role,first_seen,last_seen,identity_confidence) SELECT id,'endpoint',now(),now(),0.95 FROM unnest(ARRAY['endpoint-a','endpoint-b','endpoint-c']) id`); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-5 * time.Minute)
	session := AccountSession{SessionID: "auth-temp", AccountID: "account-a", EndpointID: "endpoint-a", MAC: "02:00:00:00:00:01", IP: "192.0.2.1", Source: "test", StartedAt: at.Format(time.RFC3339Nano), LastConfirmedAt: at.Format(time.RFC3339Nano), SessionStatus: "login"}
	write := func(want int) {
		t.Helper()
		changed, err := upsertChangedAuthenticationSessions(ctx, tx, []AccountSession{session})
		if err != nil || len(changed) != want {
			t.Fatalf("expected %d invalidation keys, got %+v: %v", want, changed, err)
		}
	}
	write(1)
	var version string
	if err = tx.QueryRowContext(ctx, `SELECT ctid::text FROM account_sessions WHERE session_id='auth-temp'`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	write(0)
	var replayVersion string
	if err = tx.QueryRowContext(ctx, `SELECT ctid::text FROM account_sessions WHERE session_id='auth-temp'`).Scan(&replayVersion); err != nil || version != replayVersion {
		t.Fatalf("replay physically rewrote a session: %s %s %v", version, replayVersion, err)
	}
	session.EndpointID, session.MAC = "endpoint-b", "02:00:00:00:00:02"
	session.LastConfirmedAt = at.Add(time.Minute).Format(time.RFC3339Nano)
	write(2) // Both old and new association readers must be invalidated.
	session.EndpointID, session.MAC = "endpoint-c", "02:00:00:00:00:03"
	session.LastConfirmedAt = at.Add(90 * time.Second).Format(time.RFC3339Nano)
	write(2)
	session.EndpointID, session.MAC = "endpoint-b", "02:00:00:00:00:02"
	session.LastConfirmedAt = at.Add(100 * time.Second).Format(time.RFC3339Nano)
	write(2)
	var departures int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_temp.identity_endpoint_invalidations WHERE completed_revision<revision`).Scan(&departures); err != nil || departures != 3 {
		t.Fatalf("rapid relationship moves lost departed endpoints: %d %v", departures, err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE pg_temp.identity_endpoint_invalidations SET revision=2 WHERE endpoint_id='endpoint-b'`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, completeAuthenticationDeparturesSQL, `[ {"endpoint_id":"endpoint-b","revision":1} ]`); err != nil {
		t.Fatal(err)
	}
	var remains bool
	if err = tx.QueryRowContext(ctx, `SELECT completed_revision=1 AND revision=2 FROM pg_temp.identity_endpoint_invalidations WHERE endpoint_id='endpoint-b'`).Scan(&remains); err != nil || !remains {
		t.Fatalf("old inventory acknowledgement erased new departure: %v", err)
	}
	session.SessionStatus, session.EndedAt = "logout", at.Add(2*time.Minute).Format(time.RFC3339Nano)
	session.LastConfirmedAt = session.EndedAt
	write(1)
	session.SessionStatus, session.EndedAt = "login", ""
	session.LastConfirmedAt = at.Add(time.Minute).Format(time.RFC3339Nano)
	write(0) // Late login must not reopen the already ended generation.
	var ended bool
	if err = tx.QueryRowContext(ctx, `SELECT ended_at IS NOT NULL AND session_status='logout' FROM account_sessions WHERE session_id='auth-temp'`).Scan(&ended); err != nil || !ended {
		t.Fatalf("late arrival reopened session: %v", err)
	}

	// A confirmation remains current even when the business row's change time
	// is old. Read the real consumer SQL, not a simulated identity lookup.
	session.SessionID = "auth-heartbeat"
	session.StartedAt = at.Add(-3 * time.Hour).Format(time.RFC3339Nano)
	session.LastConfirmedAt = at.Add(4 * time.Minute).Format(time.RFC3339Nano)
	write(1)
	if _, err = tx.ExecContext(ctx, `UPDATE account_sessions SET updated_at=now()-interval '2 hours' WHERE session_id='auth-heartbeat'`); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.QueryContext(ctx, currentAuthSessionsSQL, []string{"020000000002"}, []string{"endpoint-b"})
	if err != nil {
		t.Fatal(err)
	}
	current := 0
	for rows.Next() {
		current++
	}
	err = rows.Err()
	rows.Close()
	if err != nil || current != 1 {
		t.Fatalf("confirmation lost current authentication: count=%d %v", current, err)
	}

	if _, err = tx.ExecContext(ctx, `INSERT INTO shared_device_profile_runtime(singleton,cutover_at) VALUES(true,now()-interval '1 day'); INSERT INTO shared_device_profiles(profile_id,sensor_id,endpoint_id,mac,primary_ip,first_seen,last_observed_at,identity_at,identity_expires_at,list_item) VALUES('profile-a','sensor-a','endpoint-b','02:00:00:00:00:02','192.0.2.1',now(),now(),now(),now()+interval '1 hour','{}')`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err = enqueueSharedDeviceProfileJobs(ctx, tx, []AccountSession{session}, at); err != nil {
			t.Fatal(err)
		}
	}
	var generation int
	if err = tx.QueryRowContext(ctx, `SELECT dirty_generation FROM shared_device_profile_jobs`).Scan(&generation); err != nil || generation != 1 {
		t.Fatalf("unclaimed changes were not coalesced: %d %v", generation, err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE shared_device_profile_jobs SET lease_until=now()+interval '1 minute',lease_owner='worker'`); err != nil {
		t.Fatal(err)
	}
	if err = enqueueSharedDeviceProfileJobs(ctx, tx, []AccountSession{session}, at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT dirty_generation FROM shared_device_profile_jobs`).Scan(&generation); err != nil || generation != 2 {
		t.Fatalf("concurrent claimed generation lost a change: %d %v", generation, err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO identity_derived_fresh_starts(cancel_id,sensor_id,accepted_after,reason) VALUES('temporary','temporary',now()-interval '1 hour','temporary validation'); INSERT INTO identity_derived_ready(batch_id,first_ordinal,sensor_id,accepted_at,priority,available_at) VALUES('historical',0,'temporary',now()-interval '2 hours',0,'-infinity'),('leased',0,'temporary',now()-interval '45 seconds',0,now()+interval '1 minute')`); err != nil {
		t.Fatal(err)
	}
	var pendingAge float64
	if err = tx.QueryRowContext(ctx, authenticationPendingAgeSQL).Scan(&pendingAge); err != nil || pendingAge < 45 || pendingAge > 80 {
		t.Fatalf("pressure lost the leased fragment or included retired history: %f %v", pendingAge, err)
	}
	if path := os.Getenv("PROXY_SENTINEL_AUTH_CANDIDATE_MIGRATION"); path != "" {
		validateAuthenticationTriggers(t, ctx, tx, path)
	}
}

func validateAuthenticationTriggers(t *testing.T, ctx context.Context, tx *sql.Tx, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	migration := string(data)
	start, end := strings.Index(migration, "CREATE FUNCTION maintain_account_session_confirmation"), strings.Index(migration, "CREATE INDEX account_sessions_current_confirmation")
	if start < 0 || end <= start {
		t.Fatal("candidate confirmation trigger is missing")
	}
	confirmation := strings.ReplaceAll(migration[start:end], "maintain_account_session_confirmation", "pg_temp.maintain_account_session_confirmation")
	confirmation = strings.ReplaceAll(confirmation, "ON account_sessions", "ON pg_temp.account_sessions")
	if _, err = tx.ExecContext(ctx, confirmation); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE pg_temp.account_sessions SET policy_metadata=jsonb_set(policy_metadata,'{last_confirmed_at}',to_jsonb(now()-interval '10 seconds')) WHERE session_id='auth-heartbeat'`); err != nil {
		t.Fatal(err)
	}
	var maintained bool
	if err = tx.QueryRowContext(ctx, `SELECT last_confirmed_at=now()-interval '10 seconds' FROM pg_temp.account_sessions WHERE session_id='auth-heartbeat'`).Scan(&maintained); err != nil || !maintained {
		t.Fatalf("legacy metadata writer lost typed confirmation: %v", err)
	}
	if _, err = tx.ExecContext(ctx, `CREATE TEMP TABLE authentication_test_wakes(n int) ON COMMIT DROP; CREATE FUNCTION pg_temp.authentication_test_wake() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO pg_temp.authentication_test_wakes VALUES(1); RETURN NEW; END $$; CREATE TRIGGER endpoint_recognition_entity_dirty AFTER UPDATE ON pg_temp.endpoint_entities FOR EACH ROW EXECUTE FUNCTION pg_temp.authentication_test_wake()`); err != nil {
		t.Fatal(err)
	}
	start = strings.Index(migration, "DROP TRIGGER endpoint_recognition_entity_dirty")
	if start < 0 {
		t.Fatal("candidate device recognition trigger is missing")
	}
	recognition := strings.ReplaceAll(migration[start:], "ON endpoint_entities", "ON pg_temp.endpoint_entities")
	recognition = strings.ReplaceAll(recognition, "EXECUTE FUNCTION enqueue_endpoint_recognition_job()", "EXECUTE FUNCTION pg_temp.authentication_test_wake()")
	if _, err = tx.ExecContext(ctx, recognition); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO pg_temp.endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen,identity_confidence,attributes) VALUES('auth-endpoint','02:00:00:00:00:03','endpoint',now(),now(),0.95,'{"os":"Android","session_status":"login"}'); UPDATE pg_temp.endpoint_entities SET attributes=jsonb_set(attributes,'{session_status}','"logout"') WHERE endpoint_id='auth-endpoint'`); err != nil {
		t.Fatal(err)
	}
	var wakes int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_temp.authentication_test_wakes`).Scan(&wakes); err != nil || wakes != 0 {
		t.Fatalf("authentication status incorrectly rebuilt device recognition: %d %v", wakes, err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE pg_temp.endpoint_entities SET attributes=jsonb_set(attributes,'{os}','"Linux"') WHERE endpoint_id='auth-endpoint'; UPDATE pg_temp.endpoint_entities SET last_seen=last_seen+interval '1 hour' WHERE endpoint_id='auth-endpoint'`); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_temp.authentication_test_wakes`).Scan(&wakes); err != nil || wakes != 2 {
		t.Fatalf("device evidence or liveness change lost its wake: %d %v", wakes, err)
	}
}
