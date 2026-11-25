package controlplane

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
)

func TestPostgresSharedCaseLifecycle(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN is not set")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires an owned isolated PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err = store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, r, assessment := caseSyncFixture()
	state, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer state.db.Close()
	s.operations = state
	if err = s.syncCasesContext(ctx, "test", "10m"); err != nil {
		t.Fatal(err)
	}
	caseID := proxyReviewCaseForSharedAssessment(assessment).CaseID
	if got := state.doc.Cases[caseID]; got.RiskKind != "shared_access" || got.EvidenceSnapshot.SharedAccess == nil {
		t.Fatalf("confirmed shared case was not persisted: %+v", got)
	}
	r.shared = nil
	if err = s.syncCasesContext(ctx, "test", "10m"); err != nil {
		t.Fatal(err)
	}
	second, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.db.Close()
	if got := second.doc.Cases[caseID]; got.Status != "closed" {
		t.Fatalf("negative current generation did not close durable case: %+v", got)
	}
}

func TestOperationsTransactionOutlivesSetupBudget(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN is not set")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/(sentinel_(ieee_lease|acceptance)_[0-9]+|ps_discovery[0-9]+_test_[0-9]+)$`).MatchString(u.Path) {
		t.Fatal("requires an owned isolated PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err = store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	state, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer state.db.Close()
	state.beginLockedWithTimeout(50 * time.Millisecond)
	if state.lockErr != nil {
		t.Fatal(state.lockErr)
	}
	time.Sleep(70 * time.Millisecond)
	var one int
	if err = state.tx.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatalf("setup timer canceled an active transaction: %v", err)
	}
	state.endLocked()
}

func TestAutomaticCaseSyncKeepsActionStateOutOfItsTransaction(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN is not set")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires an owned isolated PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err = store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, _, assessment := caseSyncFixture()
	state, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer state.db.Close()
	s.operations = state
	state.doc.Actions["unrelated-action"] = EnforcementAction{ActionID: "unrelated-action"}
	if err = s.syncAutomaticCasesContext(ctx, "test", "10m"); err != nil {
		t.Fatal(err)
	}
	if _, ok := state.doc.Actions["unrelated-action"]; !ok {
		t.Fatal("automatic case synchronization replaced the shared action state")
	}
	caseID := proxyReviewCaseForSharedAssessment(assessment).CaseID
	var stored bool
	if err = state.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM risk_cases WHERE case_id=$1)`, caseID).Scan(&stored); err != nil || !stored {
		t.Fatalf("automatic case was not persisted: %v", err)
	}
}

func TestPostgresSessionCaseAcrossEvidenceExpiry(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN is not set")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_acceptance_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("requires an owned isolated PostgreSQL database")
	}
	ctx := context.Background()
	if _, err = store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	prior := legacyTransportTestBypass.Swap(false)
	t.Cleanup(func() { legacyTransportTestBypass.Store(prior) })
	s, _, base := caseSyncFixture()
	backend, err := store.NewDBStore(store.Options{PostgresDSN: dsn, ClickHouseDSN: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	s.reader = backend
	state, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer state.db.Close()
	s.operations = state
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-5 * time.Minute)
	stamp := time.Now().UnixNano()
	uid := fmt.Sprintf("session-case-%d", stamp)
	base.SensorID = uid
	mapping := sharedaccess.IdentityMapping{SensorID: base.SensorID, CampusID: base.CampusID, AccessDomain: base.AccessDomain, Source: "source-" + uid, IdentitySensorID: "identity", IdentityCampusID: "auth", IdentityAccessDomain: "domain", ValidFrom: at.Add(-time.Hour), ValidUntil: at.Add(time.Hour)}
	cfg := sharedaccess.Config{Version: "test", FreshnessSeconds: 180, IdentityMappings: []sharedaccess.IdentityMapping{mapping}, Sources: []sharedaccess.Source{{SensorID: base.SensorID, CampusID: base.CampusID, AccessDomain: base.AccessDomain, Source: "handshake-sidecar"}}}
	s.sharedConfig = cfg
	record := func(n int, account, ip, generation string, when time.Time, sync bool) string {
		t.Helper()
		id := fmt.Sprintf("%s-%d", uid, n)
		a := base
		a.AccountID, a.ObservationID, a.SessionGeneration, a.IP = account, id, generation, ip
		const mac = "02:00:00:00:00:01"
		a.LastSeen, a.FirstSeen, a.WindowStart, a.WindowEnd = when, when, when, when
		w := sharedaccess.Window{ID: id, RuleVersion: sharedaccess.RuleVersion, SensorID: base.SensorID, CampusID: base.CampusID, AccessDomain: base.AccessDomain, IP: ip, From: when.Add(-time.Second), To: when, LastObservedAt: when,
			Activity: &sharedaccess.OutletActivity{MAC: mac, At: when, EventID: id}, EventIDs: []string{id}, Sources: []string{"handshake-sidecar"}, Records: []sharedaccess.RecordRef{{Source: "handshake-sidecar", EventID: id, InstanceID: "test"}},
			RouterProof: &sharedaccess.RouterProof{AssessmentID: "router", RoleEvidenceID: "igd", RuleID: "ssdp-advertised-internet-gateway", Account: account, Session: generation, MAC: mac}}
		sessions := []policy.Session{{ID: generation, Source: mapping.Source, SensorID: mapping.IdentitySensorID, CampusID: mapping.IdentityCampusID, AccessDomain: mapping.IdentityAccessDomain, IP: ip, MAC: mac, AccountID: account, StartedAt: at.Add(-time.Hour), ConfirmedAt: when, HeartbeatSeconds: 1800}}
		result := sharedaccess.EvaluateObservation(w, cfg, sessions, when)
		d := sharedaccess.NewObservationDecision(w, result, cfg, when)
		if d.Result != "matched" {
			t.Fatalf("fresh hit failed: %+v", d)
		}
		if late := sharedaccess.NewObservationDecision(w, result, cfg, when.Add(180*time.Second)); late.Result != "expired" {
			t.Fatalf("stale decision: %s", late.Result)
		}
		d.IdentityEvidence = sessions
		a.DecisionID, a.SessionGeneration, a.ConfirmationBasis = d.DecisionID, d.SessionGeneration, sharedaccess.AuthenticatedRouter
		a.Router.RoleEvidenceID = "igd"

		tx, e := state.db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback()
		if e = persistSharedObservationDecision(ctx, tx, &d); e != nil {
			t.Fatal(e)
		}
		a.SignalGroups = []string{"router_identity"}
		a.ExpiresAt = when.Add(180 * time.Second)
		if _, e = store.PersistSharedObservationTx(ctx, tx, a); e != nil {
			t.Fatal(e)
		}
		if e = recordSharedFinding(ctx, tx, a, d); e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
		if e = state.db.QueryRow("SELECT case_id FROM shared_access_findings WHERE observation_id=$1", id).Scan(&a.CaseID); e != nil {
			t.Fatal(e)
		}
		if sync {
			e = s.syncAutomaticCasesContext(ctx, "test", "10m")
		}
		if e != nil {
			t.Fatal(e)
		}
		return a.CaseID
	}
	_, err = state.db.Exec(`INSERT INTO account_identity_session_projection(source,sensor_id,campus_id,access_domain,session_id,ip,account_id,confirmed_at,document) VALUES($1,'identity','auth','domain','login1',$2,$3,$4,'{}')`, mapping.Source, base.IP, uid, at.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	first := record(1, uid, base.IP, "login1", at, true)
	// First evidence is now over 180s old and no second hit is pending.
	if err = s.syncAutomaticCasesContext(ctx, "test", "10m"); err != nil {
		t.Fatal(err)
	}
	isCurrent := func(id string) bool {
		t.Helper()
		var raw []byte
		if e := state.db.QueryRow("SELECT "+caseAssessmentProjection+" FROM risk_cases c WHERE c.case_id=$1", id).Scan(&raw); e != nil {
			t.Fatal(e)
		}
		c, e := decodeCaseAssessment(raw)
		if e != nil {
			t.Fatal(e)
		}
		return c.AssessmentCurrent
	}
	if isCurrent(first) {
		t.Fatal("open case presented expired evidence as current")
	}
	// Exercise session-key lookup even after the hot episode has been retired.
	if _, err = state.db.Exec("DELETE FROM shared_observation_executions WHERE account_id=$1", uid); err != nil {
		t.Fatal(err)
	}
	second := record(2, uid, base.IP, "login1", at.Add(200*time.Second), false)
	// Fail after linking the second episode's action and before committing
	// its snapshot. A retry must still own both pending operations.
	failureName := fmt.Sprintf("fail_session_case_snapshot_%d", stamp)
	// The generated identifier and fixture ID contain only fixed text and
	// the numeric run timestamp. Scope the failure to this observation.
	_, err = state.db.Exec(fmt.Sprintf(`CREATE FUNCTION %[1]s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'snapshot write failed'; END $$;
 CREATE TRIGGER %[1]s BEFORE INSERT ON risk_case_evidence_snapshots FOR EACH ROW WHEN (NEW.evidence->'shared_access'->>'observation_id'='%[2]s') EXECUTE FUNCTION %[1]s()`, failureName, uid+"-2"))
	if err != nil {
		t.Fatal(err)
	}
	cleanupFailure := func() {
		_, _ = state.db.Exec(fmt.Sprintf("DROP TRIGGER IF EXISTS %[1]s ON risk_case_evidence_snapshots; DROP FUNCTION IF EXISTS %[1]s()", failureName))
	}
	defer cleanupFailure()
	if e := s.syncAutomaticCasesContext(ctx, "test", "10m"); e == nil {
		t.Fatal("injected snapshot failure was ignored")
	}
	var retryable bool
	if e := state.db.QueryRow(`SELECT f.case_pending AND a.case_id IS NULL FROM shared_access_findings f JOIN enforcement_actions a USING(action_id) WHERE f.observation_id=$1`, uid+"-2").Scan(&retryable); e != nil || !retryable {
		t.Fatalf("partial commit: retryable=%t err=%v", retryable, e)
	}
	cleanupFailure()
	if e := s.syncAutomaticCasesContext(ctx, "test", "10m"); e != nil {
		t.Fatal(e)
	}
	if !isCurrent(first) {
		t.Fatal("case did not expose the second fresh hit")
	}
	var open, hits, snaps, actions int
	err = state.db.QueryRow(`SELECT (SELECT count(*) FROM risk_cases WHERE account_id=$1 AND status NOT IN ('closed','resolved')),
 (SELECT count(*) FROM policy_decision_records WHERE account_id=$1 AND result='matched'),
 (SELECT count(*) FROM risk_case_evidence_snapshots WHERE case_id=$2),
 (SELECT count(*) FROM enforcement_actions WHERE account_id=$1 AND case_id=$2 AND mode='record_only')`, uid, first).Scan(&open, &hits, &snaps, &actions)
	if err != nil || first != second || open != 1 || hits != 2 || snaps != 2 || actions != 2 {
		t.Fatalf("200s gap: first=%s second=%s open=%d matched=%d snapshots=%d linked actions=%d err=%v", first, second, open, hits, snaps, actions, err)
	}
	// A committed hit can be waiting for evidence sync as the operator closes
	// its assigned case. The pending snapshot must survive without reopening it.
	third := record(3, uid, base.IP, "login1", at.Add(202*time.Second), false)
	if third != first {
		t.Fatal("pending hit lost its assigned case")
	}
	if _, err = state.db.Exec("UPDATE risk_cases SET status='closed' WHERE case_id=$1", first); err != nil {
		t.Fatal(err)
	}
	if err = s.syncAutomaticCasesContext(ctx, "test", "10m"); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err = state.db.QueryRow("SELECT count(*) FROM shared_access_findings WHERE case_id=$1 AND case_pending", first).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("pending=%d err=%v", pending, err)
	}
	seen := map[string]bool{first: true}
	for i, scope := range []struct{ account, ip, generation string }{
		{uid, base.IP, "login1"}, {uid, base.IP, "login2"}, {uid, "192.0.2.22", "login1"}, {uid + "-other", base.IP, "login1"},
	} {
		id := record(i+4, scope.account, scope.ip, scope.generation, at.Add(time.Duration(204+i)*time.Second), true)
		if seen[id] {
			t.Fatalf("boundaries reused case %s for %+v", id, scope)
		}
		seen[id] = true
	}
	if again := record(1, uid, base.IP, "login1", at, true); again != first {
		t.Fatalf("replay moved a closed case to %s", again)
	}
	var status string
	if err = state.db.QueryRow("SELECT status,(SELECT count(*) FROM risk_case_evidence_snapshots WHERE case_id=$1) FROM risk_cases WHERE case_id=$1", first).Scan(&status, &snaps); err != nil || status != "closed" || snaps != 3 {
		t.Fatalf("closed case status=%q snapshots=%d: %v", status, snaps, err)
	}
}
