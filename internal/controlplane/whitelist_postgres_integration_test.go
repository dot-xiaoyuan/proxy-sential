package controlplane

import (
	"context"
	"errors"
	"net/url"
	"os"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
	"regexp"
	"testing"
	"time"
)

func TestWhitelistPostgresPersistenceAndAuditReplay(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !regexp.MustCompile(`^/sentinel_acceptance_[0-9]+$`).MatchString(u.Path) {
		t.Fatal("owned isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err = store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	o, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer o.db.Close()
	m := newWhitelistManager(o.db, "")
	e, err := m.save(ctx, whitelistFixture(), "", "create", "admin")
	if err != nil {
		t.Fatal(err)
	}
	other := newWhitelistManager(o.db, "")
	items, err := other.list(ctx)
	if err != nil || len(items) != 1 || items[0].ID != e.ID {
		t.Fatal("cross-instance configuration lost", items, err)
	}
	e.Reason = "更新教学账号"
	e, err = other.save(ctx, e, e.ID, "update", "operator")
	if err != nil || e.Revision != 2 {
		t.Fatal("update failed", e, err)
	}
	if _, err = m.save(ctx, policy.WhitelistEntry{Revision: 1}, e.ID, "disable", "stale"); !errors.Is(err, errWhitelistConflict) {
		t.Fatal("stale write accepted", err)
	}
	var audits int
	if err = o.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE action LIKE 'policy.whitelist.%'`).Scan(&audits); err != nil || audits != 2 {
		t.Fatal("audit missing", audits, err)
	}
	// A failed audit must roll back the configuration change as well.
	if _, err = o.db.ExecContext(ctx, `CREATE FUNCTION whitelist_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action LIKE 'policy.whitelist.%' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER whitelist_reject_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION whitelist_reject_audit()`); err != nil {
		t.Fatal(err)
	}
	defer o.db.Exec(`DROP TRIGGER IF EXISTS whitelist_reject_audit ON audit_logs; DROP FUNCTION IF EXISTS whitelist_reject_audit()`)
	if _, err = m.save(ctx, policy.WhitelistEntry{Revision: e.Revision}, e.ID, "disable", "admin"); err == nil {
		t.Fatal("audit failure accepted")
	}
	items, err = other.list(ctx)
	if err != nil || !items[0].Enabled || items[0].Revision != 2 {
		t.Fatal("audit rollback lost whitelist", items, err)
	}
	if err = (&Server{whitelist: other}).validatePolicyDeliveryContext(ctx, EnforcementAction{AccountID: "student", ActionType: "notify"}); err == nil {
		t.Fatal("queued notification bypassed durable whitelist")
	}
}
