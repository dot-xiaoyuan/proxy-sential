package srunapi

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"proxy-sentinel/internal/legacy4k"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestJournalPostgresSingleDispatchAcrossRestart(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*cfg)
	defer admin.Close()
	schema := fmt.Sprintf("srun_journal_%d", time.Now().UnixNano())
	if _, err = admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec("DROP SCHEMA " + schema + " CASCADE")
	cfg.RuntimeParams["search_path"] = schema + ",public"
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	migration, err := os.ReadFile("../../migrations/postgres/026_native_action_dispatch.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = db.Exec(string(migration)); err != nil {
			t.Fatal(err)
		}
	}
	observationMigration, err := os.ReadFile("../../migrations/postgres/027_native_action_observations.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = db.Exec(string(observationMigration)); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	cancelMigration, err := os.ReadFile("../../migrations/postgres/028_native_action_cancellation.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = db.Exec(string(cancelMigration)); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	target, err := BindDisconnect(inventory(now), "test-user", legacy4k.OnlineSessionID("redis-boot", "session-9", "100"), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	intent := DispatchIntent{Key: "action-1/session-9", ConnectorID: "test-controller", Target: target, DropType: "radius"}
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := (Journal{DB: db}).Reserve(ctx, intent)
			if e != nil {
				t.Error(e)
				return
			}
			if r.SendAllowed {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("dispatch claims %d", won.Load())
	}
	// Reopen a new database handle: a reservation survives a crash even if no
	// receipt or post-send update was recorded. Uncertain sends are never replayed.
	restarted := stdlib.OpenDB(*cfg)
	defer restarted.Close()
	r, err := (Journal{DB: restarted}).Reserve(ctx, intent)
	if err != nil || r.SendAllowed || r.ReservedAt.IsZero() {
		t.Fatalf("restart lost intent: %+v %v", r, err)
	}
	intent.Target.RawOnlineID = "new-target"
	if _, err = (Journal{DB: restarted}).Reserve(ctx, intent); err == nil {
		t.Fatal("idempotency key accepted different target")
	}
	intent.Target = target
	intent.DropType = "portal"
	if _, err = (Journal{DB: restarted}).Reserve(ctx, intent); err == nil {
		t.Fatal("idempotency key accepted different action parameters")
	}
	// Full local transport chain: real PostgreSQL journal, native API client,
	// HTTP controller sandbox and authoritative inventory double.
	var drops atomic.Int32
	sandbox := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/auth/get-access-token":
			io.WriteString(w, `{"code":0,"data":{"access_token":"lab-token","lifetime":60}}`)
		case "/api/v2/base/online-drop":
			drops.Add(1)
			io.WriteString(w, `{"code":0}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer sandbox.Close()
	client, err := New(sandbox.URL, "lab-app", "lab-secret", sandbox.Client())
	if err != nil {
		t.Fatal(err)
	}
	intent.Key = "sandbox/native/one"
	intent.DropType = "radius"
	// The fixture and reservation must share a clock. Host/VM clock skew is
	// separately fail-closed in ownership tests, not hidden with a tolerance.
	labNow := func() time.Time {
		var at time.Time
		if err := db.QueryRow(`SELECT clock_timestamp()`).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	ex := Executor{Journal: Journal{DB: db}, Native: client, Now: labNow, MaxAge: time.Minute,
		Authorize: func(context.Context, DispatchIntent) error { return nil },
		Read: func(context.Context) (legacy4k.OnlineInventory, error) {
			v := inventory(labNow())
			if drops.Load() > 0 {
				v.Rows = nil
			}
			return v, nil
		}}
	step, err := ex.Step(ctx, intent)
	if err != nil || step.Delivery != "acknowledged" || step.Observation != "absent" {
		t.Fatalf("sandbox execution: %+v %v", step, err)
	}
	ex.Journal = Journal{DB: restarted}
	step, err = ex.Step(ctx, intent)
	if err != nil || step.Observation != "absent" || drops.Load() != 1 {
		t.Fatalf("sandbox restart resent: %+v %v drops=%d", step, err, drops.Load())
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM native_action_observations WHERE idempotency_key=$1`, intent.Key).Scan(&count); err != nil || count != 2 {
		t.Fatalf("missing durable outcomes: count=%d err=%v", count, err)
	}
	wrong := intent
	wrong.Target.Account = "different"
	if err = (Journal{DB: db}).Record(ctx, wrong, step, false); err == nil {
		t.Fatal("observation accepted for a different confirmed account")
	}
	page, err := (Journal{DB: db}).Observations(ctx, intent.Key, intent.ConnectorID, intent.Target.Account, intent.Target.SessionID, 0, 1)
	if err != nil || len(page.Items) != 1 || page.NextBefore == "" {
		t.Fatalf("first page %+v %v", page, err)
	}
	before, err := strconv.ParseInt(page.NextBefore, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	second, err := (Journal{DB: db}).Observations(ctx, intent.Key, intent.ConnectorID, intent.Target.Account, intent.Target.SessionID, before, 1)
	if err != nil || len(second.Items) != 1 || second.NextBefore != "" || second.Items[0].ID == page.Items[0].ID {
		t.Fatalf("unstable page %+v %v", second, err)
	}
	other, err := (Journal{DB: db}).Observations(ctx, intent.Key, intent.ConnectorID, "other-account", intent.Target.SessionID, 0, 10)
	if err != nil || len(other.Items) != 0 {
		t.Fatalf("cross-account results %+v %v", other, err)
	}
	cancelled := intent
	cancelled.Key = "cancel-before-reserve"
	for i := 0; i < 2; i++ {
		if err = (Journal{DB: db}).Cancel(ctx, cancelled); err != nil {
			t.Fatal(err)
		}
	}
	claim, err := (Journal{DB: restarted}).Reserve(ctx, cancelled)
	if err != nil || claim.SendAllowed {
		t.Fatalf("cancelled reservation dispatched: %+v %v", claim, err)
	}
	stopped, err := (Journal{DB: restarted}).Cancelled(ctx, cancelled)
	if err != nil || !stopped {
		t.Fatalf("cancellation lost: %v %v", stopped, err)
	}
	wrongCancel := cancelled
	wrongCancel.Target.Account = "other"
	if err = (Journal{DB: db}).Cancel(ctx, wrongCancel); err == nil {
		t.Fatal("cross-account cancellation accepted")
	}
	if _, _, err = (Journal{DB: db}).Lookup(ctx, wrongCancel); err == nil {
		t.Fatal("cross-account lookup accepted")
	}
	ex.Authorize = func(context.Context, DispatchIntent) error { return errors.New("withdrawn") }
	step, err = ex.Step(ctx, intent)
	if err != nil || step.Observation != "absent" || drops.Load() != 1 {
		t.Fatalf("real journal failed revoked reconciliation: %+v %v", step, err)
	}
}
