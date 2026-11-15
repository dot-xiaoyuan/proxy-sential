package discovery

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"os"
	"testing"
	"time"
)

func TestHardwareBatchPostgresSingleCommitAndAtomicFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			db := hardwareIntegrationDB(t)
			ctx := context.Background()
			at := time.Now().UTC().Add(-time.Minute)
			obs := []Observation{}
			for i := 0; i < 4; i++ {
				o := hardwareTestObservation(at)
				o.Origin = "arp"
				o.MAC = fmt.Sprintf("00:11:22:33:44:%02x", i)
				o.ID = fmt.Sprint(i)
				o.EventID = o.ID
				obs = append(obs, o)
			}
			if err := EnqueueHardwareObservations(ctx, db, obs); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`CREATE TABLE transaction_probe(id bigint);
 CREATE FUNCTION capture_transaction() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO transaction_probe VALUES(txid_current()); RETURN NEW; END $$;
 CREATE TRIGGER capture_transaction AFTER INSERT ON passive_hardware_current FOR EACH ROW EXECUTE FUNCTION capture_transaction()`); err != nil {
				t.Fatal(err)
			}
			if fail {
				if _, err := db.Exec(`CREATE FUNCTION fail_second() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.mac='00:11:22:33:44:01' THEN RAISE EXCEPTION 'second identity failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER fail_second BEFORE INSERT ON passive_hardware_current FOR EACH ROW EXECUTE FUNCTION fail_second()`); err != nil {
					t.Fatal(err)
				}
			}
			n, err := ProcessHardwareProjectionBatchedWithin(ctx, db, "sensor", 4, 0)
			var rows, txs, dirty, attempted int
			db.QueryRow(`SELECT count(*),count(DISTINCT id) FROM transaction_probe`).Scan(&rows, &txs)
			db.QueryRow(`SELECT count(*),count(*) FILTER(WHERE attempts>0) FROM passive_hardware_dirty`).Scan(&dirty, &attempted)
			if fail {
				if err == nil || n != 0 || rows != 0 || dirty != 4 || attempted != 1 {
					t.Fatalf("failed batch partially committed: n=%d rows=%d dirty=%d attempted=%d err=%v", n, rows, dirty, attempted, err)
				}
				db.Exec(`DROP TRIGGER fail_second ON passive_hardware_current; UPDATE passive_hardware_dirty SET next_attempt_at=now()`)
				n, err = ProcessHardwareProjectionBatchedWithin(ctx, db, "sensor", 4, 0)
				if err != nil || n != 4 {
					t.Fatalf("resume failed: %d %v", n, err)
				}
			} else if err != nil || n != 4 || rows != 4 || txs != 1 || dirty != 0 {
				t.Fatalf("not one bounded commit: n=%d rows=%d transactions=%d dirty=%d err=%v", n, rows, txs, dirty, err)
			}
		})
	}
}

func TestHardwareBatchPostgresConcurrentObservationRemainsQueued(t *testing.T) {
	db := hardwareIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var schema string
	var workerPID int
	if err := db.QueryRow(`SELECT current_schema(),pg_backend_pid()`).Scan(&schema, &workerPID); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = schema
	peer := stdlib.OpenDB(*cfg)
	peer.SetMaxOpenConns(3)
	defer peer.Close()
	blocker, err := peer.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	if _, err = blocker.ExecContext(ctx, `SELECT pg_advisory_lock(hashtext(current_schema()),17)`); err != nil {
		t.Fatal(err)
	}
	defer blocker.ExecContext(context.Background(), `SELECT pg_advisory_unlock(hashtext(current_schema()),17)`)
	if _, err = db.Exec(`CREATE FUNCTION wait_for_writer() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(hashtext(current_schema()),17); RETURN NEW; END $$; CREATE TRIGGER wait_for_writer BEFORE INSERT ON passive_hardware_current FOR EACH ROW EXECUTE FUNCTION wait_for_writer()`); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	o := hardwareTestObservation(at)
	o.Origin = "arp"
	group := []Observation{o}
	for i := 0; i < 3; i++ {
		extra := o
		extra.MAC = fmt.Sprintf("00:11:22:33:44:%02x", 0x56+i)
		extra.ID = fmt.Sprint("extra-", i)
		extra.EventID = extra.ID
		group = append(group, extra)
	}
	if err = EnqueueHardwareObservations(ctx, db, group); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, e := ProcessHardwareProjectionBatchedWithin(ctx, db, "sensor", 4, 0); done <- e }()
	waitBlocked := func(pid int) {
		t.Helper()
		for ctx.Err() == nil {
			var waiting bool
			e := peer.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted)`, pid).Scan(&waiting)
			if e != nil {
				t.Fatal(e)
			}
			if waiting {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("database participant did not reach controlled lock")
	}
	waitBlocked(workerPID)
	writer, err := peer.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	var writerPID int
	if err = writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&writerPID); err != nil {
		t.Fatal(err)
	}
	next := o
	next.ObservedAt = at.Add(10 * time.Second)
	next.EventID = "newer-concurrent"
	wrote := make(chan error, 1)
	go func() { wrote <- EnqueueHardwareObservations(ctx, writer, []Observation{next}) }()
	waitBlocked(writerPID)
	if _, err = blocker.ExecContext(ctx, `SELECT pg_advisory_unlock(hashtext(current_schema()),17)`); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = <-wrote; err != nil {
		t.Fatal(err)
	}
	var n int
	if err = db.QueryRow(`SELECT count(*) FROM passive_hardware_dirty`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("concurrent observation lost: %d %v", n, err)
	}
	if _, err = ProcessHardwareProjectionBatchedWithin(ctx, db, "sensor", 4, 0); err != nil {
		t.Fatal(err)
	}
	var last time.Time
	if err = db.QueryRow(`SELECT last_seen FROM passive_hardware_current WHERE mac=$1`, o.MAC).Scan(&last); err != nil || !last.Equal(next.ObservedAt) {
		t.Fatalf("newer fact not projected: %v %v", last, err)
	}
}
