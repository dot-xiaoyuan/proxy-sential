package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestPostgresPolicyIdentityReplayMatchesFileFold(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	pg, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	base := time.Now().UTC().Truncate(time.Second).Add(-5 * time.Minute)
	prefix := "policy-replay-" + base.Format("150405")
	events := []normalized.Event{}
	for i, status := range []string{"start", "stop", "start", "interim-update"} {
		e := universityIdentityEvent(fmt.Sprintf("%s-%d", prefix, i), prefix, status, base.Add(time.Duration(i)*time.Minute).Format(time.RFC3339Nano))
		e.Payload["heartbeat_interval_seconds"] = "60"
		e.Payload["access_domain"] = "replay-wifi"
		events = append(events, e)
	}
	defer pg.db.ExecContext(context.Background(), `DELETE FROM policy_identity_observations WHERE session_id=$1`, prefix)
	// Duplicate and delayed ingestion must fold identically to the file replay path.
	tx, err := pg.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = writePolicyIdentityEvents(ctx, tx, []normalized.Event{events[2], events[0], events[3], events[1], events[2]}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []time.Duration{30 * time.Second, 90 * time.Second, 210 * time.Second} {
		at := base.Add(offset)
		input := []normalized.Event{}
		for _, e := range events {
			observed, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
			if !observed.After(at) {
				input = append(input, e)
			}
		}
		want := foldPolicySessions(policyRows(input))
		all, err := pg.ListPolicySessions(ctx, at)
		if err != nil {
			t.Fatal(err)
		}
		got := all[:0]
		for _, s := range all {
			if s.ID == prefix {
				got = append(got, s)
			}
		}
		a, _ := json.Marshal(want)
		b, _ := json.Marshal(got)
		if string(a) != string(b) {
			t.Fatalf("at %s\nfile %s\ndb %s", offset, a, b)
		}
	}
}
