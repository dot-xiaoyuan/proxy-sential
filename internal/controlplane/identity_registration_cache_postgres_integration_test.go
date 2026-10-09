package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
)

// The native fixture uses temporary metadata and a sequence to count actual
// authority reads, rather than timing or relying on a mocked database call.
func TestPolicyIdentityRegistrationNativeReadCount(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var name string
	if err = db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^sentinel_(ieee_lease|acceptance)_[0-9]+$`).MatchString(name) {
		t.Fatal("dedicated acceptance database required")
	}
	for _, stmt := range []string{
		`CREATE TEMP TABLE enforcement_connectors(connector_id text,connector_type text,endpoint_url text,certificate_pem text)`,
		`CREATE TEMP TABLE enforcement_identity_sources(connector_id text,config_version bigint,public_config jsonb,encrypted_token bytea,state text,blocker text,observed_at timestamptz,last_success_at timestamptz,last_attempt_at timestamptz,record_count integer)`,
		`CREATE TEMP SEQUENCE registration_reads`,
		`CREATE TEMP TABLE registrations(source text,sensor_id text,hours integer)`,
		`INSERT INTO registrations VALUES('srun4k:one','one',6)`,
		`CREATE TEMP VIEW srun4k_integrations AS SELECT source,sensor_id,(hours+nextval('pg_temp.registration_reads')*0)::integer reconcile_interval_hours FROM registrations`,
	} {
		if _, err = db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	sessions := []policy.Session{}
	for i := 0; i < 128; i++ {
		sessions = append(sessions, policy.Session{ID: fmt.Sprint(i), Source: "srun4k:one", SensorID: "one", AccountID: "a", IP: "192.0.2.1", StartedAt: now.Add(-5 * time.Hour), ConfirmedAt: now.Add(-4 * time.Hour), HeartbeatSeconds: 604800})
	}
	reader := policySandboxReader{sessions: sessions}
	s := &Server{operations: &operationsState{db: db}}
	for i := 0; i < 2; i++ {
		started := time.Now()
		got, err := s.policySessions(ctx, reader, now)
		if err != nil || len(got) != 128 {
			t.Fatalf("rows=%d err=%v", len(got), err)
		}
		want := "active"
		if i == 1 {
			want = "unknown"
		}
		for _, row := range got {
			if row.State(now) != want {
				t.Fatalf("freshness state=%s want=%s", row.State(now), want)
			}
		}
		var reads int64
		if err = db.QueryRowContext(ctx, `SELECT last_value FROM pg_temp.registration_reads`).Scan(&reads); err != nil {
			t.Fatal(err)
		}
		t.Logf("read=%d sessions=%d actual_registration_queries=%d duration=%s", i+1, len(got), reads, time.Since(started))
		if reads != int64(i+1) {
			t.Fatalf("per-session SQL repeated: queries=%d want=%d", reads, i+1)
		}
		if i == 0 {
			if _, err = db.ExecContext(ctx, `UPDATE registrations SET hours=1`); err != nil {
				t.Fatal(err)
			}
		}
	}
	if reader.sessions[0].HeartbeatSeconds != 604800 {
		t.Fatal("reader source modified")
	}
	observed := []store.IdentitySourceStatus{{IdentityScope: store.IdentityScope{Source: "srun4k:one", SensorID: "one"}, ObservedAt: now.Add(-3 * time.Hour), IntervalSeconds: 604800, SnapshotID: "preserved", SessionCount: 128}}
	for _, tc := range []struct {
		hours int
		state string
	}{{6, "healthy"}, {1, "interrupted"}} {
		if _, err = db.ExecContext(ctx, `UPDATE registrations SET hours=$1`, tc.hours); err != nil {
			t.Fatal(err)
		}
		statuses, err := s.mergeManagedIdentitySources(ctx, observed, now)
		if err != nil || len(statuses) != 1 || statuses[0].State != tc.state || statuses[0].IntervalSeconds != tc.hours*3600 {
			t.Fatalf("status=%+v error=%v", statuses, err)
		}
		if statuses[0].SnapshotID != "preserved" || statuses[0].SessionCount != 128 || observed[0].IntervalSeconds != 604800 {
			t.Fatal("status reconciliation changed snapshot data")
		}
		t.Logf("native identity status hours=%d state=%s", tc.hours, statuses[0].State)
	}
}
