package proxyprotocol

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/policy"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestProxyRepositoryPostgresNormalizesLegacyPartialResults(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("test database configuration failed")
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var database string
	if err := db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&database); err != nil {
		t.Fatal("test database connection failed")
	}
	if !strings.HasPrefix(database, "sentinel_acceptance_") && !strings.HasPrefix(database, "sentinel_ieee_lease_") {
		t.Fatal("this replay requires an owned isolated sentinel test database")
	}
	ddl, err := os.ReadFile("../../migrations/postgres/019_proxy_protocol.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(ddl)); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"read-existing", "commit-new", "merge-existing", "complete-correction"} {
		t.Run(mode, func(t *testing.T) {
			e, p := fixture()
			Sign(&e, p)
			complete := Evaluate(e, Config{Version: "same", Producers: []Producer{p}})
			legacy := complete
			legacy.RuleVersion = "proxy-transactions/v1"
			legacy.ResponseAt = time.Time{}
			legacy.EventIDs = []string{"legacy-event"}
			if _, err := db.ExecContext(ctx, `DELETE FROM proxy_protocol_results WHERE evidence_id=$1`, legacy.ID); err != nil {
				t.Fatal(err)
			}
			repo := OpenRepository(db, "")
			raw, err := json.Marshal(legacy)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "commit-new" {
				if err := repo.Commit(ctx, []Result{legacy}, ScanState{}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := db.ExecContext(ctx, `INSERT INTO proxy_protocol_results(evidence_id,ip,observed_at,document) VALUES($1,$2,$3,$4)`, legacy.ID, legacy.IP, legacy.ObservedAt, raw); err != nil {
					t.Fatal(err)
				}
				if mode == "merge-existing" {
					current := legacy
					current.Outcome = "incomplete"
					current.Confidence = 0
					current.EventIDs = []string{"current-event"}
					if err := repo.Commit(ctx, []Result{current}, ScanState{}); err != nil {
						t.Fatal(err)
					}
				} else if mode == "complete-correction" {
					if err := repo.Commit(ctx, []Result{complete}, ScanState{}); err != nil {
						t.Fatal(err)
					}
				}
			}
			rows, err := OpenRepository(db, "").Query(ctx, legacy.IP, time.Time{}, 10)
			if err != nil || len(rows) != 1 {
				t.Fatalf("read result rows=%d err=%v", len(rows), err)
			}
			want := "incomplete"
			if mode == "complete-correction" {
				want = "success"
			}
			if rows[0].Outcome != want || want == "incomplete" && rows[0].Confidence != 0 {
				t.Fatalf("legacy malformed success persisted: %+v", rows[0])
			}
			if mode == "read-existing" {
				var outcome string
				if err := db.QueryRowContext(ctx, `SELECT document->>'outcome' FROM proxy_protocol_results WHERE evidence_id=$1`, legacy.ID).Scan(&outcome); err != nil || outcome != "success" {
					t.Fatal("read mutated original audit document")
				}
			}
			if mode == "complete-correction" && len(rows[0].EventIDs) != 2 {
				t.Fatal("correction discarded original evidence IDs")
			}
		})
	}
}

func TestProxyRepositoryPostgresKeepsEncodingFailureUntrusted(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("test database configuration failed")
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var database string
	if err := db.QueryRowContext(ctx, `SELECT current_database()`).Scan(&database); err != nil {
		t.Fatal("test database connection failed")
	}
	if !strings.HasPrefix(database, "sentinel_acceptance_") && !strings.HasPrefix(database, "sentinel_ieee_lease_") {
		t.Fatal("this replay requires an owned isolated sentinel test database")
	}
	ddl, err := os.ReadFile("../../migrations/postgres/019_proxy_protocol.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(ddl)); err != nil {
		t.Fatal(err)
	}
	e, p := fixture()
	e.Flow["connection_id"] = "encoding-failure-connection"
	e.Payload["extra"] = math.NaN()
	e.Observer["parser_id"], e.Observer["parser_version"] = p.ParserID, p.ParserVersion
	mac := hmac.New(sha256.New, []byte(p.Key))
	e.Observer["proxy_signature"] = hex.EncodeToString(mac.Sum(nil))
	result := Evaluate(e, Config{Version: "encoding-failure", Producers: []Producer{p}})
	if err := OpenRepository(db, "").Commit(ctx, []Result{result}, ScanState{}); err != nil {
		t.Fatal("failed to persist the untrusted derived result")
	}
	rows, err := OpenRepository(db, "").Query(ctx, result.IP, time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, stored := range rows {
		if stored.ID != result.ID {
			continue
		}
		found = true
		if stored.Trusted || stored.Confidence != 0 || stored.CampusID != "" || stored.AccessDomain != "" {
			t.Fatal("repository reload restored malformed-event authority")
		}
		ss := []policy.Session{{ID: "owner", AccountID: "owner", IP: stored.IP, CampusID: "c", AccessDomain: "nas", Source: "auth", StartedAt: stored.RequestAt.Add(-time.Minute), ConfirmedAt: stored.RequestAt, HeartbeatSeconds: 60}}
		if in := Input("owner", []Result{stored}, ss, stored.ObservedAt, time.Hour, "manual"); in.Known || in.Violated {
			t.Fatal("stored malformed event reached account policy input")
		}
	}
	if !found {
		t.Fatal("untrusted diagnostic result disappeared")
	}
}
