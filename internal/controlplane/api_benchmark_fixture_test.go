package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"proxy-sentinel/internal/store"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Opt-in disposable PostgreSQL/ClickHouse fixture; no production DSN is accepted.
func TestAPIBenchmarkFixtureServer(t *testing.T) {
	addr := os.Getenv("PROXY_SENTINEL_BENCHMARK_ADDR")
	if addr == "" {
		t.Skip("benchmark fixture is opt-in")
	}
	pg := os.Getenv("PROXY_SENTINEL_BENCHMARK_PG")
	ch := os.Getenv("PROXY_SENTINEL_BENCHMARK_CH")
	if !strings.HasPrefix(addr, "127.0.0.1:") || !strings.Contains(pg, "@127.0.0.1:") || !strings.Contains(pg, "/sentinel_benchmark") || !strings.HasPrefix(ch, "http://127.0.0.1:") {
		t.Fatal("only disposable local benchmark databases allowed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := store.ApplyPostgresMigrations(ctx, pg, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyClickHouseMigrations(ctx, ch, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", pg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var hasAdmin bool
	if err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM local_users WHERE username='admin')").Scan(&hasAdmin); err != nil {
		t.Fatal(err)
	}
	if !hasAdmin {
		if err := BootstrapAdminPostgres(pg, "admin", "Benchmark admin", DefaultInitialAdminPassword); err != nil {
			t.Fatal(err)
		}
	}
	// Start read-only to suppress action/case/backfill workers, then enable only
	// request-driven writes against the explicitly disposable databases.
	s, err := NewServerWithError(Options{ShadowDir: "/tmp/proxy-sentinel-benchmark-state-20260917", SensorID: "bench-scale-20260917", StorageMode: "db", PostgresDSN: pg, ClickHouseDSN: ch, ReadOnly: true, ApplicationsEnabled: true, ActionMasterKey: "benchmark-isolated-master-key-1234", IdentityIngestKey: "benchmark-isolated-identity-key"})
	if err != nil {
		t.Fatal(err)
	}
	s.readOnly = false
	s.startOperationWorkers()
	s.exports.startWorkers(s)
	s.operations.mu.Lock()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	s.operations.doc.Campuses["bench-campus"] = Campus{CampusID: "bench-campus", Name: "Benchmark campus", Enabled: true}
	s.operations.doc.Cases["bench-case"] = RiskCase{CaseID: "bench-case", SubjectType: "ip", SubjectID: "203.0.113.10", IP: "203.0.113.10", Status: "new", Priority: "high", RiskScore: 85, RiskConfidence: .9, AssessmentLevel: "high", DedupeKey: "bench-case", FirstSeen: now, LastSeen: now, CreatedAt: now, UpdatedAt: now, DueAt: time.Now().Add(time.Hour).Format(time.RFC3339Nano)}
	err = s.operations.saveLocked()
	s.operations.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PROXY_SENTINEL_BENCHMARK_SCALE") == "10000000" {
		if err = seedBenchmarkOperations(db); err != nil {
			t.Fatal(err)
		}
		if err = seedBenchmarkIdentityAndEvidence(db); err != nil {
			t.Fatal(err)
		}
		models, ok := s.reader.(interface {
			DrainApplicationConnectionReadModel(context.Context) error
			RunApplicationReadModels(context.Context)
		})
		if !ok {
			t.Fatal("missing application read models")
		}
		prepareCtx, prepareCancel := context.WithTimeout(context.Background(), 10*time.Minute)
		if preparer, ok := s.reader.(interface{ PrepareStatisticsReadModel(context.Context) error }); ok {
			if err = preparer.PrepareStatisticsReadModel(prepareCtx); err != nil {
				prepareCancel()
				t.Fatal(err)
			}
		}
		err = models.DrainApplicationConnectionReadModel(prepareCtx)
		prepareCancel()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(context.Background(), `INSERT INTO application_read_model_backfills(name,cursor_at,until_at,status) VALUES('latest-observations-v1',now(),now(),'completed') ON CONFLICT(name) DO UPDATE SET status='completed'`); err != nil {
			t.Fatal(err)
		}
		workerCtx, workerCancel := context.WithCancel(context.Background())
		t.Cleanup(workerCancel)
		go models.RunApplicationReadModels(workerCtx)
	}

	handler := s.Handler()
	tracePattern := regexp.MustCompile(`^[a-f0-9]{16}-[0-9]{1,5}$`)
	fixtureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if trace := r.Header.Get("X-Benchmark-ID"); tracePattern.MatchString(trace) {
			r = r.WithContext(store.WithQueryTrace(r.Context(), trace))
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/__benchmark__/identity" {
			var database string
			if err := db.QueryRowContext(r.Context(), "SELECT current_database()").Scan(&database); err != nil {
				writeError(w, 503, "fixture_unavailable", "benchmark database unavailable")
				return
			}
			writeJSON(w, 200, map[string]any{"fixture": "proxy-sentinel-disposable-benchmark", "isolated": true, "database": database, "writes_allowed": database == "sentinel_benchmark"})
			return
		}
		handler.ServeHTTP(w, r)
	})
	srv := &http.Server{Addr: addr, Handler: fixtureHandler, ReadHeaderTimeout: 5 * time.Second}
	t.Cleanup(func() { _ = srv.Close() })
	fmt.Println("BENCHMARK_FIXTURE_READY", addr)
	if err = srv.ListenAndServe(); err != http.ErrServerClosed {
		t.Fatal(err)
	}
}

func seedBenchmarkOperations(db *sql.DB) error {
	ctx := context.Background()
	// Exactly 47 active cases and 24,000 synthetic snapshots, averaging roughly
	// 6 KiB per decoded snapshot. Existing benchmark rows are not cleaned.
	_, err := db.ExecContext(ctx, `INSERT INTO risk_cases(case_id,dedupe_key,subject_type,subject_id,ip,status,priority,risk_score,risk_confidence,assessment_level,first_seen,last_seen) SELECT 'bench-scale-case-'||n,'bench-scale-case-'||n,'ip','203.0.113.'||(n+1),('203.0.113.'||(n+1))::inet,'new','high',85,.9,'high',now()-interval '6 days',now() FROM generate_series(0,46)n ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO risk_case_evidence_snapshots(snapshot_id,case_id,evidence,created_at) SELECT 'bench-scale-snapshot-'||n,'bench-scale-case-'||(n%47),jsonb_build_object('case_id','bench-scale-case-'||(n%47),'ip','203.0.113.'||(n%47+1),'event_count',20,'destinations',(SELECT jsonb_agg(jsonb_build_object('value','service-'||i||'.example.test.'||repeat('segment-',12),'count',i,'last_seen',now())) FROM generate_series(1,40)i)),now()-n*interval '10 seconds' FROM generate_series(0,23999)n ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO risk_snapshots(ip,score,level,confidence,"window",evidence_ids,summary,recommended_action,updated_at) SELECT ('203.0.113.'||(n+1))::inet,85,'high',.9,'1h',jsonb_build_array('benchmark-evidence'),'synthetic risk with normal evidence','review',now() FROM generate_series(0,46)n ON CONFLICT DO NOTHING`)
	return err
}
