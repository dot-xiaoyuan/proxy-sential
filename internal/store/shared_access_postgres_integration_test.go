package store

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"os"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/sharedaccess"
	"reflect"
	"testing"
	"time"
)

func TestSharedAccessEvidencePostgresRoundTrip(t *testing.T) {
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
	schema := fmt.Sprintf("shared_roundtrip_%d", time.Now().UnixNano())
	if _, err = admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec("DROP SCHEMA " + schema + " CASCADE")
	cfg.RuntimeParams["search_path"] = schema + ",public"
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE evidence(evidence_id text PRIMARY KEY, ip inet, type text, "window" text, score int, confidence double precision, severity text, reason text, samples jsonb, created_at timestamptz)`); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../migrations/postgres/025_shared_access_evidence.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = db.Exec(string(migration)); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	window := &sharedaccess.Window{ID: "shared-1", RuleVersion: sharedaccess.RuleVersion, IP: "192.0.2.1", SensorID: "s", CampusID: "c", AccessDomain: "a", Sources: []string{"capture"}, From: now.Add(-time.Minute), To: now, LastObservedAt: now, Complete: true, EventIDs: []string{"event1"}, Records: []sharedaccess.RecordRef{{EventID: "event1", Source: "capture", InstanceID: "boot1"}}}
	item := evidence.Evidence{EvidenceID: window.ID, IP: window.IP, Type: "shared_access_window", Window: "1m", CreatedAt: now.Format(time.RFC3339Nano), Samples: []string{}, SharedAccess: window}
	s := &PostgresStore{db: db}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err = s.WriteEvidence(ctx, []evidence.Evidence{item}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.GetIPEvidence(ctx, window.IP, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0].SharedAccess, window) {
		t.Fatalf("lost scope/proof or duplicated evidence: %+v", got)
	}
	newer := *window
	newer.ID = "shared-2"
	newer.To = now.Add(time.Second)
	newer.LastObservedAt = newer.To
	newerItem := item
	newerItem.EvidenceID = newer.ID
	newerItem.SharedAccess = &newer
	newerItem.CreatedAt = newer.To.Format(time.RFC3339Nano)
	if err = s.WriteEvidence(ctx, []evidence.Evidence{newerItem}); err != nil {
		t.Fatal(err)
	}
	windows, err := s.ListSharedAccessWindows(ctx, now.Add(-time.Hour), now.Add(time.Minute), 1)
	if err != nil || len(windows) != 1 || windows[0].ID != newer.ID {
		t.Fatalf("latest scope query: %+v %v", windows, err)
	}
	other := newer
	other.ID = "shared-3"
	other.SensorID = "another"
	otherItem := newerItem
	otherItem.EvidenceID = other.ID
	otherItem.SharedAccess = &other
	if err = s.WriteEvidence(ctx, []evidence.Evidence{otherItem}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ListSharedAccessWindows(ctx, now.Add(-time.Hour), now.Add(time.Minute), 1); err == nil {
		t.Fatal("truncated scope query treated as complete")
	}
	windows, err = s.ListSharedAccessWindows(ctx, now.Add(-time.Hour), now.Add(time.Minute), 2)
	if err != nil || len(windows) != 2 {
		t.Fatalf("sensor scopes merged: %+v %v", windows, err)
	}

}
