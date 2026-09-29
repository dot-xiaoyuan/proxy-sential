package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

func TestDBBrandBackfillActivationSummaryAndRollback(t *testing.T) {
	pgDSN, chDSN := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"), os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if pgDSN == "" || chDSN == "" {
		t.Skip("PostgreSQL and ClickHouse integration DSNs required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, pgDSN, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyClickHouseMigrations(ctx, chDSN, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("brand-backfill-%d", time.Now().UnixNano())
	db, err := NewDBStore(Options{PostgresDSN: pgDSN, ClickHouseDSN: chDSN, SensorID: id})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	original := fingerprint.Default()
	defer fingerprint.SetDefault(original)
	load := func(version string, rules []byte) *fingerprint.Library {
		l, e := fingerprint.LoadDomainLibrary(version, rules)
		if e != nil {
			t.Fatal(e)
		}
		return l
	}
	library := load(id, original.DomainRulesJSON())
	fingerprint.SetDefault(library)
	var previous []byte
	_ = db.pg.db.QueryRowContext(ctx, `SELECT to_jsonb(s) FROM domain_recognition_state s WHERE singleton`).Scan(&previous)
	defer func() {
		_, _ = db.pg.db.ExecContext(context.Background(), `DELETE FROM endpoint_domain_evidence_events WHERE endpoint_id=$1`, id)
		_, _ = db.pg.db.ExecContext(context.Background(), `DELETE FROM endpoint_entities WHERE endpoint_id=$1`, id)
		_, _ = db.pg.db.ExecContext(context.Background(), `DELETE FROM domain_evidence_backfill_jobs WHERE version LIKE $1`, id+"%")
		_, _ = db.pg.db.ExecContext(context.Background(), `DELETE FROM domain_rule_versions WHERE version LIKE $1`, id+"%")
		if len(previous) == 0 {
			_, _ = db.pg.db.ExecContext(context.Background(), `DELETE FROM domain_recognition_state`)
		} else {
			_, _ = db.pg.db.ExecContext(context.Background(), `UPDATE domain_recognition_state SET active_version=$1::jsonb->>'active_version',pending_version=$1::jsonb->>'pending_version',last_error=$1::jsonb->>'last_error'`, previous)
		}
		_ = db.ch.exec(context.Background(), "ALTER TABLE normalized_events DELETE WHERE sensor_id="+chQuote(id))
		_ = db.ch.exec(context.Background(), "ALTER TABLE domain_ecosystem_observations DELETE WHERE sensor_id="+chQuote(id))
	}()
	now := time.Now().UTC()
	identity := normalized.Event{EventID: id + "-identity", Type: "identity", Timestamp: now.Add(-time.Hour).Format(time.RFC3339Nano), Subject: map[string]any{"endpoint_id": id, "mac": "02:00:00:00:90:09", "entity_role": "endpoint"}, Payload: map[string]any{}, Flow: map[string]any{}}
	if err := db.pg.WriteIdentityEvents(ctx, []normalized.Event{identity}); err != nil {
		t.Fatal(err)
	}
	events := brandReplay(t)
	for i := range events {
		events[i].EventID = id + events[i].EventID
		events[i].Subject["endpoint_id"] = id
		events[i].Observer["sensor_id"] = id
		events[i].Timestamp = now.Add(time.Duration(i-20) * time.Minute).Format(time.RFC3339Nano)
	}
	if err := db.ch.WriteNormalizedEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	result, err := db.RebuildDomainEvidenceVersion(ctx, id, 7*24*time.Hour, 2, nil)
	if err != nil || result.Status != "completed" || result.Matched != 4 || result.Attributed != 4 {
		t.Fatalf("backfill %+v %v", result, err)
	}
	again, err := db.RebuildDomainEvidenceVersion(ctx, id, 7*24*time.Hour, 2, nil)
	if err != nil || again.Processed != result.Processed {
		t.Fatalf("repeat %+v %v", again, err)
	}
	profile, _, err := db.GetEndpointIdentity(ctx, id, Query{})
	if err != nil || profile.BrandInference.Status != "inferred" {
		t.Fatalf("profile %v %+v", err, profile)
	}
	list, err := db.ListEndpointDevices(ctx, Query{Q: id})
	if err != nil || len(list.Items) != 1 || list.Items[0].BrandInference.Status != profile.BrandInference.Status {
		t.Fatalf("list %+v %v", list, err)
	}
	summary, err := db.GetDeviceRecognitionSummary(ctx, id)
	if err != nil || summary.Coverage["brand_inferred"].Known < 1 || summary.DomainRuleVersion != id {
		t.Fatalf("summary %+v %v", summary, err)
	}
	// A job interrupted by a newer loaded version cannot replace active results.
	interrupted := load(id+"-interrupted", original.DomainRulesJSON())
	fingerprint.SetDefault(interrupted)
	_, err = db.RebuildDomainEvidenceVersion(ctx, interrupted.Version(), 7*24*time.Hour, 2, func(DomainBackfillProgress) { fingerprint.SetDefault(library) })
	if err == nil {
		t.Fatal("superseded job succeeded")
	}
	active, _, err := db.pg.activeDomainVersion(ctx)
	if err != nil || active != id {
		t.Fatalf("active result lost: %s %v", active, err)
	}
	// Importing a legacy empty-domain version must clear the active hypotheses.
	legacy := load(id+"-legacy", []byte("[]"))
	fingerprint.SetDefault(legacy)
	result, err = db.RebuildDomainEvidenceVersion(ctx, legacy.Version(), 7*24*time.Hour, 2, nil)
	if err != nil || result.Status != "completed" {
		t.Fatalf("rollback %+v %v", result, err)
	}
	profile, _, err = db.GetEndpointIdentity(ctx, id, Query{})
	if err != nil || profile.BrandInference.Status != "insufficient" {
		t.Fatalf("stale inference after rollback %v", err)
	}
}
