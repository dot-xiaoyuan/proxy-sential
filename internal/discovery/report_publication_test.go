package discovery

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestPublishedReportScopeAndLastSuccess(t *testing.T) {
	q := DeviceQuery{Window: 24 * time.Hour, Mode: "passive", IdentityScope: "devices"}
	for _, variant := range []DeviceQuery{{}, {Window: 24 * time.Hour, Mode: "passive"}, {Window: 24 * time.Hour, Mode: "passive", IdentityScope: "address_clues"}} {
		if defaultMetadataScope(variant) {
			t.Fatal("unexpected default scope", variant)
		}
	}
	if !defaultMetadataScope(q) {
		t.Fatal("missing default")
	}
	filtered := q
	filtered.DeviceType = "printer"
	if defaultMetadataScope(filtered) {
		t.Fatal("filter replaced by global result")
	}
	db := hardwareIntegrationDB(t)
	ctx := context.Background()
	repo := Repository{DB: db, HardwareV2: true}
	for _, file := range []string{"252_discovery_list_projection.sql", "253_discovery_queue_generations.sql", "254_discovery_address_links_and_reports.sql"} {
		sql, e := os.ReadFile("../../migrations/postgres/" + file)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec(string(sql)); e != nil {
			t.Fatal(e)
		}
	}
	t.Setenv("PROXY_SENTINEL_DISCOVERY_STRUCTURED_READS", "published_metadata,published_coverage")
	if _, e := repo.ReadDeviceMetadata(ctx, "site", q); !errors.Is(e, ErrReportPreparing) {
		t.Fatal(e)
	}
	if _, e := db.Exec(`INSERT INTO discovery_report_publications VALUES ('site','metadata',24,now()-interval '20 min',now()-interval '20 min',now()-interval '19 min','{"total":7,"overview":{"active":2}}')`); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.ReadDeviceMetadata(ctx, "site", q); !errors.Is(e, ErrReportPreparing) {
		t.Fatal("old publication has no evidence breakdown", e)
	}
	if _, e := db.Exec(`UPDATE discovery_report_publications SET document=document||'{"candidate":7,"profile_typed":4,"no_type_clue":3,"revoked":0}'::jsonb`); e != nil {
		t.Fatal(e)
	}
	if _, e := repo.ReadDeviceMetadata(ctx, "site", q); !errors.Is(e, ErrReportPreparing) {
		t.Fatal("missing IP count became zero", e)
	}
	if _, e := db.Exec(`UPDATE discovery_report_publications SET document=document||'{"candidate":7,"profile_typed":4,"ip_product_only":0,"no_type_clue":3,"revoked":0}'::jsonb`); e != nil {
		t.Fatal(e)
	}
	// Missing input tables make this publication fail; the committed document survives.
	var schema string
	if e := db.QueryRow("SELECT current_schema()").Scan(&schema); e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	options := u.Query()
	options.Set("search_path", schema)
	u.RawQuery = options.Encode()
	pool, e := sql.Open("pgx", u.String())
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	repo.DB = pool
	if _, e = pool.Exec("ALTER TABLE discovery_observation_latest RENAME TO temporarily_unavailable"); e != nil {
		t.Fatal(e)
	}
	if e := repo.publishReport(ctx, "site", "metadata", q.Window); e == nil {
		t.Fatal("incomplete publication was accepted")
	}
	q.SkipOverview = true
	r, e := repo.ReadDeviceMetadata(ctx, "site", q)
	if e != nil || r.Total != 7 || r.Publication == nil || !r.Publication.Delayed || r.Overview != nil {
		t.Fatal(r, e)
	}
	if _, e = repo.ReadCoverageReport(ctx, "site", q.Window); !errors.Is(e, ErrReportPreparing) {
		t.Fatal(e)
	}
}
