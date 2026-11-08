package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"proxy-sentinel/internal/pagination"
	"testing"
)

func TestRegistrationCatalogPostgresPaginationAndFactIsolation(t *testing.T) {
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
	ctx := context.Background()
	// Temporary current-state fixture shadows the production relation and is
	// dropped with this dedicated connection. No historical data is needed.
	_, err = db.ExecContext(ctx, `CREATE TEMP TABLE endpoint_entities(
 endpoint_id text PRIMARY KEY, primary_mac text, entity_role text, registration_status text,
 owner_account text,owner_name text,owner_department text,asset_tag text,ownership_class text,
 registration_note text,registration_updated_at timestamptz,registration_updated_by text,
 registered_at timestamptz,last_seen timestamptz,merge_status text NOT NULL DEFAULT 'active',merged_into_endpoint_id text,split_from_endpoint_id text,attributes jsonb)`)
	if err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(ctx, `DROP TABLE pg_temp.endpoint_entities`)
	_, err = db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,registration_status,ownership_class,owner_name,registration_updated_at,attributes) VALUES
 ('mac:02:00:00:00:00:01','02:00:00:00:00:01','endpoint','registered','school_asset','张老师',now(),'{"manual_registration":{"name":"打印机1","device_type":"printer","registered_ip":"10.0.0.8","location":"一楼"}}'),
 ('mac:02:00:00:00:00:02','02:00:00:00:00:02','endpoint','registered','school_asset','李老师',now(),'{"manual_registration":{"name":"打印机2","device_type":"printer"}}'),
 ('mac:02:00:00:00:00:03','02:00:00:00:00:03','endpoint','retired','public_terminal','李老师',now(),'{"manual_registration":{"name":"旧打印机","device_type":"printer"}}'),
 ('mac:02:00:00:00:00:04','02:00:00:00:00:04','endpoint','unregistered','unknown',NULL,NULL,'{}')`)
	if err != nil {
		t.Fatal(err)
	}
	pg := &PostgresStore{db: db}
	q := EndpointRegistrationQuery{Status: "registered", DeviceType: "printer", Limit: 1}
	first, err := pg.ListEndpointRegistrations(ctx, q)
	if err != nil || len(first.Items) != 1 || !first.HasMore {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	if first.Items[0].RegistrationDetails.RegisteredIP != "10.0.0.8" || first.Items[0].LastSeen != "" {
		t.Fatalf("registered address confused with observed: %+v", first.Items[0])
	}
	q.Cursor = first.NextCursor
	second, err := pg.ListEndpointRegistrations(ctx, q)
	if err != nil || len(second.Items) != 1 || second.HasMore || second.Items[0].EndpointID == first.Items[0].EndpointID {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	pos, err := pg.EndpointRegistrationPosition(ctx, q, 2)
	if err != nil {
		t.Fatal(err)
	}
	q.Cursor = pos.Cursor
	located, err := pg.ListEndpointRegistrations(ctx, q)
	if err != nil || len(located.Items) != 1 || located.Items[0].EndpointID != second.Items[0].EndpointID {
		t.Fatalf("random page lost registration: %+v %v", located, err)
	}
	if _, err = pg.EndpointRegistrationPosition(ctx, q, 3); !errors.Is(err, pagination.ErrPageOutOfRange) {
		t.Fatalf("accepted empty next page: %v", err)
	}
	meta, err := pg.EndpointRegistrationMetadata(ctx, q)
	if err != nil || meta.Total != 2 {
		t.Fatalf("metadata=%+v err=%v", meta, err)
	}
	meta, err = pg.EndpointRegistrationMetadata(ctx, EndpointRegistrationQuery{})
	if err != nil || meta.Total != 3 {
		t.Fatalf("passive-only candidate leaked into registration ledger: %+v err=%v", meta, err)
	}
	page, err := pg.ListEndpointRegistrations(ctx, EndpointRegistrationQuery{Search: "张老师"})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("owner search=%+v err=%v", page, err)
	}
	page, err = pg.ListEndpointRegistrations(ctx, EndpointRegistrationQuery{Search: "%"})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("search wildcard was not literal: %+v err=%v", page, err)
	}
	page, err = pg.ListEndpointRegistrations(ctx, EndpointRegistrationQuery{MAC: "02-00-00-00-00-02"})
	if err != nil || len(page.Items) != 1 || page.Items[0].PrimaryMAC != "02:00:00:00:00:02" {
		t.Fatalf("exact MAC lookup=%+v err=%v", page, err)
	}
	page, err = pg.ListEndpointRegistrations(ctx, EndpointRegistrationQuery{OwnershipClass: "public_terminal", Status: "retired"})
	if err != nil || len(page.Items) != 1 || page.Items[0].RegistrationStatus != "retired" {
		t.Fatalf("retired filter=%+v err=%v", page, err)
	}
}
