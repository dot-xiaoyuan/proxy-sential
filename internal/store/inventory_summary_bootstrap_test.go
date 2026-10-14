package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestInventorySummaryAvailabilityDoesNotAcknowledgeHistory(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id := "summary-ready:" + time.Now().Format("150405.000000000")
	at := time.Now().UTC().Add(-time.Minute)
	item := DeviceInventoryListItem{EndpointID: id, CurrentIP: "192.0.2.189", CurrentAccount: "bootstrap-account"}
	raw, _ := json.Marshal(item)
	if _, err = s.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,entity_role,last_seen) VALUES($1,'endpoint',$2)`, id, at); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO endpoint_recognition_summary(endpoint_id,list_item) VALUES($1,$2)`, id, raw); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `UPDATE endpoint_inventory_projection_state SET ready=false,summary_complete=false,summary_cursor=''`); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 10; n++ {
		if err = s.bootstrapInventorySummaries(ctx, 2000); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []Query{{View: "history", InventorySearchType: "account", Q: "bootstrap-account", InventorySkipMetadata: true}} {
		page, e := s.ListDeviceInventory(ctx, q)
		if e != nil {
			t.Fatal(e)
		}
		if len(page.Items) != 1 || page.ReadModelState.Complete || !page.ReadModelState.Available {
			t.Fatalf("summary unavailable or history falsely complete: %+v", page)
		}
	}
	var processed int64
	if err = s.db.QueryRowContext(ctx, `SELECT processed_generation FROM endpoint_inventory_projection_jobs WHERE endpoint_id=$1`, id).Scan(&processed); err != nil || processed != 0 {
		t.Fatal("bootstrap acknowledged source tasks", processed, err)
	}
	if _, err = s.db.ExecContext(ctx, `UPDATE endpoint_inventory_lookup SET device_name='prepared-wins' WHERE endpoint_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `UPDATE endpoint_inventory_projection_state SET summary_complete=false,summary_cursor=''`); err != nil {
		t.Fatal(err)
	}
	if err = s.bootstrapInventorySummaries(ctx, 2000); err != nil {
		t.Fatal(err)
	}
	var name string
	if err = s.db.QueryRowContext(ctx, `SELECT device_name FROM endpoint_inventory_lookup WHERE endpoint_id=$1`, id).Scan(&name); err != nil || name != "prepared-wins" {
		t.Fatal("bootstrap replaced prepared row", name, err)
	}
}
