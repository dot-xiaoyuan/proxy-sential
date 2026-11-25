package discovery

import (
	"context"
	"testing"
	"time"
)

func TestDevicesEventBusIntegration(t *testing.T) {
	db := discoveryTestSchema(t)
	if _, err := db.Exec(`CREATE TABLE discovery_device_current_shadow (LIKE public.discovery_device_current_shadow INCLUDING ALL);
	 INSERT INTO discovery_device_current_shadow(device_key,last_seen,fact_count,facts,document)
	 SELECT 'page-'||n,now(),0,'{}','{"current":true}' FROM generate_series(1,6) n`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo := Repository{DB: db}
	page, err := repo.DevicesEventBus(ctx, DeviceQuery{Limit: 5, Window: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	items, _ := page["items"].([]map[string]any)
	if len(items) != 5 {
		t.Fatalf("unexpected items: %d", len(items))
	}
	if cursor, _ := page["next_cursor"].(string); cursor == "" {
		t.Fatal("expected next cursor for non-empty page")
	}
	next, err := repo.DevicesEventBus(ctx, DeviceQuery{Limit: 5, Window: 24 * time.Hour, Cursor: page["next_cursor"].(string)})
	if err != nil {
		t.Fatal(err)
	}
	nextItems, _ := next["items"].([]map[string]any)
	if len(nextItems) != 1 || nextItems[0]["id"] != "page-6" || next["next_cursor"] != "" {
		t.Fatalf("unexpected next page: %+v", next)
	}
}
