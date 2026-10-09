package store

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestCurrentInventoryReplacesRunsWithoutAppendingHistory(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(PostgresOptions{DSN: dsn, SensorID: "current-replay"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer s.db.Exec(`DELETE FROM device_inventory_current WHERE sensor_id='current-replay'`)
	for i, run := range []string{"first", "second"} {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		item := IPDeviceInventory{IP: "192.0.2.7", Window: "1h", SuspectedDeviceCount: i + 1, Confidence: .9, Status: "identified", Devices: []ObservedDevice{{DeviceID: "current-device"}}, Signals: []DeviceSignal{}, Conflicts: []DeviceConflict{}, LastSeen: time.Now().UTC().Format(time.RFC3339Nano)}
		if err = upsertCurrentDeviceInventory(ctx, tx, Run{RunID: run, SensorID: "current-replay"}, "1h", item); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ListDeviceInventories(ctx, Query{Limit: 20, IncludeWeak: true})
	if err != nil || len(page.Items) != 1 || page.Items[0].SuspectedDeviceCount != 2 {
		t.Fatalf("current replacement: %+v %v", page, err)
	}
	item, err := s.GetIPDeviceInventory(ctx, "192.0.2.7", ActivityQuery{})
	if err != nil || item.SuspectedDeviceCount != 2 {
		t.Fatalf("detail: %+v %v", item, err)
	}
	var history int
	if err = s.db.QueryRow(`SELECT count(*) FROM device_inventory_snapshots WHERE sensor_id='current-replay'`).Scan(&history); err != nil || history != 0 {
		t.Fatalf("history appended: %d %v", history, err)
	}
}
