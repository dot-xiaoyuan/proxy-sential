package discovery

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestDevicesEventBusIntegration(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repo := Repository{DB: db}
	page, err := repo.DevicesEventBus(ctx, DeviceQuery{Limit: 5, Window: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	items, _ := page["items"].([]map[string]any)
	if len(items) == 0 || len(items) > 5 {
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
	first := items[len(items)-1]["id"]
	for _, item := range nextItems {
		if item["id"] == first {
			t.Fatalf("cursor repeated last device %v", first)
		}
	}
}
