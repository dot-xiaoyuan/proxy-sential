package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/pagination"
)

func TestInventoryPostgresNumberedPositionMatchesCursorPages(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, statement := range []string{
		`CREATE TEMP TABLE endpoint_entities(endpoint_id text PRIMARY KEY,entity_role text)`,
		`CREATE TEMP TABLE endpoint_recognition_summary(endpoint_id text PRIMARY KEY,filter_brand text)`,
		`CREATE TEMP TABLE endpoint_inventory_lookup(endpoint_id text PRIMARY KEY,last_seen timestamptz,list_item jsonb,updated_at timestamptz)`,
		`CREATE TEMP TABLE endpoint_state_watermark(singleton bool,bootstrap_complete bool,last_error text,last_success_at timestamptz,updated_at timestamptz)`,
		`INSERT INTO endpoint_state_watermark VALUES(true,true,'',now(),now())`,
		`CREATE TEMP TABLE endpoint_recognition_jobs(processed_generation int,dirty_generation int)`,
	} {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for index, id := range []string{"a", "b", "c", "d", "e", "x"} {
		var at any
		var seen string
		if index < 3 || id == "x" {
			v := now
			if id == "c" {
				v = now.Add(-time.Second)
			}
			at = v
			seen = v.Format(time.RFC3339Nano)
		}
		brand := "Dell"
		if id == "x" {
			brand = "HP"
		}
		raw, _ := json.Marshal(EndpointDeviceInventory{EndpointID: id, LastSeen: seen})
		for _, insert := range []struct {
			statement string
			args      []any
		}{
			{`INSERT INTO endpoint_entities VALUES($1,'endpoint')`, []any{id}},
			{`INSERT INTO endpoint_recognition_summary VALUES($1,$2)`, []any{id, brand}},
			{`INSERT INTO endpoint_inventory_lookup VALUES($1,$2,$3,$4)`, []any{id, at, raw, now}},
		} {
			if _, err = db.ExecContext(ctx, insert.statement, insert.args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	pg := &PostgresStore{db: db}
	// Reverse random access covers timestamp ties, null timestamps, page sizes,
	// and a brand filter without decoding intervening list payloads.
	for _, limit := range []int{1, 2, 3} {
		pages := (5 + limit - 1) / limit
		for number := pages; number >= 1; number-- {
			q := Query{Brand: "Dell", Limit: limit, InventoryPositionPage: number, InventorySkipMetadata: true}
			position, err := pg.ListDeviceInventory(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			if position.Page.NextCursor == nil {
				t.Fatal("missing position")
			}
			q.InventoryPositionPage = 0
			q.InventoryCursor = *position.Page.NextCursor
			result, err := pg.ListDeviceInventory(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			start := (number - 1) * limit
			end := min(start+limit, 5)
			if len(result.Items) != end-start {
				t.Fatalf("page %d size %d items=%+v", number, limit, result.Items)
			}
			for i, item := range result.Items {
				want := string(rune('a' + start + i))
				if item.EndpointID != want {
					t.Fatalf("page=%d size=%d got=%s want=%s", number, limit, item.EndpointID, want)
				}
			}
		}
		if _, err = pg.ListDeviceInventory(ctx, Query{Brand: "Dell", Limit: limit, InventoryPositionPage: pages + 1}); !errors.Is(err, pagination.ErrPageOutOfRange) {
			t.Fatalf("page beyond end: %v", err)
		}
	}
	if _, err = pg.ListDeviceInventory(ctx, Query{Brand: "HP", Limit: 1, InventoryPositionPage: 2}); !errors.Is(err, pagination.ErrPageOutOfRange) {
		t.Fatalf("full final page allowed empty successor: %v", err)
	}
}
