package productpolicy

import (
	"context"
	"os"
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestReadRedisSnapshotUsesCompleteCatalog(t *testing.T) {
	addr := os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("dedicated Redis not configured")
	}
	ctx := context.Background()
	client := NewRedisCatalogClient(&redis.Options{Addr: addr, DB: 15})
	defer client.Close()
	keys := []string{"list:products", "list:control", "list:products:control:p1", "hash:products:p1", "hash:control:c1", "hash:control:c2"}
	client.Del(ctx, keys...)
	defer client.Del(ctx, keys...)
	client.RPush(ctx, "list:products", "p1")
	client.HSet(ctx, "hash:products:p1", "products_id", "p1", "products_name", "办公产品", "mgr_name", "office")
	client.RPush(ctx, "list:control", "c1", "c2")
	client.RPush(ctx, "list:products:control:p1", "c1", "c2")
	client.HSet(ctx, "hash:control:c1", "control_id", "c1", "control_name", "基础", "max_online_num", "2")
	client.HSet(ctx, "hash:control:c2", "control_id", "c2", "control_name", "宽松", "max_online_num", "4", "disable_proxy", "1", "route_condition", "campus=office")
	snapshot, err := ReadRedisSnapshot(ctx, client, "office", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Complete || len(snapshot.Products) != 1 || len(snapshot.Controls) != 2 || len(snapshot.Products[0].ControlIDs) != 2 || snapshot.ContentHash == "" {
		t.Fatalf("incomplete product snapshot: %+v", snapshot)
	}
	if snapshot.Controls[1].Reference["route_condition"] != "campus=office" {
		t.Fatalf("control reference fields lost: %+v", snapshot.Controls[1])
	}
	client.Del(ctx, "hash:control:c2")
	if _, err = ReadRedisSnapshot(ctx, client, "office", 10); err == nil {
		t.Fatal("missing control hash accepted")
	}
}
