package legacy4k

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Use a dedicated disposable Redis database, never the field source.
func TestAtomicOnlineInventoryRedis(t *testing.T) {
	addr := os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("dedicated Redis not configured")
	}
	ctx := context.Background()
	c := redis.NewClient(&redis.Options{Addr: addr, DB: 15})
	defer c.Close()
	prefix := fmt.Sprintf("snapshot-test-%d", time.Now().UnixNano())
	list, ready, id := prefix+":list", prefix+":ready", prefix+":1"
	hash := "hash:rad_online:" + id
	defer c.Del(ctx, list, ready, hash)
	if _, err := ReadOnlineInventory(ctx, c, list, ready, 2); err == nil {
		t.Fatal("missing source accepted as empty")
	}
	if err := c.Set(ctx, ready, "1", 0).Err(); err != nil {
		t.Fatal(err)
	}
	got, err := ReadOnlineInventory(ctx, c, list, ready, 2)
	if err != nil || len(got.Rows) != 0 || got.InstanceID == "" {
		t.Fatal(got, err)
	}
	c.RPush(ctx, list, id)
	if _, err = ReadOnlineInventory(ctx, c, list, ready, 2); err == nil {
		t.Fatal("missing hash accepted")
	}
	c.HSet(ctx, hash, "rad_online_id", id, "user_name", "alice", "ip", "192.0.2.1", "ip6", "2001:db8::1")
	got, err = ReadOnlineInventory(ctx, c, list, ready, 2)
	if err != nil || len(got.Rows) != 1 || got.Rows[0]["user_name"] != "alice" {
		t.Fatal(got, err)
	}
	addresses, err := got.IdentityRecords()
	if err != nil || len(addresses) != 2 || got.Rows[0]["ip6"] != "2001:db8::1" {
		t.Fatalf("native IPv6 field lost in Redis read: %+v %v", addresses, err)
	}
	c.RPush(ctx, list, id)
	if _, err = ReadOnlineInventory(ctx, c, list, ready, 2); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err = ReadOnlineInventory(ctx, c, list, ready, 1); err == nil {
		t.Fatal("oversized accepted")
	}
	c.LPop(ctx, list)
	c.HSet(ctx, hash, "rad_online_id", "wrong")
	if _, err = ReadOnlineInventory(ctx, c, list, ready, 2); err == nil {
		t.Fatal("mismatched identity accepted")
	}
}
