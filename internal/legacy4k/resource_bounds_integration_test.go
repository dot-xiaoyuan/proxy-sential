package legacy4k

import (
	"context"
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOnlineNativeResourceBounds(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR") != "127.0.0.1:16399" || os.Getenv("PROXY_SENTINEL_TEST_REDIS_DISPOSABLE") != "1" {
		t.Skip("dedicated disposable acceptance Redis required")
	}
	ctx, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()
	w := redis.NewClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15})
	defer w.Close()
	for _, name := range []string{"field_boundary", "field_over_bound", "aggregate_projection", "oversized_bulk", "ignored_hash_payload"} {
		t.Run(name, func(t *testing.T) {
			prefix := fmt.Sprintf("sentinel-online-bounds-%d", time.Now().UnixNano())
			list := prefix + ":list"
			count := 1
			if name == "aggregate_projection" {
				count = 17000
			}
			keys := []string{list}
			for i := 0; i < count; i++ {
				keys = append(keys, "hash:rad_online:"+fmt.Sprintf("%s:%d", prefix, i))
			}
			t.Cleanup(func() {
				clean, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				for i := 0; i < len(keys); i += 500 {
					if err := w.Del(clean, keys[i:min(i+500, len(keys))]...).Err(); err != nil {
						t.Error("owned fixture cleanup failed", err)
					}
				}
			})
			value := strings.Repeat("x", MaxOnlineFieldBytes)
			if name == "field_over_bound" {
				value += "x"
			}
			if name == "oversized_bulk" {
				value = strings.Repeat("x", (64<<10)+1)
			}
			for start := 0; start < count; start += 500 {
				pipe := w.Pipeline()
				ids := []any{}
				for i := start; i < min(start+500, count); i++ {
					id := fmt.Sprintf("%s:%d", prefix, i)
					ids = append(ids, id)
					pipe.HSet(ctx, keys[i+1], "rad_online_id", id, "user_name", "alice", "ip", "192.0.2.1", "device_id", value)
				}
				pipe.RPush(ctx, list, ids...)
				if _, err := pipe.Exec(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if name == "ignored_hash_payload" {
				if err := w.HSet(ctx, keys[1], "unrelated_accounting_blob", strings.Repeat("x", 8<<20)).Err(); err != nil {
					t.Fatal(err)
				}
			}
			r := NewRedisOnlineClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15, MaxRetries: -1})
			defer r.Close()
			started := time.Now()
			in, err := ReadOnlineInventoryPaged(ctx, r, list, 100000, 500)
			if name == "field_boundary" || name == "ignored_hash_payload" {
				if err != nil || len(in.Rows) != 1 {
					t.Fatalf("bounded valid projection rejected: %v", err)
				}
				if r.BudgetUsage().Bytes > 20000 {
					t.Fatal("irrelevant hash field downloaded", r.BudgetUsage())
				}
			} else {
				if !errors.Is(err, ErrOnlineResourceLimit) || len(in.Rows) != 0 || !in.ObservedAt.IsZero() {
					t.Fatalf("oversized projection not rejected completely: rows=%d err=%v", len(in.Rows), err)
				}
			}
			t.Logf("case=%s elapsed=%s consumed_bytes=%d", name, time.Since(started), r.BudgetUsage().Bytes)
			// Restore only owned source fields, then prove a rejected read does not
			// poison the client pool or retain the old operation's budget.
			for start := 0; start < count; start += 500 {
				pipe := w.Pipeline()
				for i := start; i < min(start+500, count); i++ {
					pipe.HSet(ctx, keys[i+1], "device_id", "device")
				}
				if _, err := pipe.Exec(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.Ping(ctx).Err(); err != nil {
				t.Fatal("client did not recover", err)
			}
			if recovered, err := ReadOnlineInventoryPaged(ctx, r, list, 100000, 500); err != nil || len(recovered.Rows) != count {
				t.Fatalf("complete bounded read did not recover: rows=%d err=%v", len(recovered.Rows), err)
			}
		})
	}
}
