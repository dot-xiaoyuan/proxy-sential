package productpolicy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestRedisCatalogNativeResourceBounds(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR") != "127.0.0.1:16399" || os.Getenv("PROXY_SENTINEL_TEST_REDIS_DISPOSABLE") != "1" {
		t.Skip("dedicated disposable acceptance Redis required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	w := redis.NewClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15, ContextTimeoutEnabled: true})
	defer w.Close()
	for _, name := range []string{"relation_boundary", "aggregate_reference_bytes", "oversized_bulk", "oversized_array", "ignored_product_field"} {
		t.Run(name, func(t *testing.T) {
			prefix := fmt.Sprintf("resource-%d", time.Now().UnixNano())
			keys := []string{"list:products", "list:control"}
			cleanup := func() {
				if err := w.Del(context.Background(), keys...).Err(); err != nil {
					t.Error(err)
				}
			}
			cleanup()
			defer cleanup()
			count := 1
			if name == "relation_boundary" {
				count = 100
			}
			if name == "aggregate_reference_bytes" {
				count = 9
			}
			pipe := w.Pipeline()
			for i := 0; i < count; i++ {
				p, c := fmt.Sprintf("%s-p%d", prefix, i), fmt.Sprintf("%s-c%d", prefix, i)
				keys = append(keys, "hash:products:"+p, "list:products:control:"+p, "hash:control:"+c)
				pipe.RPush(ctx, "list:products", p)
				pipe.HSet(ctx, "hash:products:"+p, "products_name", p)
				if name == "relation_boundary" {
					c = prefix + "-c0"
					references := make([]any, 1000)
					for j := range references {
						references[j] = c
					}
					pipe.RPush(ctx, "list:products:control:"+p, references...)
				} else {
					pipe.RPush(ctx, "list:products:control:"+p, c)
				}
				pipe.HSet(ctx, "hash:control:"+c, "control_name", c, "max_online_num", "2")
				if name == "aggregate_reference_bytes" {
					fields := map[string]any{}
					for j := 0; j < 256; j++ {
						fields[fmt.Sprint(j)] = strings.Repeat("x", 10000)
					}
					pipe.HSet(ctx, "hash:control:"+c, fields)
				}
			}
			if _, err := pipe.Exec(ctx); err != nil {
				t.Fatal(err)
			}
			p, c := prefix+"-p0", prefix+"-c0"
			switch name {
			case "oversized_bulk":
				if err := w.HSet(ctx, "hash:control:"+c, "large", strings.Repeat("x", maxRedisBulkBytes+1)).Err(); err != nil {
					t.Fatal(err)
				}
			case "oversized_array":
				fields := map[string]any{}
				for i := 0; i < 50001; i++ {
					fields[fmt.Sprint(i)] = "x"
				}
				if err := w.HSet(ctx, "hash:control:"+c, fields).Err(); err != nil {
					t.Fatal(err)
				}
			case "ignored_product_field":
				if err := w.HSet(ctx, "hash:products:"+p, "not_a_catalog_field", strings.Repeat("x", 8<<20)).Err(); err != nil {
					t.Fatal(err)
				}
			}
			r := NewRedisCatalogClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15, MaxRetries: -1})
			defer r.Close()
			hook := &catalogReadHook{commands: map[string]int{}}
			r.AddHook(hook)
			started := time.Now()
			snapshot, err := ReadRedisSnapshot(ctx, r, "acceptance", 10000)
			if name == "relation_boundary" || name == "ignored_product_field" {
				if err != nil || !snapshot.Complete || len(snapshot.Products) != count {
					t.Fatal("valid complete catalog rejected", err)
				}
				if name == "ignored_product_field" && r.BudgetUsage().Bytes > 20000 {
					t.Fatal("ignored product payload was downloaded", r.BudgetUsage().Bytes)
				}
			} else if !errors.Is(err, ErrCatalogResourceLimit) || snapshot.Complete || len(snapshot.Products) > 0 {
				t.Fatal("oversized catalog published or incorrectly classified", err)
			}
			if name == "relation_boundary" {
				if err := w.RPush(ctx, "list:products:control:"+p, c).Err(); err != nil {
					t.Fatal(err)
				}
				hook.txCalls, hook.readHashCalls = 0, 0
				snapshot, err = ReadRedisSnapshot(ctx, r, "acceptance", 10000)
				if !errors.Is(err, ErrCatalogResourceLimit) || snapshot.Complete || hook.txCalls != 0 || hook.readHashCalls != 0 {
					t.Fatal("aggregate overflow reached hash materialization", err)
				}
			}
			if err := r.Ping(ctx).Err(); err != nil {
				t.Fatal("pool failed to recover after rejected read", err)
			}
			if name == "oversized_bulk" || name == "oversized_array" || name == "aggregate_reference_bytes" {
				for i := 0; i < count; i++ {
					id := fmt.Sprintf("%s-c%d", prefix, i)
					if err := w.Del(ctx, "hash:control:"+id).Err(); err != nil {
						t.Fatal(err)
					}
					if err := w.HSet(ctx, "hash:control:"+id, "control_name", id, "max_online_num", "2").Err(); err != nil {
						t.Fatal(err)
					}
				}
				recovered, err := ReadRedisSnapshot(ctx, r, "acceptance", 10000)
				if err != nil || !recovered.Complete || len(recovered.Controls) != count {
					t.Fatal("valid whole snapshot did not recover after resource rejection", err)
				}
			}
			t.Logf("case=%s elapsed=%s received_budget_bytes=%d", name, time.Since(started), r.BudgetUsage().Bytes)
		})
	}
}
