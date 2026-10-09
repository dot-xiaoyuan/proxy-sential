package productpolicy

import (
	"context"
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
	"os"
	"testing"
	"time"
)

type catalogReadHook struct {
	beforeFinal   func(context.Context) error
	txCalls       int
	readHashCalls int
	commands      map[string]int
}

func (h *catalogReadHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *catalogReadHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, c redis.Cmder) error { h.commands[c.Name()]++; return next(ctx, c) }
}
func (h *catalogReadHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, commands []redis.Cmder) error {
		transaction := len(commands) > 0 && commands[0].Name() == "multi"
		for _, c := range commands {
			h.commands[c.Name()]++
			if c.Name() == "hgetall" || c.Name() == "hmget" {
				h.readHashCalls++
			}
		}
		if transaction {
			h.txCalls++
			if h.beforeFinal != nil {
				if err := h.beforeFinal(ctx); err != nil {
					return err
				}
			}
		}
		return next(ctx, commands)
	}
}
func TestRedisCatalogNativeConsistency(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR") != "127.0.0.1:16399" || os.Getenv("PROXY_SENTINEL_TEST_REDIS_DISPOSABLE") != "1" {
		t.Skip("dedicated disposable acceptance Redis required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	writer := redis.NewClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15, ContextTimeoutEnabled: true})
	defer writer.Close()
	for _, name := range []string{"stable", "referenced_controls_at_bound", "referenced_controls_over_bound", "duplicate_product_member", "duplicate_control_member", "blank_control_member", "membership_change", "relation_change", "hash_update_at_atomic_point", "missing_control_hash", "cancelled_before_transaction", "empty_catalog", "duplicate_relation_is_canonical"} {
		t.Run(name, func(t *testing.T) {
			keys := []string{"list:products", "list:control", "list:products:control:p1", "list:products:control:p2", "hash:products:p1", "hash:products:p2", "hash:control:c1", "hash:control:c2", "hash:control:c3"}
			if err := writer.Del(ctx, keys...).Err(); err != nil {
				t.Fatal(err)
			}
			defer writer.Del(context.Background(), keys...)
			if name != "empty_catalog" {
				pipe := writer.Pipeline()
				pipe.RPush(ctx, "list:products", "p1", "p2")
				pipe.RPush(ctx, "list:control", "c1")
				for _, id := range []string{"p1", "p2"} {
					pipe.HSet(ctx, "hash:products:"+id, "products_id", id, "products_name", id)
					pipe.RPush(ctx, "list:products:control:"+id, "c1")
				}
				for _, id := range []string{"c1", "c2", "c3"} {
					pipe.HSet(ctx, "hash:control:"+id, "control_id", id, "control_name", id, "max_online_num", "2")
				}
				if _, err := pipe.Exec(ctx); err != nil {
					t.Fatal(err)
				}
			}
			max := 2
			switch name {
			case "duplicate_relation_is_canonical":
				if err := writer.RPush(ctx, "list:products:control:p1", "c1").Err(); err != nil {
					t.Fatal(err)
				}
			case "referenced_controls_at_bound":
				if err := writer.LSet(ctx, "list:products:control:p2", 0, "c2").Err(); err != nil {
					t.Fatal(err)
				}
			case "referenced_controls_over_bound":
				if err := writer.LSet(ctx, "list:products:control:p1", 0, "c2").Err(); err != nil {
					t.Fatal(err)
				}
				if err := writer.LSet(ctx, "list:products:control:p2", 0, "c3").Err(); err != nil {
					t.Fatal(err)
				}
			case "duplicate_product_member":
				if err := writer.LSet(ctx, "list:products", 1, "p1").Err(); err != nil {
					t.Fatal(err)
				}
			case "duplicate_control_member":
				if err := writer.RPush(ctx, "list:control", "c1").Err(); err != nil {
					t.Fatal(err)
				}
			case "blank_control_member":
				if err := writer.RPush(ctx, "list:control", "").Err(); err != nil {
					t.Fatal(err)
				}
			case "missing_control_hash":
				if err := writer.Del(ctx, "hash:control:c1").Err(); err != nil {
					t.Fatal(err)
				}
			}
			reader := NewRedisCatalogClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15, ContextTimeoutEnabled: true})
			defer reader.Close()
			callCtx, stop := context.WithCancel(ctx)
			defer stop()
			hook := &catalogReadHook{commands: map[string]int{}}
			switch name {
			case "membership_change":
				hook.beforeFinal = func(ctx context.Context) error { return writer.LSet(ctx, "list:products", 1, "p1").Err() }
			case "relation_change":
				hook.beforeFinal = func(ctx context.Context) error { return writer.LSet(ctx, "list:products:control:p1", 0, "c2").Err() }
			case "hash_update_at_atomic_point":
				hook.beforeFinal = func(ctx context.Context) error {
					return writer.HSet(ctx, "hash:control:c1", "control_name", "latest", "max_online_num", "9").Err()
				}
			case "cancelled_before_transaction":
				hook.beforeFinal = func(context.Context) error { stop(); return callCtx.Err() }
			}
			reader.AddHook(hook)
			in, err := ReadRedisSnapshot(callCtx, reader, "acceptance", max)
			switch name {
			case "stable", "referenced_controls_at_bound", "hash_update_at_atomic_point", "empty_catalog", "duplicate_relation_is_canonical":
				if err != nil || !in.Complete || in.InstanceID == "" || in.ObservedAt.IsZero() {
					t.Fatal("valid atomic catalog rejected", err)
				}
				if len(in.Controls) > max {
					t.Fatal("control union exceeds requested bound")
				}
				if name == "duplicate_relation_is_canonical" && len(in.Products[0].ControlIDs) != 1 {
					t.Fatal("repeated reference changed its set semantics")
				}
				if name == "hash_update_at_atomic_point" && (in.Controls[0].Name != "latest" || in.Controls[0].MaxOnlineNum != 9) {
					t.Fatal("hash fields were not read at final atomic point")
				}
			default:
				if err == nil || in.Complete || len(in.Products) > 0 || !in.ObservedAt.IsZero() {
					t.Fatalf("invalid/interrupted catalog accepted: products=%d controls=%d err=%v", len(in.Products), len(in.Controls), err)
				}
			}
			if name == "referenced_controls_over_bound" || name == "duplicate_product_member" || name == "duplicate_control_member" || name == "blank_control_member" {
				if hook.txCalls != 0 || hook.readHashCalls != 0 {
					t.Error("invalid preliminary membership triggered hash materialization", hook.txCalls, hook.readHashCalls)
				}
			}
			if name == "membership_change" || name == "relation_change" {
				if !errors.Is(err, ErrRedisCatalogChanged) {
					t.Error("concurrent change classified as connection failure", err)
				}
			}
			for command := range hook.commands {
				switch command {
				case "hello", "client", "select", "llen", "lrange", "hgetall", "hmget", "multi", "exec", "info", "time":
				default:
					t.Error("unexpected command", command)
				}
			}
			if err := reader.Ping(ctx).Err(); err != nil {
				t.Fatal("caller connection pool unusable", fmt.Sprint(err))
			}
		})
	}
}

func TestRedisCatalogNativeConfiguredBound(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR") != "127.0.0.1:16399" || os.Getenv("PROXY_SENTINEL_TEST_REDIS_DISPOSABLE") != "1" {
		t.Skip("dedicated disposable acceptance Redis required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	writer := redis.NewClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15, ContextTimeoutEnabled: true})
	defer writer.Close()
	prefix := fmt.Sprintf("catalog-bound-%d", time.Now().UnixNano())
	const count = 10000
	productID := func(i int) string { return fmt.Sprintf("%s-p%d", prefix, i) }
	controlID := func(i int) string { return fmt.Sprintf("%s-c%d", prefix, i) }
	cleanup := func() {
		for start := 0; start < count; start += 500 {
			keys := make([]string, 0, 1500)
			for i := start; i < start+500; i++ {
				keys = append(keys, "hash:products:"+productID(i), "list:products:control:"+productID(i), "hash:control:"+controlID(i))
			}
			if err := writer.Del(context.Background(), keys...).Err(); err != nil {
				t.Error("owned fixture cleanup failed", err)
			}
		}
		if err := writer.Del(context.Background(), "list:products", "list:control").Err(); err != nil {
			t.Error(err)
		}
	}
	if err := writer.Del(ctx, "list:products", "list:control").Err(); err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for start := 0; start < count; start += 500 {
		pipe := writer.Pipeline()
		ids := make([]any, 0, 500)
		for i := start; i < start+500; i++ {
			p, c := productID(i), controlID(i)
			ids = append(ids, p)
			pipe.HSet(ctx, "hash:products:"+p, "products_id", p, "products_name", p)
			pipe.RPush(ctx, "list:products:control:"+p, c)
			pipe.HSet(ctx, "hash:control:"+c, "control_id", c, "control_name", c, "max_online_num", "2")
		}
		pipe.RPush(ctx, "list:products", ids...)
		if _, err := pipe.Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.RPush(ctx, "list:control", controlID(0)).Err(); err != nil {
		t.Fatal(err)
	}
	reader := NewRedisCatalogClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15, ContextTimeoutEnabled: true})
	defer reader.Close()
	hook := &catalogReadHook{commands: map[string]int{}}
	reader.AddHook(hook)
	started := time.Now()
	snapshot, err := ReadRedisSnapshot(ctx, reader, "acceptance", count)
	if err != nil || len(snapshot.Products) != count || len(snapshot.Controls) != count || !snapshot.Complete {
		t.Fatal("configured catalog maximum rejected", err)
	}
	if hook.txCalls != 1 || hook.readHashCalls != count*2 {
		t.Fatal("unexpected hash/transaction count", hook.txCalls, hook.readHashCalls)
	}
	t.Logf("10000 products plus 10000 referenced controls accepted in %s", time.Since(started))
	// Each list remains within its own bound, while the distinct control union
	// gains one member. It must fail before expensive hash materialization.
	if err := writer.RPush(ctx, "list:products:control:"+productID(0), prefix+"-extra").Err(); err != nil {
		t.Fatal(err)
	}
	hook.txCalls, hook.readHashCalls = 0, 0
	snapshot, err = ReadRedisSnapshot(ctx, reader, "acceptance", count)
	if err == nil || snapshot.Complete || hook.txCalls != 0 || hook.readHashCalls != 0 {
		t.Fatal("over-bound union fetched or published", err, hook.txCalls, hook.readHashCalls)
	}
}

func TestRedisCatalogNativeDeadline(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR") != "127.0.0.1:16399" || os.Getenv("PROXY_SENTINEL_TEST_REDIS_DISPOSABLE") != "1" {
		t.Skip("dedicated disposable acceptance Redis required")
	}
	writer := redis.NewClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15, ContextTimeoutEnabled: true})
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := writer.Del(ctx, "list:products", "list:control").Err(); err != nil {
		t.Fatal(err)
	}
	reader := NewRedisCatalogClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15, ReadTimeout: 3 * time.Second, ContextTimeoutEnabled: true, MaxRetries: 1})
	defer reader.Close()
	paused := false
	hook := &catalogReadHook{commands: map[string]int{}, beforeFinal: func(ctx context.Context) error {
		err := writer.Do(ctx, "CLIENT", "PAUSE", 500, "ALL").Err()
		paused = err == nil
		return err
	}}
	reader.AddHook(hook)
	short, stop := context.WithTimeout(ctx, 75*time.Millisecond)
	defer stop()
	start := time.Now()
	in, err := ReadRedisSnapshot(short, reader, "acceptance", 2)
	elapsed := time.Since(start)
	if !paused || hook.txCalls != 1 || err == nil || in.Complete || !in.ObservedAt.IsZero() || short.Err() == nil || elapsed > 450*time.Millisecond {
		t.Fatal("read ignored shorter network deadline", elapsed, err)
	}
	t.Logf("paused owned Redis read aborted in %s", elapsed)
	// CLIENT PAUSE expires automatically; it never runs against the configured
	// upstream. Check pool recovery on a fresh operation after the source resumes.
	if err := writer.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Ping(ctx).Err(); err != nil {
		t.Fatal("reader pool did not recover", err)
	}
}
