package legacy4k

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

type pagedInventoryHook struct {
	afterPage         func(context.Context) error
	infoCalls         int
	fired             bool
	maxPage           int
	maxWatch          int
	finalTx           int
	commands          map[string]int
	validationElapsed time.Duration
}

func (h *pagedInventoryHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *pagedInventoryHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, c redis.Cmder) error {
		h.commands[c.Name()]++
		if c.Name() == "watch" && len(c.Args())-1 > h.maxWatch {
			h.maxWatch = len(c.Args()) - 1
		}
		started := time.Now()
		err := next(ctx, c)
		if (c.Name() == "evalsha" || c.Name() == "eval") && time.Since(started) > h.validationElapsed {
			h.validationElapsed = time.Since(started)
		}
		if c.Name() == "info" {
			h.infoCalls++
		}
		return err
	}
}
func (h *pagedInventoryHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		page := 0
		transaction := false
		for _, c := range cmds {
			h.commands[c.Name()]++
			if c.Name() == "hmget" {
				page++
			}
			if c.Name() == "multi" {
				h.finalTx = len(cmds)
				transaction = true
			}
		}
		if !transaction && page > h.maxPage {
			h.maxPage = page
		}
		started := time.Now()
		err := next(ctx, cmds)
		if transaction {
			h.validationElapsed = time.Since(started)
		}
		if err == nil && !transaction && page > 0 && !h.fired && h.afterPage != nil {
			h.fired = true
			return h.afterPage(ctx)
		}
		return err
	}
}

func TestPagedOnlineInventoryNativeConsistency(t *testing.T) {
	addr := os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("disposable Redis required")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" || port != "16399" || os.Getenv("PROXY_SENTINEL_TEST_REDIS_DISPOSABLE") != "1" {
		t.Fatal("dedicated loopback acceptance Redis required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	writer := redis.NewClient(&redis.Options{Addr: addr, DB: 15})
	defer writer.Close()
	for _, tc := range []string{"stable_paging", "same_id_hash_change", "same_id_hash_aba", "membership_aba", "hash_deleted_after_read", "hash_deleted_before_read", "reader_connection_lost", "cancelled_between_pages", "empty_inventory", "unrelated_accounting_update", "hybrid_identity_pair", "missing_field_becomes_empty", "membership_added", "membership_reordered", "group_id_changed", "products_id_changed", "control_id_changed", "vlan_id_changed", "device_id_changed", "login_generation_changed"} {
		t.Run(tc, func(t *testing.T) {
			prefix := fmt.Sprintf("sentinel-page-%d", time.Now().UnixNano())
			list := prefix + ":list"
			first, second := prefix+":1", prefix+":2"
			hash1, hash2 := "hash:rad_online:"+first, "hash:rad_online:"+second
			defer writer.Del(context.Background(), list, hash1, hash2)
			if tc != "empty_inventory" {
				if err := writer.RPush(ctx, list, first, second).Err(); err != nil {
					t.Fatal(err)
				}
				for _, v := range []struct{ key, id, account, ip string }{{hash1, first, "alice", "192.0.2.1"}, {hash2, second, "bob", "192.0.2.2"}} {
					if err := writer.HSet(ctx, v.key, "rad_online_id", v.id, "user_name", v.account, "ip", v.ip, "add_time", fmt.Sprint(time.Now().Add(-time.Minute).Unix())).Err(); err != nil {
						t.Fatal(err)
					}
				}
			}
			reader := NewRedisOnlineClient(&redis.Options{Addr: addr, DB: 15, PoolSize: 1, MaxRetries: 1, ContextTimeoutEnabled: true})
			defer reader.Close()
			connection, err := reader.ClientID(ctx).Result()
			if err != nil {
				t.Fatal(err)
			}
			callCtx, stop := context.WithCancel(ctx)
			defer stop()
			hook := &pagedInventoryHook{commands: map[string]int{}}
			var firstReadTime time.Time
			switch tc {
			case "stable_paging":
				hook.afterPage = func(ctx context.Context) error {
					var err error
					firstReadTime, err = writer.Time(ctx).Result()
					return err
				}
			case "membership_added":
				hook.afterPage = func(ctx context.Context) error { return writer.RPush(ctx, list, first).Err() }
			case "membership_reordered":
				hook.afterPage = func(ctx context.Context) error {
					_, err := writer.TxPipelined(ctx, func(pipe redis.Pipeliner) error { pipe.LPop(ctx, list); pipe.RPush(ctx, list, first); return nil })
					return err
				}
			case "group_id_changed", "products_id_changed", "control_id_changed", "vlan_id_changed", "device_id_changed", "login_generation_changed":
				field := strings.TrimSuffix(tc, "_changed")
				value := "replacement"
				if tc == "login_generation_changed" {
					field = "add_time"
					value = fmt.Sprint(time.Now().Add(-2 * time.Minute).Unix())
				}
				hook.afterPage = func(ctx context.Context) error { return writer.HSet(ctx, hash1, field, value).Err() }
			case "unrelated_accounting_update":
				hook.afterPage = func(ctx context.Context) error { return writer.HSet(ctx, hash1, "bytes_in", "999").Err() }
			case "hybrid_identity_pair":
				hook.afterPage = func(ctx context.Context) error {
					_, err := writer.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
						pipe.HSet(ctx, hash1, "user_name", "replacement-a")
						pipe.HSet(ctx, hash2, "user_name", "replacement-b")
						return nil
					})
					return err
				}
			case "missing_field_becomes_empty":
				hook.afterPage = func(ctx context.Context) error { return writer.HSet(ctx, hash1, "seed_tag", "").Err() }
			case "same_id_hash_change":
				hook.afterPage = func(ctx context.Context) error {
					return writer.HSet(ctx, hash1, "user_name", "replacement", "ip", "192.0.2.9").Err()
				}
			case "same_id_hash_aba":
				hook.afterPage = func(ctx context.Context) error {
					if err := writer.HSet(ctx, hash1, "user_name", "replacement").Err(); err != nil {
						return err
					}
					return writer.HSet(ctx, hash1, "user_name", "alice").Err()
				}
			case "membership_aba":
				hook.afterPage = func(ctx context.Context) error {
					if err := writer.LPop(ctx, list).Err(); err != nil {
						return err
					}
					return writer.LPush(ctx, list, first).Err()
				}
			case "hash_deleted_after_read":
				hook.afterPage = func(ctx context.Context) error { return writer.Del(ctx, hash1).Err() }
			case "hash_deleted_before_read":
				hook.afterPage = func(ctx context.Context) error { return writer.Del(ctx, hash2).Err() }
			case "reader_connection_lost":
				hook.afterPage = func(ctx context.Context) error {
					if err := writer.HSet(ctx, hash1, "user_name", "replacement-after-close").Err(); err != nil {
						return err
					}
					return writer.ClientKillByFilter(ctx, "ID", fmt.Sprint(connection)).Err()
				}
			case "cancelled_between_pages":
				hook.afterPage = func(context.Context) error { stop(); return nil }
			}
			conn := reader.Conn()
			defer conn.Close()
			conn.AddHook(hook)
			before, err := writer.Time(ctx).Result()
			if err != nil {
				t.Fatal(err)
			}
			got, err := readOnlineInventoryPagedConnection(callCtx, reader, conn, list, 10, 1)
			conn.Close()
			if tc == "stable_paging" || tc == "empty_inventory" || tc == "unrelated_accounting_update" || tc == "same_id_hash_aba" || tc == "membership_aba" {
				expected := 2
				if tc == "empty_inventory" {
					expected = 0
				}
				if err != nil || len(got.Rows) != expected || got.InstanceID == "" || got.ObservedAt.Before(before) {
					t.Fatalf("stable inventory rejected: rows=%d err=%v", len(got.Rows), err)
				}
				if tc == "stable_paging" && got.ObservedAt.Before(firstReadTime) {
					t.Error("observation predates its atomic validation")
				}
				if hook.maxPage > 1 || hook.maxWatch != 0 || hook.finalTx != expected+5 {
					t.Fatal("unbounded upstream transaction or page", hook.maxPage, hook.maxWatch, hook.finalTx)
				}
			} else if err == nil || len(got.Rows) != 0 || !got.ObservedAt.IsZero() {
				t.Errorf("changed/interrupted inventory accepted: rows=%d err=%v", len(got.Rows), err)
			}
			if tc != "stable_paging" && tc != "empty_inventory" && tc != "unrelated_accounting_update" && tc != "same_id_hash_aba" && tc != "membership_aba" && tc != "reader_connection_lost" && tc != "cancelled_between_pages" {
				if !errors.Is(err, ErrOnlineInventoryChanged) {
					t.Error("concurrent change was reported as a connection failure", err)
				}
			}
			for command := range hook.commands {
				switch command {
				case "llen", "lrange", "hmget", "info", "time", "multi", "exec", "hello", "client", "select":
				default:
					t.Errorf("inventory issued non-read command %s", command)
				}
			}
			// The caller remains usable after the pinned observation connection closes.
			if err := writer.HSet(ctx, hash1, "rad_online_id", first, "user_name", "alice", "ip", "192.0.2.1").Err(); err != nil {
				t.Fatal(err)
			}
			if err := reader.Ping(ctx).Err(); err != nil && !strings.Contains(err.Error(), "closed") {
				t.Fatal("reader pool did not recover after aborted observation", err)
			}
		})
	}
}

func TestPagedOnlineInventoryNativeConfiguredBound(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR") != "127.0.0.1:16399" || os.Getenv("PROXY_SENTINEL_TEST_REDIS_DISPOSABLE") != "1" {
		t.Skip("dedicated disposable acceptance Redis required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	writer := redis.NewClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15, ContextTimeoutEnabled: true})
	defer writer.Close()
	prefix := fmt.Sprintf("sentinel-bound-%d", time.Now().UnixNano())
	list := prefix + ":list"
	const count = 100000
	cleanup := func() {
		for start := 0; start < count; start += 1000 {
			keys := make([]string, 0, 1000)
			for i := start; i < min(start+1000, count); i++ {
				keys = append(keys, "hash:rad_online:"+fmt.Sprintf("%s:%d", prefix, i))
			}
			if err := writer.Del(ctx, keys...).Err(); err != nil {
				t.Error("owned fixture cleanup failed", err)
				return
			}
		}
		writer.Del(ctx, list)
	}
	defer cleanup()
	for start := 0; start < count; start += 1000 {
		pipe := writer.Pipeline()
		ids := make([]any, 0, 1000)
		for i := start; i < min(start+1000, count); i++ {
			id := fmt.Sprintf("%s:%d", prefix, i)
			ids = append(ids, id)
			pipe.HSet(ctx, "hash:rad_online:"+id, "session_id", id, "rad_online_id", id, "user_name", "load", "ip", "192.0.2.1", "ipv6", "2001:db8::1", "ip6", "2001:db8::1", "user_mac", "02:00:00:00:00:01", "nas_ip", "192.0.2.254", "add_time", strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10), "group_id", "1", "products_id", "1", "control_id", "control-1", "vlan_id", "7", "device_id", "load-device", "seed_tag", "fixture")
		}
		pipe.RPush(ctx, list, ids...)
		if _, err := pipe.Exec(ctx); err != nil {
			t.Fatal("bounded fixture setup failed", err)
		}
	}
	reader := NewRedisOnlineClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15, PoolSize: 4, MaxRetries: 1, ContextTimeoutEnabled: true})
	defer reader.Close()
	hook := &pagedInventoryHook{commands: map[string]int{}}
	conn := reader.Conn()
	defer conn.Close()
	conn.AddHook(hook)
	started := time.Now()
	got, err := readOnlineInventoryPagedConnection(ctx, reader, conn, list, count, 2000)
	if err != nil || len(got.Rows) != count {
		t.Fatal("configured maximum inventory rejected", len(got.Rows), err)
	}
	if hook.maxWatch != 0 || hook.maxPage > 2000 || hook.finalTx != count+5 || hook.commands["info"] != 1 {
		t.Fatal("upstream commands exceeded page/transaction bounds", hook.maxWatch, hook.maxPage, hook.finalTx)
	}
	records, err := got.IdentityRecords()
	if err != nil || len(records) != 2*count {
		t.Fatalf("dual-address maximum expansion rejected: count=%d err=%v", len(records), err)
	}
	records = nil
	t.Logf("100000 rows validated in %s; validation RPC=%s, read page=%d, MULTI/EXEC=%d commands", time.Since(started), hook.validationElapsed, hook.maxPage, hook.finalTx)
	if err := writer.RPush(ctx, list, "over-bound").Err(); err != nil {
		t.Fatal(err)
	}
	got, err = readOnlineInventoryPagedConnection(ctx, reader, conn, list, count, 2000)
	if err == nil || len(got.Rows) != 0 {
		t.Fatal("over-bound inventory accepted")
	}
}

func TestPagedOnlineInventoryNativeLargeValidationFailure(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR") != "127.0.0.1:16399" || os.Getenv("PROXY_SENTINEL_TEST_REDIS_DISPOSABLE") != "1" {
		t.Skip("dedicated disposable acceptance Redis required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	writer := redis.NewClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15, ContextTimeoutEnabled: true})
	defer writer.Close()
	for _, tc := range []string{"already_read_row_changed", "later_page_update_is_consistent", "later_page_row_deleted", "large_observation_connection_lost"} {
		t.Run(tc, func(t *testing.T) {
			prefix := fmt.Sprintf("sentinel-large-%d", time.Now().UnixNano())
			list := prefix + ":list"
			const count = 8000
			defer func() {
				for start := 0; start < count; start += 1000 {
					keys := make([]string, 0, 1000)
					for i := start; i < min(start+1000, count); i++ {
						keys = append(keys, "hash:rad_online:"+fmt.Sprintf("%s:%d", prefix, i))
					}
					writer.Del(ctx, keys...)
				}
				writer.Del(ctx, list)
			}()
			for start := 0; start < count; start += 1000 {
				pipe := writer.Pipeline()
				ids := make([]any, 0, 1000)
				for i := start; i < min(start+1000, count); i++ {
					id := fmt.Sprintf("%s:%d", prefix, i)
					ids = append(ids, id)
					pipe.HSet(ctx, "hash:rad_online:"+id, "rad_online_id", id, "user_name", "load", "ip", "192.0.2.1")
				}
				pipe.RPush(ctx, list, ids...)
				if _, err := pipe.Exec(ctx); err != nil {
					t.Fatal(err)
				}
			}
			reader := NewRedisOnlineClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15, PoolSize: 4, ClientName: prefix, MaxRetries: 1, ContextTimeoutEnabled: true})
			defer reader.Close()
			hook := &pagedInventoryHook{commands: map[string]int{}}
			switch tc {
			case "already_read_row_changed":
				hook.afterPage = func(ctx context.Context) error {
					return writer.HSet(ctx, "hash:rad_online:"+prefix+":0", "user_name", "replacement").Err()
				}
			case "later_page_update_is_consistent":
				hook.afterPage = func(ctx context.Context) error {
					return writer.HSet(ctx, "hash:rad_online:"+fmt.Sprintf("%s:%d", prefix, count-1), "user_name", "replacement").Err()
				}
			case "later_page_row_deleted":
				hook.afterPage = func(ctx context.Context) error {
					return writer.Del(ctx, "hash:rad_online:"+fmt.Sprintf("%s:%d", prefix, count-1)).Err()
				}
			case "large_observation_connection_lost":
				hook.afterPage = func(ctx context.Context) error {
					clients, err := writer.ClientList(ctx).Result()
					if err != nil {
						return err
					}
					var last int64
					for _, line := range strings.Split(clients, "\n") {
						name := ""
						var id int64
						for _, field := range strings.Fields(line) {
							if strings.HasPrefix(field, "name=") {
								name = strings.TrimPrefix(field, "name=")
							}
							if strings.HasPrefix(field, "id=") {
								id, _ = strconv.ParseInt(strings.TrimPrefix(field, "id="), 10, 64)
							}
						}
						if name == prefix && id > last {
							last = id
						}
					}
					if last == 0 {
						return fmt.Errorf("owned observation connection missing")
					}
					return writer.ClientKillByFilter(ctx, "ID", fmt.Sprint(last)).Err()
				}
			}
			conn := reader.Conn()
			defer conn.Close()
			conn.AddHook(hook)
			got, err := readOnlineInventoryPagedConnection(ctx, reader, conn, list, count, 1000)
			if tc == "later_page_update_is_consistent" {
				if err != nil || len(got.Rows) != count || got.Rows[count-1]["user_name"] != "replacement" {
					t.Fatal("valid later-page update was rejected", err)
				}
			} else if err == nil || len(got.Rows) != 0 || !got.ObservedAt.IsZero() {
				t.Fatal("failed validation published partial/full snapshot", len(got.Rows), err)
			}
			if hook.infoCalls != 1 {
				t.Fatal("observation did not stay on one connection", hook.infoCalls)
			}
			if tc == "already_read_row_changed" || tc == "later_page_row_deleted" {
				if !errors.Is(err, ErrOnlineInventoryChanged) {
					t.Fatal("changed row reported as broken connection", err)
				}
			}
		})
	}
}

func TestPagedOnlineInventoryNativePublicWrapper(t *testing.T) {
	if os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR") != "127.0.0.1:16399" || os.Getenv("PROXY_SENTINEL_TEST_REDIS_DISPOSABLE") != "1" {
		t.Skip("dedicated disposable acceptance Redis required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := NewRedisOnlineClient(&redis.Options{Addr: "127.0.0.1:16399", DB: 15, PoolSize: 1, PoolTimeout: time.Second, ContextTimeoutEnabled: true})
	defer client.Close()
	id := fmt.Sprintf("sentinel-wrapper-%d", time.Now().UnixNano())
	list, hash := id+":list", "hash:rad_online:"+id
	defer client.Del(context.Background(), list, hash)
	if err := client.RPush(ctx, list, id).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.HSet(ctx, hash, "rad_online_id", id, "user_name", "wrapper", "ip", "192.0.2.1").Err(); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		in, err := ReadOnlineInventoryPaged(ctx, client, list, 10, 1)
		if err != nil || len(in.Rows) != 1 || in.Rows[0]["rad_online_id"] != id {
			t.Fatal("public wrapper rejected stable inventory", err)
		}
		// A leaked pinned connection exhausts this single-connection pool.
		if err := client.Ping(ctx).Err(); err != nil {
			t.Fatal("public wrapper leaked its connection", err)
		}
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	in, err := ReadOnlineInventoryPaged(cancelled, client, list, 10, 1)
	if err == nil || len(in.Rows) != 0 || !in.ObservedAt.IsZero() {
		t.Fatal("cancelled public call returned a snapshot")
	}
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal("cancelled public call exhausted its pool", err)
	}
	if _, err := ReadOnlineInventoryPaged(ctx, nil, list, 10, 1); err == nil {
		t.Fatal("nil public client accepted")
	}
}
