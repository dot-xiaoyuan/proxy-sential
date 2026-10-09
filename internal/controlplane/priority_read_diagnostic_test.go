package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/store"
	"testing"
	"time"
)

// Opt-in diagnostic: no listener, no worker, only GET, DB-enforced read-only.
func TestPriorityRepairReadDiagnostic(t *testing.T) {
	if os.Getenv("SENTINEL_READ_DIAGNOSTIC") != "30" {
		t.Skip("explicit read-only diagnostic required")
	}
	u, err := url.Parse(os.Getenv("PROXY_SENTINEL_POSTGRES_DSN"))
	if err != nil || u.Hostname() != "127.0.0.1" {
		t.Fatal("local production database only")
	}
	q := u.Query()
	q.Set("default_transaction_read_only", "on")
	q.Set("application_name", "sentinel-read-diagnostic")
	q.Set("statement_timeout", "12000")
	u.RawQuery = q.Encode()
	reader, err := store.NewDBStore(store.Options{PostgresDSN: u.String(), ClickHouseDSN: os.Getenv("PROXY_SENTINEL_CLICKHOUSE_DSN"), RequestTimeout: 12 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ops, err := newOperationsState("", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer ops.db.Close()
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.shadowDir = "/opt/proxy-sentinel/data/shadow"
	s.reader = reader
	s.operations = ops
	s.identityIngest.db = ops.db
	s.identityIngest.key = os.Getenv("PROXY_SENTINEL_IDENTITY_INGEST_KEY")
	s.exceptions = newExceptionManager(ops.db)
	s.whitelist = newWhitelistManager(ops.db, "")
	s.productPolicies = newProductPolicyState("", ops.db)
	s.srun4KDefaults = SRun4KDefaults{RedisPassword: os.Getenv("PROXY_SENTINEL_SRUN4K_REDIS_PASSWORD")}
	items, err := s.listSRun4K(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Host != "192.168.0.190" {
			continue
		}
		client := s.srunRedis(item)
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		before := time.Now().UTC()
		stamp, err := client.Time(ctx).Result()
		after := time.Now().UTC()
		raw, _ := json.Marshal(map[string]any{"redis_time": stamp, "local_before": before, "local_after": after, "remote_minus_local_ms": stamp.Sub(after).Milliseconds(), "error": fmt.Sprint(err)})
		fmt.Println(string(raw))
		inventory, err := legacy4k.ReadOnlineInventoryPaged(ctx, client, "list:rad_online", 100000, 1000)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		found := []map[string]string{}
		for _, row := range inventory.Rows {
			if row["ip"] == "192.168.0.57" {
				found = append(found, row)
			}
		}
		raw, _ = json.Marshal(map[string]any{"online_count": len(inventory.Rows), "target_rows": found, "observed": inventory.ObservedAt, "now": time.Now().UTC()})
		fmt.Println(string(raw))
	}
	for _, path := range []string{"/device-inventory?view=recent&window=24h&limit=20", "/device-recognition/summary", "/accounts/yuantong/identity", "/integrations/srun4k", "/integrations/identity/status", "/activity/reports?window=1h&dimension=src_ip&limit=20", "/discovery/devices?limit=20&offset=0", "/dpi/overview?window=1h", "/ips/192.168.0.57/devices?window=24h", "/devices?window=24h&limit=20", "/shared-access/devices?limit=20", "/router-observations?limit=20", "/whitelist?limit=20", "/actions?limit=20", "/audit-logs?limit=20"} {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		ctx = context.WithValue(ctx, sessionContextKey{}, Session{User: User{ID: "read-only-diagnostic"}, Role: "admin", Permissions: rolePermissions("admin")})
		r := httptest.NewRequest("GET", "/api/v1"+path, nil).WithContext(ctx)
		w := httptest.NewRecorder()
		started := time.Now()
		s.dispatchAPI(w, r, r.URL.Path[len("/api/v1"):])
		cancel()
		result := map[string]any{"path": path, "seconds": time.Since(started).Seconds(), "status": w.Code, "bytes": w.Body.Len()}
		if path == "/accounts/yuantong/identity" && w.Code == 200 {
			var profile store.AccountIdentityProfile
			if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil {
				t.Fatal(err)
			}
			targets := []map[string]any{}
			for _, session := range profile.Sessions {
				if session.IP == "192.168.0.57" {
					targets = append(targets, map[string]any{"account": session.AccountID, "ip": session.IP, "session_id": session.SessionID, "source": session.Source, "started_at": session.StartedAt, "ended_at": session.EndedAt, "mac": session.MAC, "endpoint_id": session.EndpointID})
				}
			}
			result["target_sessions"] = targets
			result["account_session_count"] = len(profile.Sessions)
		}
		if w.Code >= 400 {
			result["error"] = w.Body.String()
		}
		if w.Body.Len() < 20000 && path != "/activity/reports?window=1h&dimension=src_ip&limit=20" {
			result["response"] = json.RawMessage(w.Body.Bytes())
		}
		raw, _ := json.Marshal(result)
		fmt.Println(string(raw))

		if w.Code >= 500 || (path == "/accounts/yuantong/identity" && w.Code != 200) {
			t.Errorf("read API failed: %s status=%d", path, w.Code)
		}
	}
	// Warm and cold timing samples use real data with database-enforced read-only.
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ctx = context.WithValue(ctx, sessionContextKey{}, Session{User: User{ID: "read-only-diagnostic"}, Role: "admin", Permissions: rolePermissions("admin")})
		r := httptest.NewRequest("GET", "/api/v1/discovery/devices?limit=20", nil).WithContext(ctx)
		w := httptest.NewRecorder()
		start := time.Now()
		s.dispatchAPI(w, r, "/discovery/devices")
		cancel()
		fmt.Printf("discovery_timing status=%d milliseconds=%.3f\n", w.Code, float64(time.Since(start).Microseconds())/1000)
		if w.Code != 200 || time.Since(start) > time.Second {
			t.Errorf("discovery latency/status: %d %s", w.Code, time.Since(start))
		}
	}
}
