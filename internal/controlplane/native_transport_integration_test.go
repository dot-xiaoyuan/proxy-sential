package controlplane

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/redis/go-redis/v9"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
	"sync/atomic"
	"testing"
	"time"
)

// Isolated local services only. This fixture never uses field credentials.
func TestConfiguredNativeTransportRedisPostgresAccountFanout(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "all_success", true: "partial_rejection"}[reject], func(t *testing.T) { runConfiguredNativeTransport(t, reject) })
	}
}

func runConfiguredNativeTransport(t *testing.T, rejectSecond bool) {
	dsn, addr := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN"), os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR")
	if dsn == "" || addr == "" {
		t.Skip("dedicated PostgreSQL and Redis required")
	}
	ctx := context.Background()
	if _, err := store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	ops, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer ops.db.Close()
	rc := redis.NewClient(&redis.Options{Addr: addr, DB: 15})
	defer rc.Close()
	prefix := fmt.Sprintf("native-transport-%d", time.Now().UnixNano())
	list, ready := prefix+":list", prefix+":ready"
	ids := []string{prefix + ":1", prefix + ":2"}
	keys := []string{list, ready, "hash:rad_online:" + ids[0], "hash:rad_online:" + ids[1]}
	defer rc.Del(ctx, keys...)
	if err := rc.Set(ctx, ready, "1", 0).Err(); err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		if err := rc.HSet(ctx, "hash:rad_online:"+id, "rad_online_id", id, "session_id", fmt.Sprintf("session-%d", i), "user_name", "lab-user", "ip", fmt.Sprintf("192.0.2.%d", 10+i), "add_time", "100").Err(); err != nil {
			t.Fatal(err)
		}
		if err := rc.RPush(ctx, list, id).Err(); err != nil {
			t.Fatal(err)
		}
	}
	var drops atomic.Int32
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method", 405)
			return
		}
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/auth/get-access-token":
			if r.Form.Get("appId") != "lab-app" || r.Form.Get("appSecret") != "lab-secret" {
				http.Error(w, "auth", 403)
				return
			}
			io.WriteString(w, `{"code":0,"data":{"access_token":"lab-token","lifetime":60}}`)
		case "/api/v2/base/online-drop":
			id := r.Form.Get("rad_online_id")
			if r.Form.Get("access_token") != "lab-token" || r.Form.Get("user_name") != "lab-user" || r.Form.Get("drop_type") != "radius" || (id != ids[0] && id != ids[1]) {
				http.Error(w, "target", 400)
				return
			}
			drops.Add(1)
			if rejectSecond && id == ids[1] {
				io.WriteString(w, `{"code":10503}`)
				return
			}
			_, err := rc.TxPipelined(ctx, func(p redis.Pipeliner) error { p.LRem(ctx, list, 0, id); p.Del(ctx, "hash:rad_online:"+id); return nil })
			if err != nil {
				http.Error(w, "inventory", 500)
				return
			}
			io.WriteString(w, `{"code":0}`)
		default:
			http.Error(w, "unexpected", 404)
		}
	}))
	defer tlsServer.Close()
	dir := t.TempDir()
	cert := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	config := []nativeConfigEntry{{ConnectorID: prefix, CampusID: "lab", AccessDomain: "nas", Endpoint: tlsServer.URL, AppID: "lab-app", AppSecret: "lab-secret", CertificateFile: cert, RedisURL: "redis://" + addr + "/15", OnlineList: list, ReadyKey: ready, MaxRecords: 10, DropType: "radius"}}
	raw, _ := json.Marshal(config)
	file := filepath.Join(dir, "native.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	runtimes, closeRuntime, err := LoadNativeActions(file)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRuntime()
	runtime := runtimes[prefix]
	// Docker's VM clock differs slightly from the host. All fixture comparisons
	// use the same Redis/DB host clock; production freshness rules remain strict.
	runtime.Now = func() time.Time {
		at, err := rc.Time(ctx).Result()
		if err != nil {
			t.Fatal(err)
		}
		return at
	}
	runtimes[prefix] = runtime
	in, err := runtime.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	records, err := in.IdentityRecords()
	if err != nil || len(records) != 2 {
		t.Fatal("incomplete fixture", err)
	}
	now := formatDBTime(time.Now().UTC())
	ops.mu.Lock()
	ops.doc.Connectors[prefix] = ActionConnector{ConnectorID: prefix, Enabled: true, Mode: "active", ShadowReady: true, UpdatedAt: now}
	actionIDs := []string{}
	for _, r := range records {
		id := prefix + "-" + r["source_session_id"]
		actionIDs = append(actionIDs, id)
		ops.doc.Actions[id] = EnforcementAction{ActionID: id, IdempotencyKey: id, ConnectorID: prefix, ActionType: "session.disconnect", SubjectType: "session", AccountID: "lab-user", SessionID: r["session_id"], CampusID: "lab", IP: r["ip"], Status: "pending", Mode: "active", CreatedAt: now, UpdatedAt: now, PolicyParameters: PolicyActionParameters{AccessDomain: "nas"}}
	}
	err = ops.saveLocked()
	ops.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{operations: ops, nativeActions: runtimes}
	stage := policy.Execution{Stages: []policy.StageState{{ActionIDs: actionIDs}}}
	s.deliverAction(actionIDs[0], false)
	s.refreshPolicyStagesLocked(&stage, time.Now())
	if drops.Load() != 1 || stage.Stages[0].Status != "partial_success" {
		t.Fatalf("first result: %d %+v %+v", drops.Load(), stage, ops.doc.Actions[actionIDs[0]])
	}
	s.deliverAction(actionIDs[1], false)
	s.refreshPolicyStagesLocked(&stage, time.Now())
	wantStage := "succeeded"
	if rejectSecond {
		wantStage = "partial_success"
	}
	if drops.Load() != 2 || stage.Stages[0].Status != wantStage {
		t.Fatalf("account result: %d %+v %+v", drops.Load(), stage, ops.doc.Actions[actionIDs[1]])
	}
	reopened, err := newOperationsState("", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.db.Close()
	s.operations = reopened
	for _, id := range actionIDs {
		s.deliverAction(id, false)
		expected := "succeeded"
		if rejectSecond && id == actionIDs[1] {
			expected = "pending"
		}
		if reopened.doc.Actions[id].Status != expected {
			t.Fatal("lost completed result")
		}
	}
	if drops.Load() != 2 {
		t.Fatal("restart resent disconnect")
	}
	remaining, err := runtime.Read(ctx)
	wantRemaining := 0
	if rejectSecond {
		wantRemaining = 1
	}
	if err != nil || len(remaining.Rows) != wantRemaining {
		t.Fatal("account sessions remain", err)
	}
}
