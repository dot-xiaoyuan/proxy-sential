package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"proxy-sentinel/internal/store"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Only opt in against an owned isolated test database, never a field database.
func TestDeviceInventoryLargeReadModelAcceptance(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("owned isolated PostgreSQL required")
	}
	u, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(u.Path, "/sentinel_acceptance_") {
		t.Fatal("requires an owned sentinel_acceptance_ database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err = store.ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	prefix := "inventory-bench-" + time.Now().Format("150405.000000000") + ":"
	defer func() {
		for _, table := range []string{"account_sessions", "identity_ip_mac_history", "identity_access_history", "endpoint_entities"} {
			_, _ = db.ExecContext(context.Background(), "DELETE FROM "+table+" WHERE endpoint_id LIKE $1", prefix+"%")
		}
	}()
	seed := []string{
		`INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen) SELECT $1||n,'00:10:20:30:40:50','endpoint',now(),now() FROM generate_series(1,35001) n`,
		`INSERT INTO endpoint_recognition_summary(endpoint_id,brand,model,os_family,role,confidence,summary,first_seen,last_seen,primary_mac,current_ip,current_account,current_access_id,filter_brand,filter_os_family,list_item)
   SELECT $1||n,'Dell','Latitude 7440','Windows 11','laptop',.95,'{}',now(),now(),'00:10:20:30:40:50','192.0.2.44','student-1','AP-D3-01','Dell','Windows 11',
   jsonb_build_object('endpoint_id',$1||n,'primary_mac','00:10:20:30:40:50','current_ip','192.0.2.44','current_account','student-1','current_access_id','AP-D3-01','brand','Dell','brand_confidence',.95,'device_type','laptop','device_type_confidence',.95,'os_family','Windows 11','os_family_confidence',.95,'last_seen',now()) FROM generate_series(1,35001) n`,
		`INSERT INTO account_sessions(session_id,account_id,endpoint_id,ip,access_id,source,started_at,ended_at,identity_confidence,raw_ref,campus_id) SELECT $1||'session:'||n||':'||h,'student-1',$1||n,'198.51.100.77','AP-D3-01','test',now()-interval '1 hour',now()-interval '10 minutes',.9,'{}','campus-test' FROM generate_series(1,20)n CROSS JOIN generate_series(1,250)h`,
		`INSERT INTO identity_ip_mac_history(event_id,endpoint_id,entity_role,ip,mac,source,first_seen,last_seen,identity_confidence) SELECT $1||'ip:'||n||':'||h,$1||n,'endpoint','198.51.100.77','00:10:20:30:40:50','test',now()-interval '1 hour',now()-interval '10 minutes',.9 FROM generate_series(1,20)n CROSS JOIN generate_series(1,250)h`,
		`INSERT INTO identity_access_history(event_id,endpoint_id,entity_role,access_id,source,first_seen,last_seen,identity_confidence) SELECT $1||'access:'||n||':'||h,$1||n,'endpoint','AP-D3-01','test',now()-interval '1 hour',now()-interval '10 minutes',.9 FROM generate_series(1,20)n CROSS JOIN generate_series(1,250)h`,
	}
	for _, statement := range seed {
		if _, err = db.ExecContext(ctx, statement, prefix); err != nil {
			t.Fatal(err)
		}
	}
	pg, err := store.NewPostgresStore(store.PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	server := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	server.reader = struct {
		store.Reader
		store.DeviceInventoryReader
		store.RouterObservationSummaryReader
	}{server.reader, pg, pg}
	target := "/api/v1/device-inventory?view=recent&window=24h&limit=20&include_metadata=false"
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	client := &http.Client{Timeout: 30 * time.Second}
	request := func(path string) (time.Duration, int, string, error) {
		start := time.Now()
		response, err := client.Get(httpServer.URL + path)
		if err != nil {
			return time.Since(start), 0, "", err
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			return time.Since(start), 0, "", err
		}
		if response.StatusCode != 200 {
			return time.Since(start), len(raw), string(raw), &inventoryAcceptanceError{string(raw)}
		}
		return time.Since(start), len(raw), string(raw), nil
	}
	cold, bytes, body, err := request(target)
	if err != nil {
		t.Fatal(err)
	}
	if bytes > 80*1024 {
		t.Fatalf("payload %d > 80KB", bytes)
	}
	if strings.Contains(body, `"accounts"`) || strings.Contains(body, `"ips"`) || strings.Contains(body, `"access_ids"`) {
		t.Fatal("detail histories leaked")
	}
	if cold > time.Second {
		t.Fatalf("uncached list %v > 1s", cold)
	}
	metadataDuration, _, metadataBody, err := request("/api/v1/device-inventory/metadata?view=recent&window=24h")
	var metadata struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal([]byte(metadataBody), &metadata)
	if err != nil || metadata.Total < 35001 {
		t.Fatalf("metadata: %s %v", metadataBody, err)
	}
	_, _, ipBody, err := request(target + "&q=198.51.100.77")
	var historical DeviceInventoryListResponse
	_ = json.Unmarshal([]byte(ipBody), &historical)
	if err != nil || len(historical.Items) != 20 || historical.Items[0].IPMatch == nil || historical.Items[0].IPMatch.IsRecentIP {
		t.Fatalf("historical match: %s %v", ipBody, err)
	}
	for _, mode := range []string{"serial", "20-concurrent"} {
		durations := make([]time.Duration, 200)
		failures := make(chan error, 200)
		clients := 1
		if mode == "20-concurrent" {
			clients = 20
		}
		var group sync.WaitGroup
		for client := 0; client < clients; client++ {
			group.Add(1)
			go func(client int) {
				defer group.Done()
				for i := client; i < 200; i += clients {
					d, _, _, e := request(target)
					durations[i] = d
					if e != nil {
						failures <- e
					}
				}
			}(client)
		}
		group.Wait()
		close(failures)
		for e := range failures {
			t.Fatal(e)
		}
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		t.Logf("local %s: p50=%v p95=%v p99=%v", mode, durations[99], durations[189], durations[197])
		if durations[189] > 500*time.Millisecond {
			t.Fatalf("local warm p95 %v > 500ms", durations[189])
		}
	}
	server.deviceInventory = newDeviceInventoryPageCache(5 * time.Second)
	expired, _, _, err := request(target)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("local isolated PostgreSQL: identities=35001 history=15000 uncached=%v cache-reset=%v metadata=%v payload=%dB; no field network/authentication measured", cold, expired, metadataDuration, bytes)
}

type inventoryAcceptanceError struct{ message string }

func (e *inventoryAcceptanceError) Error() string { return e.message }
