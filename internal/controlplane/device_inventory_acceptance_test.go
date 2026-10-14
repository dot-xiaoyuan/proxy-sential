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
	"strconv"
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
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
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
	reuse := os.Getenv("PROXY_SENTINEL_INVENTORY_FIXTURE_PREFIX")
	if reuse != "" {
		if !strings.HasPrefix(reuse, "inventory-bench-") || !strings.HasSuffix(reuse, ":") || strings.ContainsAny(reuse, "%_ '") {
			t.Fatal("invalid owned fixture prefix")
		}
		prefix = reuse
	}
	scale := os.Getenv("PROXY_SENTINEL_INVENTORY_SCALE") == "1"
	readyFixture := os.Getenv("PROXY_SENTINEL_INVENTORY_FIXTURE_READY") == "1"
	identities := 35001
	indexes := map[string]string{}
	if scale && !readyFixture {
		// Test-only generation: save and temporarily detach non-constraint raw
		// indexes in this owned database, then restore ALL definitions before measuring.
		if _, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS inventory_fixture_index_restore(index_name text PRIMARY KEY,index_sql text NOT NULL)`); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `INSERT INTO inventory_fixture_index_restore SELECT i.indexname,i.indexdef FROM pg_indexes i LEFT JOIN pg_constraint c ON c.conindid=to_regclass(i.schemaname||'.'||i.indexname) WHERE i.tablename='identity_ip_mac_history' AND c.oid IS NULL ON CONFLICT DO NOTHING`); err != nil {
			t.Fatal(err)
		}
		indexRows, e := db.QueryContext(ctx, `SELECT index_name,index_sql FROM inventory_fixture_index_restore`)
		if e != nil {
			t.Fatal(e)
		}
		for indexRows.Next() {
			var name, definition string
			if e = indexRows.Scan(&name, &definition); e != nil {
				t.Fatal(e)
			}
			indexes[name] = definition
		}
		e = indexRows.Err()
		indexRows.Close()
		if e != nil {
			t.Fatal(e)
		}
		for name := range indexes {
			if _, e = db.ExecContext(ctx, `DROP INDEX IF EXISTS `+strconv.Quote(name)); e != nil {
				t.Fatal(e)
			}
		}
		identities = 70001
	}
	if scale {
		identities = 70001
	}
	defer func() {
		if scale {
			return
		} // Owned scale fixture retained for EXPLAIN and repeatable audit.
		for _, table := range []string{"account_sessions", "identity_ip_mac_history", "identity_access_history", "endpoint_entities", "endpoint_inventory_lookup", "endpoint_inventory_accounts", "endpoint_inventory_sessions", "endpoint_inventory_ip_points", "endpoint_inventory_associations", "endpoint_inventory_projection_jobs"} {
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
		if reuse != "" {
			continue
		}
		if scale {
			statement = strings.ReplaceAll(statement, "35001", "70001")
		}
		if _, err = db.ExecContext(ctx, statement, prefix); err != nil {
			t.Fatal(err)
		}
	}
	if scale && !readyFixture {
		// This owned fixture has no production materializer. Suppress notification
		// triggers only while generating ten million repeated historical points.
		if _, err = db.ExecContext(ctx, `ALTER TABLE identity_ip_mac_history DISABLE TRIGGER USER`); err != nil {
			t.Fatal(err)
		}
		defer db.ExecContext(context.Background(), `ALTER TABLE identity_ip_mac_history ENABLE TRIGGER USER`)
		for batch := 0; batch < 20; batch++ {
			var complete bool
			if err = db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM identity_ip_mac_history WHERE event_id=$1)`, prefix+":scale:"+strconv.Itoa((batch+1)*500000)).Scan(&complete); err != nil {
				t.Fatal(err)
			}
			if complete {
				continue
			}
			if _, err = db.ExecContext(ctx, `INSERT INTO identity_ip_mac_history(event_id,endpoint_id,entity_role,ip,source,first_seen,last_seen,identity_confidence)
			SELECT $1||':scale:'||n,$1||((n%70001)+1),'endpoint','198.51.100.200','scale',now()-interval '3 days',now()-interval '3 days',.8 FROM generate_series($2::bigint,$3::bigint)n`, prefix, batch*500000+1, (batch+1)*500000); err != nil {
				t.Fatal(err)
			}
			t.Logf("isolated history fixture: %d/10000000", (batch+1)*500000)
		}
		if _, err = db.ExecContext(ctx, `ALTER TABLE identity_ip_mac_history ENABLE TRIGGER USER`); err != nil {
			t.Fatal(err)
		}
		conn, e := db.Conn(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = conn.ExecContext(ctx, `SET maintenance_work_mem='512MB'`); e != nil {
			t.Fatal(e)
		}
		for name, definition := range indexes {
			t.Logf("restoring owned fixture index %s", name)
			if _, e = conn.ExecContext(ctx, strings.Replace(definition, "CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ", 1)); e != nil {
				conn.Close()
				t.Fatal(e)
			}
		}
		conn.Close()
	}
	// Prepared compact model is the benchmark prerequisite. Replay correctness
	// and worker backfill are exercised separately by database replay tests.
	prepared := []string{
		`INSERT INTO endpoint_inventory_lookup(endpoint_id,list_item,last_seen,mac_key,current_ip,search_text) SELECT endpoint_id,list_item,last_seen,'001020304050',current_ip::inet,lower(endpoint_id||' student-1') FROM endpoint_recognition_summary WHERE endpoint_id LIKE $1 ON CONFLICT DO NOTHING`,
		`INSERT INTO endpoint_inventory_accounts SELECT endpoint_id,CASE WHEN endpoint_id IN(SELECT endpoint_id FROM endpoint_inventory_lookup WHERE endpoint_id LIKE $1 ORDER BY endpoint_id LIMIT 20) THEN 'student-sparse' ELSE 'student-1' END,now() FROM endpoint_inventory_lookup WHERE endpoint_id LIKE $1 ON CONFLICT DO NOTHING`,
		`UPDATE endpoint_inventory_lookup i SET list_item=jsonb_set(i.list_item,'{current_account}',to_jsonb(a.account_id)) FROM endpoint_inventory_accounts a WHERE i.endpoint_id=a.endpoint_id AND i.endpoint_id LIKE $1 AND i.list_item->>'current_account' IS DISTINCT FROM a.account_id`,
		`INSERT INTO endpoint_inventory_ip_points SELECT endpoint_id,ip,max(last_seen),source FROM identity_ip_mac_history WHERE endpoint_id LIKE $1 GROUP BY endpoint_id,ip,source ON CONFLICT DO NOTHING`,
		`UPDATE endpoint_inventory_projection_state SET ready=true,backfill_complete=true,snapshot_backfill_complete=true`,
	}
	for _, statement := range prepared {
		var args []any
		if strings.Contains(statement, "$1") {
			args = []any{prefix + "%"}
		}
		if _, err = db.ExecContext(ctx, statement, args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.ExecContext(ctx, `ANALYZE endpoint_inventory_lookup; ANALYZE endpoint_inventory_accounts; ANALYZE endpoint_inventory_ip_points`); err != nil {
		t.Fatal(err)
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
		store.InventoryTraceReader
	}{server.reader, pg, pg, pg}
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
	if err != nil || metadata.Total < identities {
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
	for _, filter := range []string{"search_type=account&q=student-sparse", "search_type=account&q=no-such-account", "search_type=ip&q=198.51.100.77", "search_type=ip&q=203.0.113.254"} {
		d, _, _, e := request(target + "&refresh=true&" + filter)
		if e != nil || d > time.Second {
			t.Fatalf("uncached %s: %v %v", strings.Split(filter, "&")[0], d, e)
		}
		t.Logf("local indexed %s cache-bypass: %v", strings.Split(filter, "&")[0], d)
		durations := make([]time.Duration, 200)
		failures := make(chan error, 200)
		var group sync.WaitGroup
		for client := 0; client < 20; client++ {
			group.Add(1)
			go func(client int) {
				defer group.Done()
				for i := client; i < 200; i += 20 {
					duration, _, _, err := request(target + "&" + filter)
					durations[i] = duration
					if err != nil {
						failures <- err
					}
				}
			}(client)
		}
		group.Wait()
		close(failures)
		for err := range failures {
			t.Fatal(err)
		}
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		t.Logf("local indexed %s 20-concurrent warm: p50=%v p95=%v p99=%v", strings.Split(filter, "&")[0], durations[99], durations[189], durations[197])
		if durations[189] > 500*time.Millisecond {
			t.Fatal("indexed warm p95 exceeded 500ms")
		}
	}
	server.deviceInventory = newDeviceInventoryPageCache(5 * time.Second)
	expired, _, _, err := request(target)
	if err != nil {
		t.Fatal(err)
	}
	// Prefer a genuinely materialized replay terminal, not a synthetically
	// prepared list-only benchmark row, for the detail/trace acceptance check.
	var detailID string
	if e := db.QueryRowContext(ctx, `SELECT endpoint_id FROM endpoint_inventory_associations WHERE endpoint_id NOT LIKE $1 ORDER BY endpoint_id LIMIT 1`, prefix+"%").Scan(&detailID); e == nil {
		detailDuration, _, _, e := request("/api/v1/device-inventory/" + url.PathEscape(detailID))
		if e != nil || detailDuration > time.Second {
			t.Fatalf("prepared detail: %v %v", detailDuration, e)
		}
		traceDuration, _, _, e := request("/api/v1/endpoints/" + url.PathEscape(detailID) + "/observations?kind=ip&limit=20")
		if e != nil || traceDuration > time.Second {
			t.Fatalf("indexed trace: %v %v", traceDuration, e)
		}
		t.Logf("local prepared detail=%v indexed trace first 20=%v", detailDuration, traceDuration)
	}
	t.Logf("local isolated PostgreSQL: identities=%d scale_history=%t uncached=%v cache-reset=%v metadata=%v payload=%dB; no field network/authentication measured", identities, scale, cold, expired, metadataDuration, bytes)
}

type inventoryAcceptanceError struct{ message string }

func (e *inventoryAcceptanceError) Error() string { return e.message }
