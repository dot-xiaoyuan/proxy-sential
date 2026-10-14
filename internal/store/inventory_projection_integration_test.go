package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestInventoryIndexedProjectionReplay(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id := "inventory-replay:" + time.Now().Format("150405.000000000")
	defer func() {
		for _, table := range []string{"identity_ip_mac_history", "identity_access_history", "account_sessions", "endpoint_entities", "endpoint_inventory_lookup", "endpoint_inventory_accounts", "endpoint_inventory_sessions", "endpoint_inventory_ip_points", "endpoint_inventory_associations", "endpoint_inventory_projection_jobs"} {
			_, _ = s.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE endpoint_id=$1`, id)
		}
	}()
	at := time.Now().UTC().Add(-time.Minute)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := s.db.ExecContext(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,last_seen) VALUES($1,'aa:bb:cc:dd:ee:fe','endpoint',$2)`, id, at)
	raw, _ := json.Marshal(DeviceInventoryListItem{EndpointID: id, CurrentAccount: "a-old", CurrentIP: "192.0.2.1", LastSeen: at.Format(time.RFC3339Nano)})
	exec(`INSERT INTO endpoint_recognition_summary(endpoint_id,last_seen,list_item,device_name) VALUES($1,$2,$3,'Desk-A')`, id, at, raw)
	exec(`INSERT INTO identity_ip_mac_history(event_id,endpoint_id,account_id,ip,source,first_seen,last_seen,identity_confidence)
 VALUES($1,$2,'a-old','192.0.2.1','replay',$3,$3,.8),($4,$2,'z-latest','192.0.2.2','replay',$5,$5,.9)`, id+":old", id, at.Add(-48*time.Hour), id+":new", at)
	prepare := func() {
		t.Helper()
		for i := 0; i < 20; i++ {
			if more, e := s.backfillInventoryBatch(ctx, 2000); e != nil {
				t.Fatal(e)
			} else if !more {
				break
			}
		}
		for i := 0; i < 10000; i++ {
			if done, e := s.materializeNextInventory(ctx); e != nil {
				t.Fatal(e)
			} else if !done {
				break
			}
		}
		exec(`UPDATE endpoint_inventory_projection_state SET ready=true`)
	}
	prepare()
	search := func(kind, value, view string) DeviceInventoryListPage {
		t.Helper()
		p, e := s.ListDeviceInventory(ctx, Query{InventorySearchType: kind, Q: value, View: view, Window: "24h", Limit: 20, InventorySkipMetadata: true})
		if e != nil {
			t.Fatal(e)
		}
		items := []DeviceInventoryListItem{}
		for _, item := range p.Items {
			if item.EndpointID == id {
				items = append(items, item)
			}
		}
		p.Items = items
		return p
	}
	if p := search("account", "a-old", "history"); len(p.Items) != 0 {
		t.Fatal("historical account leaked into current list")
	}
	if p := search("account", "z-latest", "recent"); len(p.Items) != 1 || p.Items[0].CurrentAccount != "z-latest" {
		t.Fatalf("latest: %+v", p)
	}
	if len(search("account", "Z-LATEST", "history").Items) != 0 {
		t.Fatal("account case was folded")
	}
	if len(search("mac", "AA-BB-CC-DD-EE-FE", "recent").Items) != 1 {
		t.Fatal("MAC canonical exact failed")
	}
	if len(search("name", "desk-a", "recent").Items) != 1 {
		t.Fatal("case-insensitive name failed")
	}
	if len(search("ip", "192.0.2.1", "recent").Items) != 0 {
		t.Fatal("old observation became a continuous interval")
	}
	p := search("ip", "192.0.2.1", "history")
	if len(p.Items) != 1 || p.Items[0].IPMatch == nil || p.Items[0].IPMatch.IsRecentIP {
		t.Fatal("historical IP explanation missing")
	}
	// Same instant: two candidates, neither arbitrarily represented as certain.
	exec(`INSERT INTO identity_access_history(event_id,endpoint_id,account_id,access_id,source,first_seen,last_seen,identity_confidence) VALUES($1,$2,'parallel','AP-Z','replay',$3,$3,.8)`, id+":tie", id, at)
	prepare()
	p = search("account", "parallel", "recent")
	if len(p.Items) != 1 || !p.Items[0].CurrentAccountConflict || p.Items[0].CurrentAccount != "" {
		t.Fatal("tie not retained")
	}
	// Replay duplicate event updates and late old observations leave count/latest correct.
	exec(`UPDATE identity_ip_mac_history SET identity_confidence=.91 WHERE event_id=$1`, id+":new")
	exec(`INSERT INTO identity_ip_mac_history(event_id,endpoint_id,account_id,ip,source,first_seen,last_seen) VALUES($1,$2,'a-old','192.0.2.1','replay',$3,$3)`, id+":late", id, at.Add(-72*time.Hour))
	prepare()
	if len(search("account", "a-old", "history").Items) != 0 {
		t.Fatal("late event overwrote latest")
	}
	detail, found, err := s.GetDeviceInventoryDetail(ctx, id)
	if err != nil || !found || !detail.State.Complete || len(detail.Profile.IPHistory) != 0 {
		t.Fatalf("slim detail: %+v %v", detail, err)
	}
	// Over 500 records; real backend keysets, no giant frontend history response.
	exec(`INSERT INTO identity_ip_mac_history(event_id,endpoint_id,ip,source,first_seen,last_seen)
 SELECT $1||':page:'||n,$1,'198.51.100.90','page',$2::timestamptz-n*interval '1 second',$2::timestamptz-n*interval '1 second' FROM generate_series(1,601)n`, id, at)
	prepare()
	seen := map[string]bool{}
	cursor := ""
	for n := 0; n < 40; n++ {
		page, e := s.ListEndpointObservations(ctx, id, EndpointObservationQuery{Kind: "ip", Value: "198.51.100.90", Cursor: cursor, Limit: 20})
		if e != nil {
			t.Fatal(e)
		}
		for _, v := range page.Items {
			if seen[v.RecordID] {
				t.Fatal("duplicate cursor record")
			}
			seen[v.RecordID] = true
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(seen) != 601 {
		t.Fatalf("cursor history truncated: %d", len(seen))
	}
	// Only actual authentication evidence supplies a closed interval. It remains
	// endpoint-scoped and reachable as an original session, never a fabricated event.
	exec(`INSERT INTO account_sessions(session_id,account_id,endpoint_id,ip,source,started_at,ended_at,identity_confidence) VALUES($1,'old-auth',$2,'198.51.100.240','replay-auth',$3,$4,.9)`, id+"/+session", id, at.Add(-time.Hour), at.Add(-30*time.Minute))
	prepare()
	if len(search("account", "old-auth", "history").Items) != 0 {
		t.Fatal("historical auth account leaked into latest account search")
	}
	if p := search("ip", "198.51.100.240", "recent"); len(p.Items) != 1 || p.Items[0].IPMatch == nil || p.Items[0].IPMatch.Source != "account_session" {
		t.Fatal("explicit session interval lost its historical IP match")
	}
	auth, e := s.ListEndpointObservations(ctx, id, EndpointObservationQuery{Kind: "ip", Value: "198.51.100.240", Limit: 20})
	if e != nil || len(auth.Items) != 1 || auth.Items[0].StartedAt == "" || auth.Items[0].EndedAt == "" || auth.Items[0].EvidenceURL == "" || auth.Items[0].EventID != "" {
		t.Fatalf("authentication interval trace: %+v %v", auth, e)
	}
	if v, found, e := s.GetInventorySessionEvidence(ctx, id, auth.Items[0].RecordID); e != nil || !found || v.SessionID != id+"/+session" {
		t.Fatal("original session evidence missing", e)
	}
	if _, found, e := s.GetInventorySessionEvidence(ctx, "other", auth.Items[0].RecordID); e != nil || found {
		t.Fatal("cross-endpoint session leaked")
	}
	// SQL list relation is protected against accidental reintroduction of raw history.
	var plan string
	err = s.db.QueryRowContext(ctx, `EXPLAIN (FORMAT JSON) SELECT endpoint_id FROM endpoint_inventory_accounts WHERE account_id=$1`, "z-latest").Scan(&plan)
	if err != nil || strings.Contains(plan, "identity_ip_mac_history") || strings.Contains(plan, "account_sessions") {
		t.Fatal("raw table in list plan", err)
	}
}

func TestInventoryCursorBindsEndpointAndFilters(t *testing.T) {
	q := EndpointObservationQuery{Kind: "ip", Value: "192.0.2.1", Limit: 20}
	c, _ := observationPosition("a", q)
	c.At = time.Now().Format(time.RFC3339Nano)
	c.Key = "ip:1"
	raw, _ := json.Marshal(c)
	q.Cursor = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := observationPosition("a", q); err != nil {
		t.Fatal(err)
	}
	if _, err := observationPosition("b", q); err == nil {
		t.Fatal("cross-endpoint cursor accepted")
	}
	q.Value = "192.0.2.2"
	if _, err := observationPosition("a", q); err == nil {
		t.Fatal("changed filter accepted")
	}
}
