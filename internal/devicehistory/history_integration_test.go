package devicehistory

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib"
	"os"
	"testing"
	"time"
)

func TestConsecutiveHistoryPagination(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires test PostgreSQL")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	_, err = db.Exec(`CREATE TEMP TABLE discovery_observations(id text,device_key text,source_id text,origin text,observed_at timestamptz,data jsonb)`)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Hour)
	// Repeated renewals collapse; IP reuse by another device and another scope
	// never joins this identity. A/B/A, withdrawal and a rule change remain.
	for i, state := range []string{"A", "A", "B", "A", "A", "withdrawn", "rule2"} {
		payload := map[string]any{"ip": "192.0.2.1", "mac": "00:11:22:33:44:55", "name": state, "rule_version": "v1", "origin": "dhcp", "observed_at": at.Add(time.Duration(i) * time.Second), "valid_until": at.Add(time.Duration(i)*time.Second + time.Hour), "id": fmt.Sprint(i), "event_id": fmt.Sprint(i)}
		if state == "withdrawn" {
			payload["name"] = "A"
			payload["withdrawn"] = true
		}
		if state == "rule2" {
			payload["name"] = "A"
			payload["rule_version"] = "v2"
		}
		data, _ := json.Marshal(payload)
		_, err = db.Exec(`INSERT INTO discovery_observations VALUES($1,'device-a','scope-a','dhcp',$2,$3)`, fmt.Sprint(i), at.Add(time.Duration(i)*time.Second), data)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = db.Exec(`INSERT INTO discovery_observations VALUES('other','device-b','scope-b','dhcp',$1,'{"ip":"192.0.2.1"}'),('dns','device-a','scope-a','dns_sd',$1,'{"capabilities":["printing"],"origin":"dns_sd"}')`, at)
	if err != nil {
		t.Fatal(err)
	}
	q := Query{Kind: "discovery", Keys: []string{"device-a"}, Limit: 2, AsOf: time.Now().UTC()}
	first, err := Read(ctx, db, q)
	if err != nil {
		t.Fatal(err)
	}
	if first.Total != 6 || len(first.Items) != 2 {
		t.Fatalf("bad first page: %+v", first)
	}
	q.Offset = 2
	second, err := Read(ctx, db, q)
	if err != nil {
		t.Fatal(err)
	}
	if second.Total != 6 || len(second.Items) != 2 || second.Items[0].Count != 2 {
		t.Fatalf("A return not preserved: %+v", second)
	}
	q.Offset = 0
	q.Group = second.Items[0].ID
	q.Limit = 1
	raw, err := Read(ctx, db, q)
	if err != nil {
		t.Fatal(err)
	}
	if raw.Total != 2 || len(raw.Items) != 1 || raw.Items[0].Content == nil {
		t.Fatalf("raw unavailable: %+v", raw)
	}
	q.Group = ""
	q.Offset = 999
	empty, err := Read(ctx, db, q)
	if err != nil || empty.Total != 6 || len(empty.Items) != 0 {
		t.Fatalf("empty-page total lost: %+v %v", empty, err)
	}
}

func TestAllHistorySourcesPostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires test PostgreSQL")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TEMP TABLE router_assessment_history(history_id bigint,changed_at timestamptz,assessment_id text,status text,confidence int,rule_version text,conflicts jsonb);
 CREATE TEMP TABLE shared_device_profile_history(history_id bigint,observed_at timestamptz,profile_id text,payload jsonb);
 CREATE TEMP TABLE shared_behavior_observations(observation_id text,sensor_id text,campus_id text,access_domain text,ip inet);
 CREATE TEMP TABLE shared_behavior_observation_history(history_id bigint,observation_id text,observed_at timestamptz,observation jsonb);
 CREATE TEMP TABLE identity_ip_mac_history(history_id bigint,last_seen timestamptz,endpoint_id text,source text,ip inet,mac text,account_id text,entity_role text);
 CREATE TEMP TABLE identity_access_history(history_id bigint,last_seen timestamptz,endpoint_id text,source text,access_id text,account_id text,ap text,switch_id text,switch_port text,vlan text);
 INSERT INTO shared_behavior_observations VALUES('id','s','c','d','192.0.2.1');`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		rule := "v1"
		if i == 3 {
			rule = "v2"
		}
		at := time.Now().Add(time.Duration(i-10) * time.Second)
		_, err = db.Exec(`INSERT INTO router_assessment_history VALUES($1,$2,'id','confirmed',90,$3,'[]')`, i, at, rule)
		if err != nil {
			t.Fatal(err)
		}
		raw := fmt.Sprintf(`{"ip":"192.0.2.1","latest_account_id":"student","rule_version":%q,"last_observed_at":%q}`, rule, at.Format(time.RFC3339Nano))
		for _, table := range []string{"shared_device_profile_history", "shared_behavior_observation_history"} {
			_, err = db.Exec(`INSERT INTO `+table+` VALUES($1,`+map[string]string{"shared_device_profile_history": "$2,'id'", "shared_behavior_observation_history": "'id',$2"}[table]+`,$3)`, i, at, raw)
			if err != nil {
				t.Fatal(err)
			}
		}
		_, err = db.Exec(`INSERT INTO identity_ip_mac_history VALUES($1,$2,'id','dhcp','192.0.2.1','mac','student','endpoint');`, i, at)
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec(`INSERT INTO identity_access_history VALUES($1,$2,'id','auth','ap-1','student','ap-1','','','1');`, i, at)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []string{"router", "profile", "shared", "endpoint", "access"} {
		page, err := Read(context.Background(), db, Query{Kind: kind, ID: "id"})
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		want := 2
		if kind == "endpoint" || kind == "access" {
			want = 1
		}
		if page.Total != want {
			t.Fatalf("%s: %d", kind, page.Total)
		}
	}
}
