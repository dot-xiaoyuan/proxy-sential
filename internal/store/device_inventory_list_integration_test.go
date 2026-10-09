package store

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"
)

func TestDeviceInventoryReadModelFiltersAndIncrementalDirtyTriggers(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	if _, err := ApplyPostgresMigrations(ctx, dsn, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	store, err := NewPostgresStore(PostgresOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	suffix := time.Now().UTC().Format("150405.000000000")
	endpointID := "test:device-inventory:" + suffix
	eventID := "device-inventory-ip-" + suffix
	accessEventID := "device-inventory-access-" + suffix
	sessionID := "device-inventory-session-" + suffix
	now := time.Now().UTC()
	item := DeviceInventoryListItem{
		EndpointID: endpointID, PrimaryMAC: "00:10:20:30:40:71", CurrentIP: "192.0.2.44",
		CurrentAccount: "inventory-account", CurrentAccessID: "AP-D3-01", LastSeen: now.Format(time.RFC3339Nano),
		Brand: "Dell", Model: "Latitude 7440", DeviceType: "laptop", OSFamily: "Windows 11",
		BrandConfidence: .95, ModelConfidence: .9, DeviceTypeConfidence: .9, OSFamilyConfidence: .92,
		DeviceName: &DeviceName{Value: "inventory-fixture", Source: "manual_note", Manual: true, Status: "current"},
	}
	listRaw, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen) VALUES($1,$2,'endpoint',$3,$3)`, endpointID, item.PrimaryMAC, now); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, table := range []string{"device_name_notes", "account_sessions", "identity_ip_mac_history", "identity_access_history", "endpoint_entities"} {
			_, _ = store.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE endpoint_id=$1`, endpointID)
		}
	}()
	if _, err = store.db.ExecContext(ctx, `INSERT INTO endpoint_recognition_summary(
 endpoint_id,brand,model,os_family,role,confidence,summary,first_seen,last_seen,primary_mac,current_ip,current_account,current_access_id,device_name,filter_brand,filter_os_family,list_item)
 VALUES($1,'Dell','Latitude 7440','Windows 11','laptop',.95,'{}',$2,$2,$3,$4,'inventory-account','AP-D3-01','inventory-fixture','Dell','Windows 11',$5)`, endpointID, now, item.PrimaryMAC, item.CurrentIP, listRaw); err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.ExecContext(ctx, `UPDATE endpoint_recognition_jobs SET processed_generation=dirty_generation WHERE endpoint_id=$1`, endpointID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.ExecContext(ctx, `INSERT INTO device_name_notes(endpoint_id,value,updated_by) VALUES($1,'inventory-renamed','test')`, endpointID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.ExecContext(ctx, `INSERT INTO account_sessions(session_id,account_id,endpoint_id,ip,access_id,source,started_at,identity_confidence,raw_ref,campus_id,department,person_type,ssid,vlan,ap,nas_ip)
 VALUES($1,'inventory-account',$2,'198.51.100.77','AP-D3-01','test',$3,.9,'{}','campus-test','engineering','student','Campus-WiFi','310','AP-D3-01','10.0.0.10')`, sessionID, endpointID, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.ExecContext(ctx, `INSERT INTO identity_ip_mac_history(event_id,endpoint_id,entity_role,ip,mac,source,first_seen,last_seen,identity_confidence) VALUES($1,$2,'endpoint','198.51.100.77',$3,'test',$4,$4,.9)`, eventID, endpointID, item.PrimaryMAC, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.ExecContext(ctx, `INSERT INTO identity_access_history(event_id,endpoint_id,entity_role,access_id,source,first_seen,last_seen,identity_confidence) VALUES($1,$2,'endpoint','AP-D3-01','test',$3,$3,.9)`, accessEventID, endpointID, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	page, err := store.ListDeviceInventory(ctx, Query{View: "recent", Window: "24h", Q: "198.51.100.77", Brand: "dell", OSFamily: "windows 11", CampusID: "campus-test", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if page.Page.Total != 1 || len(page.Items) != 1 || page.Items[0].EndpointID != endpointID {
		t.Fatalf("unexpected filtered inventory: %+v", page)
	}
	if page.Items[0].IPMatch == nil || page.Items[0].IPMatch.IP != "198.51.100.77" || page.Items[0].IPMatch.IsRecentIP {
		t.Fatalf("expected historical IP explanation: %+v", page.Items[0].IPMatch)
	}
	if !page.ReadModelUpdating || page.AsOf == "" {
		t.Fatalf("expected truthful updating state and materialization time: %+v", page)
	}
	if !slices.Contains(page.Facets.Brands, "Dell") || !slices.Contains(page.Facets.OSFamilies, "Windows 11") {
		t.Fatalf("missing global facets: %+v", page.Facets)
	}
	var dirty, processed int64
	if err = store.db.QueryRowContext(ctx, `SELECT dirty_generation,processed_generation FROM endpoint_recognition_jobs WHERE endpoint_id=$1`, endpointID).Scan(&dirty, &processed); err != nil {
		t.Fatal(err)
	}
	if dirty-processed < 4 {
		t.Fatalf("name, session, IP and access changes must dirty the read model: dirty=%d processed=%d", dirty, processed)
	}
}
