package store

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"
)

// The endpoint state row must carry what the terminal list shows: the latest account and
// access from current sessions, the latest IP from sessions or DHCP, the manual name over
// the observed one, and dimensions from the newest session.
func TestBuildEndpointStateComposesCurrentAssociations(t *testing.T) {
	now := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	in := endpointStateInput{
		ID: "mac:aa:bb:cc:dd:ee:ff", MAC: "AA:BB:CC:DD:EE:FF", Name: "实验室打印机", Manual: true,
		Item:    []byte(`{"endpoint_id":"mac:aa:bb:cc:dd:ee:ff","brand":"HP","brand_confidence":0.9}`),
		Seen:    sql.NullTime{Time: now.Add(-30 * time.Minute), Valid: true},
		LeaseIP: "10.0.0.9", LeaseAt: sql.NullTime{Time: now.Add(-2 * time.Minute), Valid: true},
		Sessions: []endpointStateSession{
			{Account: "old", Access: "AP-1", IP: "10.0.0.5", At: now.Add(-50 * time.Minute), Dimensions: map[string]string{"ssid": "old"}},
			{Account: "20260001", Access: "AP-2", IP: "10.0.0.6", At: now.Add(-5*time.Minute - 17*time.Second), Dimensions: map[string]string{"ssid": "NCU", "vlan": "12"}},
		},
	}
	row, err := buildEndpointState(in, now)
	if err != nil {
		t.Fatal(err)
	}
	var item EndpointDeviceInventory
	if err = json.Unmarshal(row.Item, &item); err != nil {
		t.Fatal(err)
	}
	if item.CurrentAccount != "20260001" || item.CurrentAccessID != "AP-2" {
		t.Fatalf("latest session not chosen: account=%q access=%q", item.CurrentAccount, item.CurrentAccessID)
	}
	if item.CurrentIP != "10.0.0.9" || row.CurrentIP != "10.0.0.9" {
		t.Fatalf("newer DHCP lease IP not chosen: %q", item.CurrentIP)
	}
	if item.DeviceName == nil || item.DeviceName.Value != "实验室打印机" || !item.DeviceName.Manual {
		t.Fatalf("manual name lost: %+v", item.DeviceName)
	}
	if row.LastSeen == nil || !row.LastSeen.Equal(now.Add(-2*time.Minute)) {
		t.Fatalf("last_seen must be the newest observation at minute precision: %v", row.LastSeen)
	}
	var dims map[string]string
	_ = json.Unmarshal(row.Dimensions, &dims)
	if dims["ssid"] != "NCU" || dims["vlan"] != "12" {
		t.Fatalf("dimensions not from newest session: %v", dims)
	}
	if row.MACKey != "aabbccddeeff" || len(row.Accounts) != 1 {
		t.Fatalf("lookup keys wrong: %q %v", row.MACKey, row.Accounts)
	}
}

func TestBuildEndpointStateWithoutSessionsKeepsRecognition(t *testing.T) {
	now := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	row, err := buildEndpointState(endpointStateInput{ID: "mac:01", MAC: "01", Item: []byte(`{"brand":"Huawei"}`)}, now)
	if err != nil {
		t.Fatal(err)
	}
	var item EndpointDeviceInventory
	_ = json.Unmarshal(row.Item, &item)
	if item.Brand != "Huawei" || item.CurrentAccount != "" || row.LastSeen != nil || string(row.Dimensions) != "{}" {
		t.Fatalf("unexpected row: %+v %s", item, row.Dimensions)
	}
}
