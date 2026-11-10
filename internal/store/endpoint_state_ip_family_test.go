package store

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"
)

func TestBuildEndpointStateSelectsAddressFamilies(t *testing.T) {
	now := time.Date(2026, 11, 10, 2, 0, 0, 0, time.UTC)
	in := endpointStateInput{
		ID: "mac:aa:bb:cc:dd:ee:01", MAC: "AA:BB:CC:DD:EE:01",
		Item:    []byte("{\"endpoint_id\":\"mac:aa:bb:cc:dd:ee:01\"}"),
		LeaseIP: "2001:db8::5", LeaseAt: sql.NullTime{Time: now.Add(-time.Minute), Valid: true},
		Sessions: []endpointStateSession{{Account: "a", IP: "192.0.2.10", At: now.Add(-2 * time.Minute)}},
	}
	row, err := buildEndpointState(in, now)
	if err != nil {
		t.Fatal(err)
	}
	var item EndpointDeviceInventory
	if err = json.Unmarshal(row.Item, &item); err != nil {
		t.Fatal(err)
	}
	if item.CurrentIPv4 != "192.0.2.10" {
		t.Fatalf("current IPv4 = %q, want 192.0.2.10", item.CurrentIPv4)
	}
	if item.CurrentIPv6 != "2001:db8::5" {
		t.Fatalf("current IPv6 = %q, want 2001:db8::5", item.CurrentIPv6)
	}
	if row.CurrentIP != "192.0.2.10" {
		t.Fatalf("lookup IP column = %q, want the operational IPv4", row.CurrentIP)
	}
}
