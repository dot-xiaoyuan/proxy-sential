package store

import (
	"testing"

	"proxy-sentinel/internal/normalized"
)

func TestEndpointRecentIPReplay(t *testing.T) {
	state := BuildIdentityState([]normalized.Event{
		identityStoreEvent("old-ip", "account-a", "10.0.0.1", "aa:bb:cc:dd:ee:01", "ap-a", "endpoint", "session-a", "2026-09-17T10:00:00Z"),
		identityStoreEvent("new-ip", "account-a", "10.0.0.9", "aa:bb:cc:dd:ee:01", "ap-a", "endpoint", "session-a", "2026-09-17T11:00:00Z"),
		identityStoreEvent("reused-ip", "account-b", "10.0.0.9", "aa:bb:cc:dd:ee:02", "ap-a", "endpoint", "session-b", "2026-09-17T12:00:00Z"),
	})
	items := BuildEndpointDeviceInventories(state, Query{})
	if len(items) != 2 {
		t.Fatalf("IP reuse must preserve two endpoint identities: %+v", items)
	}
	for _, item := range items {
		if item.CurrentIP != "10.0.0.9" {
			t.Fatalf("expected most recently observed IP, got %+v", item)
		}
	}
}

func TestEndpointRecentIPOrdering(t *testing.T) {
	tests := []struct {
		name    string
		history []IdentityIPMACHistory
		want    string
	}{
		{"empty", nil, ""},
		{"first seen breaks tie", []IdentityIPMACHistory{
			{IP: "10.0.0.1", LastSeen: "2026-09-17T12:00:00Z", FirstSeen: "2026-09-17T10:00:00Z"},
			{IP: "10.0.0.9", LastSeen: "2026-09-17T12:00:00Z", FirstSeen: "2026-09-17T11:00:00Z"},
		}, "10.0.0.9"},
		{"IP breaks equal time tie", []IdentityIPMACHistory{
			{IP: "10.0.0.9", LastSeen: "2026-09-17T12:00:00Z", FirstSeen: "2026-09-17T10:00:00Z"},
			{IP: "10.0.0.1", LastSeen: "2026-09-17T12:00:00Z", FirstSeen: "2026-09-17T10:00:00Z"},
		}, "10.0.0.1"},
		{"timestamps compare instants", []IdentityIPMACHistory{
			{IP: "10.0.0.1", LastSeen: "2026-09-17T12:00:00+08:00"},
			{IP: "10.0.0.9", LastSeen: "2026-09-17T05:00:00Z"},
		}, "10.0.0.9"},
		{"ignore blank IP", []IdentityIPMACHistory{
			{LastSeen: "2026-09-17T12:00:00Z"},
			{IP: "10.0.0.9", LastSeen: "2026-09-17T11:00:00Z"},
		}, "10.0.0.9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := BuildEndpointDeviceInventory(EndpointIdentityProfile{IPHistory: tt.history})
			if item.CurrentIP != tt.want {
				t.Fatalf("recent IP = %q, want %q", item.CurrentIP, tt.want)
			}
		})
	}
}
