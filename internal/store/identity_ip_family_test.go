package store

import "testing"

func TestRecentEndpointIPFamilySeparatesFamilies(t *testing.T) {
	history := []IdentityIPMACHistory{
		{IP: "2001:db8::1", LastSeen: "2026-11-09T10:00:00Z", FirstSeen: "2026-11-09T09:00:00Z"},
		{IP: "192.0.2.10", LastSeen: "2026-11-09T09:30:00Z", FirstSeen: "2026-11-09T08:00:00Z"},
	}
	if got := recentEndpointIP(history); got != "2001:db8::1" {
		t.Fatalf("most recent address = %q, want 2001:db8::1", got)
	}
	if got := recentEndpointIPFamily(history, 4); got != "192.0.2.10" {
		t.Fatalf("recent IPv4 = %q, want 192.0.2.10", got)
	}
	if got := recentEndpointIPFamily(history, 6); got != "2001:db8::1" {
		t.Fatalf("recent IPv6 = %q, want 2001:db8::1", got)
	}
}

func TestRecentEndpointIPFamilyReturnsEmptyForMissingFamily(t *testing.T) {
	history := []IdentityIPMACHistory{
		{IP: "2001:db8::2", LastSeen: "2026-11-09T10:00:00Z", FirstSeen: "2026-11-09T09:00:00Z"},
	}
	if got := recentEndpointIPFamily(history, 4); got != "" {
		t.Fatalf("recent IPv4 = %q, want empty", got)
	}
}

func TestRecentEndpointIPFamilyIgnoresInvalidAddresses(t *testing.T) {
	history := []IdentityIPMACHistory{
		{IP: "not-an-ip", LastSeen: "2026-11-09T11:00:00Z", FirstSeen: "2026-11-09T10:00:00Z"},
		{IP: "192.0.2.20", LastSeen: "2026-11-09T09:00:00Z", FirstSeen: "2026-11-09T08:00:00Z"},
	}
	if got := recentEndpointIPFamily(history, 4); got != "192.0.2.20" {
		t.Fatalf("recent IPv4 = %q, want 192.0.2.20", got)
	}
}
