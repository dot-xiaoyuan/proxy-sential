package store

import (
	"reflect"
	"testing"
	"time"
)

func TestInventoryLatestAssociationsUseEvidenceTime(t *testing.T) {
	now := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	profile := EndpointIdentityProfile{
		Accounts:  []string{"a-old", "z-latest"},
		Sessions:  []AccountSession{{AccountID: "a-old", AccessID: "A-old", StartedAt: now.Add(-2 * time.Hour).Format(time.RFC3339)}, {AccountID: "z-latest", AccessID: "Z-latest", StartedAt: now.Add(-time.Hour).Format(time.RFC3339)}},
		IPHistory: []IdentityIPMACHistory{{AccountID: "a-old", IP: "192.0.2.1", LastSeen: now.Add(-3 * time.Hour).Format(time.RFC3339)}},
	}
	got := latestInventoryAssociations(profile, now)
	if got.Account != "z-latest" || got.Access != "Z-latest" || got.AccountConflict {
		t.Fatalf("latest association came from lexical order: %+v", got)
	}
	profile.IPHistory = append(profile.IPHistory, IdentityIPMACHistory{AccountID: "a-old", LastSeen: now.Add(-4 * time.Hour).Format(time.RFC3339)})
	if late := latestInventoryAssociations(profile, now); late.Account != "z-latest" {
		t.Fatal("late old observation overwrote latest association")
	}
}

func TestInventoryLatestAccountTieIsAConflict(t *testing.T) {
	now := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	at := now.Add(-time.Minute).Format(time.RFC3339)
	profile := EndpointIdentityProfile{IPHistory: []IdentityIPMACHistory{{AccountID: "z", LastSeen: at}, {AccountID: "a", LastSeen: at}, {AccountID: "z", LastSeen: at}}}
	got := latestInventoryAssociations(profile, now)
	if got.Account != "" || !got.AccountConflict || !reflect.DeepEqual(got.AccountCandidates, []string{"a", "z"}) {
		t.Fatalf("ambiguous account presented as certain: %+v", got)
	}
	profile.IPHistory = append(profile.IPHistory, IdentityIPMACHistory{AccountID: "future", LastSeen: now.Add(time.Hour).Format(time.RFC3339)})
	if got = latestInventoryAssociations(profile, now); !reflect.DeepEqual(got.AccountCandidates, []string{"a", "z"}) {
		t.Fatal("future evidence became current")
	}
}

func TestInventoryLatestAssociationUsesConfirmationWithoutAssumingOnline(t *testing.T) {
	now := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	profile := EndpointIdentityProfile{Sessions: []AccountSession{
		{AccountID: "new-login", StartedAt: now.Add(-time.Hour).Format(time.RFC3339)},
		{AccountID: "confirmed-old-login", StartedAt: now.Add(-24 * time.Hour).Format(time.RFC3339), LastConfirmedAt: now.Add(-time.Minute).Format(time.RFC3339), EndedAt: now.Add(-time.Minute).Format(time.RFC3339)},
	}}
	if got := latestInventoryAssociations(profile, now); got.Account != "confirmed-old-login" {
		t.Fatalf("latest confirmation was ignored: %+v", got)
	}
}
func TestInventorySessionFutureConfirmationKeepsPastFact(t *testing.T) {
	now := time.Now().UTC()
	profile := EndpointIdentityProfile{Sessions: []AccountSession{{AccountID: "past", StartedAt: now.Add(-time.Hour).Format(time.RFC3339Nano), LastConfirmedAt: now.Add(time.Hour).Format(time.RFC3339Nano)}}}
	if got := latestInventoryAssociations(profile, now); got.Account != "past" || got.AccountAt.After(now) {
		t.Fatal("future confirmation hid a valid past fact")
	}
}

func TestInventorySearchNormalization(t *testing.T) {
	for _, tc := range []struct {
		kind, input, want string
		fail              bool
	}{
		{"account", " Student-A ", "Student-A", false},
		{"ip", "2001:0db8::1", "2001:db8::1", false},
		{"mac", "AA-BB-CC-DD-EE-FF", "aabbccddeeff", false},
		{"all", "Desk", "desk", false},
		{"invalid", "account", "", true}, {"ip", "not-an-ip", "", true}, {"mac", "not-a-mac", "", true},
		{"mac", "aa:::bb:cc:dd:ee:ff", "", true},
	} {
		q := Query{InventorySearchType: tc.kind, Q: tc.input}
		err := normalizeInventorySearch(&q)
		if (err != nil) != tc.fail || err == nil && q.Q != tc.want {
			t.Fatalf("%s/%s: got %+v, %v", tc.kind, tc.input, q, err)
		}
	}
}
