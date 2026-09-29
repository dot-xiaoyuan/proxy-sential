package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveIdentitySnapshotLifecycle(t *testing.T) {
	dir := os.Getenv("SENTINEL_LIVE_IDENTITY_DIR")
	if dir == "" {
		t.Skip("explicit test-account API captures required")
	}
	read := func(name string) []Session {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var data struct {
			Sessions []Session `json:"sessions"`
		}
		if err = json.Unmarshal(raw, &data); err != nil {
			t.Fatal(err)
		}
		if len(data.Sessions) != 1 {
			t.Fatal("expected only designated account session")
		}
		return data.Sessions
	}
	online := read("test-account-quota.json")
	offline := read("test-account-after-logout.json")
	before := online[0].ConfirmedAt
	s := offline[0]
	if s.EndedAt.IsZero() || !s.EndedAt.After(before) {
		t.Fatal("full offline inventory did not close session")
	}
	historical := Attribute(offline, s.CampusID, s.AccessDomain, s.IP, before)
	if historical.State != "resolved" || historical.AccountID != "yuantong" {
		t.Fatal("historical account attribution lost", historical)
	}
	after := Attribute(offline, s.CampusID, s.AccessDomain, s.IP, s.EndedAt.Add(time.Second))
	if after.State == "resolved" {
		t.Fatal("ended session reused for future traffic", after)
	}
	inventory := EvaluateQuota("yuantong", online, Limits{}, before)
	if inventory.Total != 0 || inventory.State != "unknown" {
		t.Fatal("missing stable endpoint became confirmed device", inventory)
	}
}
