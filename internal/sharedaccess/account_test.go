package sharedaccess

import (
	"os"
	"path/filepath"
	"proxy-sentinel/internal/policy"
	"testing"
	"time"
)

func TestAccountLatestAndCoverage(t *testing.T) {
	now := time.Now().UTC()
	cfg := Config{Version: "lab", FreshnessSeconds: 180, Sources: []Source{{SensorID: "s", Source: "capture", CampusID: "c", AccessDomain: "nas"}}}
	ss := []policy.Session{{ID: "one", Source: "auth", SensorID: "auth", AccountID: "a", IP: "192.0.2.1", EndpointID: "endpoint", CampusID: "c", AccessDomain: "nas", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, Confirmations: []time.Time{now.Add(-time.Minute), now}, HeartbeatSeconds: 60}}
	w := Window{ID: "shared-old", RuleVersion: RuleVersion, IP: "192.0.2.1", SensorID: "s", CampusID: "c", AccessDomain: "nas", Sources: []string{"capture"}, EventIDs: []string{"event"}, From: now.Add(-time.Minute), To: now.Add(-time.Second), LastObservedAt: now.Add(-time.Second), Complete: true, UAOS: []string{"Android", "Windows"}, TTLPaths: []string{"63", "127"}, TLSStacks: []string{"one", "two"}}
	addRepeatedSamples(&w)
	current := w
	current.ID = "shared-new"
	current.To = now
	current.LastObservedAt = now
	current.UAOS = []string{"Android"}
	current.TTLPaths = []string{"63"}
	current.TLSStacks = []string{"one"}
	input := func(rows []Window, sessions []policy.Session) policy.Input {
		return Input("a", AccountResults("a", rows, cfg, sessions, now, 10*time.Minute), "observe")
	}
	if got := input([]Window{w}, ss); !got.Known || !got.Violated {
		t.Fatal(got)
	}
	for _, rows := range [][]Window{{w, current}, {current, w}} {
		if got := input(rows, ss); !got.Known || got.Violated {
			t.Fatal("old positive overrode latest window", got)
		}
	}
	other := ss[0]
	other.ID = "two"
	other.IP = "192.0.2.2"
	ss = append(ss, other)
	if got := input([]Window{current}, ss); got.Known {
		t.Fatal("missing IP observation became recovery", got)
	}
	ss[1].AccessDomain = "unregistered"
	if got := input([]Window{current}, ss); got.Known {
		t.Fatal("unregistered scope became recovery", got)
	}
	current.Complete = false
	if got := input([]Window{w, current}, ss[:1]); got.Known {
		t.Fatal("partial latest fell back to positive", got)
	}
}
func TestControlledSourceConfig(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sources.json")
	good := `{"schema_version":"shared-access-sources/v1","version":"lab1","freshness_seconds":180,"sources":[{"sensor_id":"s","source":"capture","campus_id":"c","access_domain":"nas"}]}`
	if err := os.WriteFile(file, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(file); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{good + `{}`, `{"schema_version":"future"}`, `{"verified":true}`, `{"schema_version":"shared-access-sources/v1","version":"lab1","freshness_seconds":180,"sources":[{"sensor_id":"s","source":"capture","campus_id":"c","access_domain":"nas"},{"sensor_id":"s","source":"capture","campus_id":"different","access_domain":"nas"}]}`} {
		os.WriteFile(file, []byte(bad), 0600)
		if _, err := Load(file); err == nil {
			t.Fatal("accepted invalid registration", bad)
		}
	}
}
