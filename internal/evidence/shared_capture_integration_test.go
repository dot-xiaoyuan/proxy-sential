package evidence

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"testing"
	"time"
)

func TestSharedLiveCaptureReplay(t *testing.T) {
	dir := os.Getenv("SENTINEL_SHARED_CAPTURE_DIR")
	if dir == "" {
		t.Skip("isolated NAT live capture required")
	}
	var scenario struct {
		Scenario string `json:"scenario"`
	}
	label, err := os.ReadFile(filepath.Join(dir, "scenario.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(label, &scenario); err != nil {
		t.Fatal(err)
	}
	want, ok := map[string]string{
		"heterogeneous": "basis_present",
		"single":        "not_matched",
		"multi_browser": "insufficient",
		// Identical downstream stacks are a known blind spot, not a negative label.
		"homogeneous": "not_matched",
	}[scenario.Scenario]
	if !ok {
		t.Fatalf("unknown capture scenario %q", scenario.Scenario)
	}
	events := []normalized.Event{}
	var from, to time.Time
	for _, name := range []string{"scoped-normalized.jsonl", "device-signals.jsonl"} {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		scan := bufio.NewScanner(f)
		scan.Buffer(make([]byte, 65536), 16<<20)
		for scan.Scan() {
			var e normalized.Event
			if err = json.Unmarshal(scan.Bytes(), &e); err != nil {
				t.Fatal(err)
			}
			at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
			if err != nil {
				t.Fatal(err)
			}
			if from.IsZero() || at.Before(from) {
				from = at
			}
			if at.After(to) {
				to = at
			}
			events = append(events, e)
			if len(events) > 100000 {
				t.Fatal("bounded lab replay exceeded")
			}
		}
		err = scan.Err()
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg := sharedaccess.Config{Version: "isolated-capture", FreshnessSeconds: 180, Sources: []sharedaccess.Source{{SensorID: "campus-lab", Source: "suricata", CampusID: "campus-lab", AccessDomain: "lab-nas"}, {SensorID: "campus-lab", Source: "packet-sidecar", CampusID: "campus-lab", AccessDomain: "lab-nas"}}}
	windows := SharedWindows(events, from, to, true)
	var nat *sharedaccess.Window
	for i := range windows {
		if windows[i].IP == "172.29.250.2" {
			nat = &windows[i]
			break
		}
	}
	if nat == nil {
		t.Fatal("NAT exit window missing")
	}
	if got := sharedaccess.Evaluate(*nat, cfg, nil, to, 10*time.Minute); got.State != "insufficient" || got.AccountID != "" {
		t.Fatal("capture alone invented account", got)
	}
	// This explicit laboratory identity fixture is not the 190 authentication feed.
	ss := []policy.Session{{ID: "lab-auth-fixture", AccountID: "lab-fixture", EndpointID: "upstream-router", IP: nat.IP, CampusID: "campus-lab", AccessDomain: "lab-nas", Source: "lab-fixture", SensorID: "auth-lab", StartedAt: from.Add(-time.Minute), ConfirmedAt: to, Confirmations: []time.Time{from, to}, HeartbeatSeconds: 60}}
	result := sharedaccess.Evaluate(*nat, cfg, ss, to, 10*time.Minute)
	if result.State != want || result.DeviceLowerBound != 1 {
		t.Fatalf("live evidence did not produce expected bounded basis: %+v window=%+v", result, *nat)
	}
	sources := map[string]bool{}
	for _, ref := range result.Records {
		sources[ref.Source] = true
		if ref.InstanceID == "" {
			t.Fatal("missing capture instance")
		}
	}
	if !sources["suricata"] || !sources["packet-sidecar"] {
		t.Fatal("raw references omitted signal source", sources)
	}
	report := map[string]any{"scenario": scenario.Scenario, "expected_state": want, "known_shared": scenario.Scenario == "heterogeneous" || scenario.Scenario == "homogeneous", "events": len(events), "result": result, "identity": "explicit lab fixture; real 190 authentication not tested"}
	raw, _ := json.Marshal(report)
	t.Log(string(raw))
}
