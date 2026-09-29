package replay

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/risk"
)

func TestGoldenLegacyEssentialsRemainReplayable(t *testing.T) {
	path := filepath.Join("..", "..", "examples", "replay", "golden-legacy-essentials.jsonl")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	result, err := evidence.Analyze(file, evidence.Options{})
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]bool{}
	for _, item := range result.Evidence {
		types[item.Type] = true
	}
	if !types["device_fingerprint_conflict"] || !types["ttl_clusters"] || !types["vpn_proxy_rule_match"] || !types["known_game_accelerator"] || !types["account_concurrent_endpoints"] {
		t.Fatalf("golden evidence missing: %#v", types)
	}
	evidenceJSON, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	riskResult, err := risk.Batch(bytes.NewReader(evidenceJSON))
	if err != nil {
		t.Fatal(err)
	}
	byIP := map[string]risk.Snapshot{}
	for _, snapshot := range riskResult.Snapshots {
		byIP[snapshot.IP] = snapshot
	}
	assertRiskAtMost(t, byIP["10.10.0.30"], "suspicious", "single DHCP profile")
	assertRiskAtMost(t, byIP["10.10.0.10"], "suspicious", "known game accelerator")
	assertRiskAtMost(t, byIP["10.10.0.1"], "suspicious", "infrastructure TTL")
	assertRiskAtMost(t, byIP["2001:db8:10::12"], "suspicious", "IPv6 hop-limit only")
	if snapshot := byIP["10.10.0.9"]; snapshot.DetectionBasis != "explicit_tunnel" || (snapshot.Level != "high" && snapshot.Level != "confirmed") {
		t.Fatalf("explicit VPN rule did not produce an explicit tunnel result: %+v", snapshot)
	}
}

func assertRiskAtMost(t *testing.T, snapshot risk.Snapshot, maximum, scenario string) {
	t.Helper()
	levels := map[string]int{"": 0, "normal": 0, "suspicious": 1, "high": 2, "confirmed": 3}
	if levels[snapshot.Level] > levels[maximum] {
		t.Fatalf("%s exceeded %s: %+v", scenario, maximum, snapshot)
	}
}
