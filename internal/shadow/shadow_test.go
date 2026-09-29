package shadow

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWithDefaultsAllowsProductionSizedStoreWrites(t *testing.T) {
	opts := withDefaults(Options{})
	if opts.StoreTimeout != 5*time.Minute {
		t.Fatalf("unexpected store timeout: %s", opts.StoreTimeout)
	}
	explicit := withDefaults(Options{StoreTimeout: 90 * time.Second})
	if explicit.StoreTimeout != 90*time.Second {
		t.Fatalf("explicit store timeout was overwritten: %s", explicit.StoreTimeout)
	}
}

func TestRunReadsIncrementally(t *testing.T) {
	dir := t.TempDir()
	evePath := filepath.Join(dir, "eve.json")
	statePath := filepath.Join(dir, "state.json")
	outDir := filepath.Join(dir, "shadow")

	first := eveLine("1", "10.0.0.1", "198.51.100.1", "a.example.test")
	second := eveLine("2", "10.0.0.1", "198.51.100.2", "b.example.test")
	if err := os.WriteFile(evePath, []byte(first), 0644); err != nil {
		t.Fatal(err)
	}

	firstSummary, err := Run(Options{EVEPath: evePath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if firstSummary.PreviousOffset != 0 || firstSummary.NewOffset <= 0 || firstSummary.Normalized.Emitted != 1 {
		t.Fatalf("unexpected first summary: %+v", firstSummary)
	}

	file, err := os.OpenFile(evePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(second); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	secondSummary, err := Run(Options{EVEPath: evePath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if secondSummary.PreviousOffset != firstSummary.NewOffset || secondSummary.Normalized.Emitted != 1 {
		t.Fatalf("unexpected second summary: %+v", secondSummary)
	}

	emptySummary, err := Run(Options{EVEPath: evePath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if emptySummary.PreviousOffset != secondSummary.NewOffset || emptySummary.Normalized.Emitted != 0 || emptySummary.EvidenceCount != 0 || emptySummary.RiskCount != 0 {
		t.Fatalf("unexpected empty summary: %+v", emptySummary)
	}
}

func TestRunRestartsWhenEVEIsTruncated(t *testing.T) {
	dir := t.TempDir()
	evePath := filepath.Join(dir, "eve.json")
	statePath := filepath.Join(dir, "state.json")
	outDir := filepath.Join(dir, "shadow")

	if err := os.WriteFile(evePath, []byte(eveLine("1", "10.0.0.1", "198.51.100.1", "a.example.test")+eveLine("2", "10.0.0.2", "198.51.100.2", "b.example.test")), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(Options{EVEPath: evePath, StatePath: statePath, OutDir: outDir, SensorID: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evePath, []byte(eveLine("3", "10.0.0.3", "198.51.100.3", "c.example.test")), 0644); err != nil {
		t.Fatal(err)
	}

	summary, err := Run(Options{EVEPath: evePath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Truncated || summary.PreviousOffset != 0 || summary.Normalized.Emitted != 1 {
		t.Fatalf("unexpected truncated summary: %+v", summary)
	}
}

func TestRunWritesExpectedFiles(t *testing.T) {
	dir := t.TempDir()
	evePath := filepath.Join(dir, "eve.json")
	statePath := filepath.Join(dir, "state.json")
	outDir := filepath.Join(dir, "shadow")

	if err := os.WriteFile(evePath, []byte(eveLine("1", "10.0.0.1", "198.51.100.1", "a.example.test")), 0644); err != nil {
		t.Fatal(err)
	}
	summary, err := Run(Options{EVEPath: evePath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"normalized", "evidence", "risk_snapshots", "risk_list_suspicious", "router_evidence", "router_assessments", "run_summary"} {
		path, ok := summary.Files[name].(string)
		if !ok || path == "" {
			t.Fatalf("missing file %s in %+v", name, summary.Files)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}

	var state State
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if state.Offset != summary.NewOffset || state.EVEPath != evePath {
		t.Fatalf("unexpected state: %+v summary=%+v", state, summary)
	}
}

func TestRunAppendsZeekDHCPDeviceEvents(t *testing.T) {
	dir := t.TempDir()
	evePath := filepath.Join(dir, "eve.json")
	zeekPath := filepath.Join(dir, "dhcp.log")
	statePath := filepath.Join(dir, "state.json")
	outDir := filepath.Join(dir, "shadow")

	if err := os.WriteFile(evePath, []byte(eveLine("1", "10.0.0.1", "198.51.100.1", "a.example.test")), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zeekPath, []byte(zeekDHCPLog()), 0644); err != nil {
		t.Fatal(err)
	}

	summary, err := Run(Options{EVEPath: evePath, ZeekDHCPPath: zeekPath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Normalized.Emitted != 2 || summary.ZeekNormalized.Emitted != 1 || summary.Normalized.ByType["device"] != 1 {
		t.Fatalf("unexpected summary with zeek: %+v", summary)
	}
	if summary.ZeekStatus != "ok" || summary.ZeekReason == "" {
		t.Fatalf("expected ok zeek status, got %+v", summary)
	}

	normalizedPath := summary.Files["normalized"].(string)
	data, err := os.ReadFile(normalizedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesContains(data, []byte(`"source":"zeek"`)) || !bytesContains(data, []byte(`"type":"device"`)) {
		t.Fatalf("expected normalized output to contain zeek device event: %s", string(data))
	}

	var state State
	stateData, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(stateData, &state); err != nil {
		t.Fatal(err)
	}
	if state.ZeekDHCPPath != zeekPath || state.ZeekDHCPOffset == 0 {
		t.Fatalf("unexpected zeek state: %+v", state)
	}
	if state.Sources["dhcp"].Path != zeekPath || state.Sources["dhcp"].Offset == 0 {
		t.Fatalf("generic source state was not persisted: %+v", state.Sources)
	}
}

func TestRunDegradesWhenZeekDHCPLogIsMissing(t *testing.T) {
	dir := t.TempDir()
	evePath := filepath.Join(dir, "eve.json")
	zeekPath := filepath.Join(dir, "missing-dhcp.log")
	statePath := filepath.Join(dir, "state.json")
	outDir := filepath.Join(dir, "shadow")

	if err := os.WriteFile(evePath, []byte(eveLine("1", "10.0.0.1", "198.51.100.1", "a.example.test")), 0644); err != nil {
		t.Fatal(err)
	}

	summary, err := Run(Options{EVEPath: evePath, ZeekDHCPPath: zeekPath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Normalized.Emitted != 1 || summary.ZeekNormalized.Emitted != 0 || summary.ZeekStatus != "unavailable" {
		t.Fatalf("expected suricata-only run with unavailable zeek, got %+v", summary)
	}
}

func TestRunAppendsZeekSoftwareDeviceEvents(t *testing.T) {
	dir := t.TempDir()
	evePath := filepath.Join(dir, "eve.json")
	softwarePath := filepath.Join(dir, "software.log")
	statePath := filepath.Join(dir, "state.json")
	outDir := filepath.Join(dir, "shadow")

	if err := os.WriteFile(evePath, []byte(eveLine("1", "10.0.0.1", "198.51.100.1", "a.example.test")), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(softwarePath, []byte(zeekSoftwareLog()), 0644); err != nil {
		t.Fatal(err)
	}

	summary, err := Run(Options{EVEPath: evePath, ZeekSoftwarePath: softwarePath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Normalized.Emitted != 2 || summary.ZeekNormalized.Emitted != 1 || summary.Normalized.ByType["device"] != 1 {
		t.Fatalf("unexpected summary with zeek software: %+v", summary)
	}
	if summary.ZeekStatus != "ok" || summary.ZeekSoftwareNewOffset == 0 {
		t.Fatalf("expected ok zeek software status and offset, got %+v", summary)
	}

	normalizedPath := summary.Files["normalized"].(string)
	data, err := os.ReadFile(normalizedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesContains(data, []byte(`"source_event_type":"software"`)) || !bytesContains(data, []byte(`"software_name":"MSFT"`)) {
		t.Fatalf("expected normalized output to contain zeek software device event: %s", string(data))
	}

	var state State
	stateData, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(stateData, &state); err != nil {
		t.Fatal(err)
	}
	if state.ZeekSoftwarePath != softwarePath || state.ZeekSoftwareOffset == 0 {
		t.Fatalf("unexpected zeek software state: %+v", state)
	}
}

func TestRunMarksEmptyZeekDHCPLogAsNoData(t *testing.T) {
	dir := t.TempDir()
	evePath := filepath.Join(dir, "eve.json")
	zeekPath := filepath.Join(dir, "dhcp.log")
	statePath := filepath.Join(dir, "state.json")
	outDir := filepath.Join(dir, "shadow")

	if err := os.WriteFile(evePath, []byte(eveLine("1", "10.0.0.1", "198.51.100.1", "a.example.test")), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zeekPath, nil, 0644); err != nil {
		t.Fatal(err)
	}

	summary, err := Run(Options{EVEPath: evePath, ZeekDHCPPath: zeekPath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if summary.ZeekStatus != "no_dhcp_events" || summary.ZeekNormalized.Emitted != 0 {
		t.Fatalf("expected no DHCP data zeek status, got %+v", summary)
	}
}

func TestRunRestartsWhenZeekDHCPLogIsTruncated(t *testing.T) {
	dir := t.TempDir()
	evePath := filepath.Join(dir, "eve.json")
	zeekPath := filepath.Join(dir, "dhcp.log")
	statePath := filepath.Join(dir, "state.json")
	outDir := filepath.Join(dir, "shadow")

	if err := os.WriteFile(evePath, []byte(eveLine("1", "10.0.0.1", "198.51.100.1", "a.example.test")), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zeekPath, []byte(zeekDHCPLog()+zeekDHCPLog()), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(Options{EVEPath: evePath, ZeekDHCPPath: zeekPath, StatePath: statePath, OutDir: outDir, SensorID: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zeekPath, []byte(zeekDHCPLog()), 0644); err != nil {
		t.Fatal(err)
	}

	summary, err := Run(Options{EVEPath: evePath, ZeekDHCPPath: zeekPath, StatePath: statePath, OutDir: outDir, SensorID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !summary.ZeekTruncated || summary.ZeekStatus != "log_truncated" || summary.ZeekPrevOffset != 0 {
		t.Fatalf("expected zeek offset reset after truncation, got %+v", summary)
	}
}

func eveLine(id string, srcIP string, dstIP string, host string) string {
	return `{"timestamp":"2026-07-24T13:16:47.547787+0800","flow_id":` + id + `,"in_iface":"ens1f1","event_type":"http","src_ip":"` + srcIP + `","src_port":50000,"dest_ip":"` + dstIP + `","dest_port":80,"proto":"TCP","http":{"hostname":"` + host + `","url":"/","http_user_agent":"UA","http_method":"GET"}}` + "\n"
}

func zeekDHCPLog() string {
	return "#separator \\x09\n" +
		"#empty_field\t(empty)\n" +
		"#unset_field\t-\n" +
		"#path\tdhcp\n" +
		"#fields\tts\tuids\tclient_addr\tserver_addr\tclient_port\tserver_port\tmac\thost_name\tclient_fqdn\tdomain\trequested_addr\tassigned_addr\tlease_time\tclient_message\tserver_message\tmsg_types\tduration\tclient_software\trequested_options\n" +
		"#types\ttime\tset[string]\taddr\taddr\tport\tport\tstring\tstring\tstring\tstring\taddr\taddr\tinterval\tstring\tstring\tvector[string]\tinterval\tstring\tstring\n" +
		"2026-07-24T13:16:47.000000+0800\tC1\t0.0.0.0\t192.168.10.1\t68\t67\taa:bb:cc:dd:ee:01\tYuan-iPhone\t-\tlan\t10.0.0.1\t10.0.0.1\t86400.0\t-\t-\tDISCOVER,OFFER,REQUEST,ACK\t0.40\tApple iOS DHCP\t1,3,6,15,119,252\n"
}

func zeekSoftwareLog() string {
	return "#separator \\x09\n" +
		"#empty_field\t(empty)\n" +
		"#unset_field\t-\n" +
		"#path\tsoftware\n" +
		"#fields\tts\thost\thost_p\tsoftware_type\tname\tversion.major\tversion.minor\tversion.minor2\tversion.minor3\tversion.addl\tunparsed_version\n" +
		"#types\ttime\taddr\tport\tenum\tstring\tcount\tcount\tcount\tcount\tstring\tstring\n" +
		"2026-07-24T13:16:47.000000+0800\t10.0.0.6\t68\tDHCP::CLIENT\tMSFT\t5\t0\t-\t-\t-\tMSFT 5.0\n"
}

func bytesContains(data []byte, sub []byte) bool {
	for i := 0; i+len(sub) <= len(data); i++ {
		if string(data[i:i+len(sub)]) == string(sub) {
			return true
		}
	}
	return false
}
