package discovery

import (
	"strings"
	"testing"
	"time"
)

func TestHardwareSelectionKeepsOnlyCompactCandidateProjection(t *testing.T) {
	q := DeviceQuery{HardwareV2: true, Mode: "passive"}
	s, err := buildIndexedDeviceSelection(q)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.CTE, "observation_tid") || !strings.Contains(s.CTE, "display_links AS NOT MATERIALIZED") {
		t.Fatal("hardware selection still materializes full observation payloads before pagination")
	}
	for _, materialized := range []string{"source_rows", "seed_rows", "candidate_rows"} {
		start := strings.Index(s.CTE, materialized+" AS MATERIALIZED (")
		if start < 0 {
			t.Fatalf("missing compact stage %s", materialized)
		}
		end := strings.Index(s.CTE[start:], "\n),")
		if start < 0 || end < 0 {
			t.Fatalf("missing compact stage %s", materialized)
		}
		stage := s.CTE[start : start+end]
		if strings.Contains(stage, "l.data,") || strings.Contains(stage, "l.data\n") {
			t.Fatalf("stage %s carries raw documents", materialized)
		}
	}
	if !strings.Contains(s.CTE, `GROUP BY identity_key COLLATE "C"`) {
		t.Fatal("identity grouping differs from byte-exact cursor ordering")
	}
	if !strings.Contains(s.CTE, "observation_id=ANY(ARRAY(SELECT id FROM source_rows WHERE raw_mac=''))") || !strings.Contains(s.CTE, "i.observation_id=l.id AND l.raw_mac=''") {
		t.Fatal("batched missing-MAC link lookup changed per-observation admission")
	}
	if !strings.Contains(s.CTE, "dl.sensor_id=l.sensor_id") || !strings.Contains(s.CTE, "dl.campus_id=l.source_campus") || !strings.Contains(s.CTE, "dl.event_id=l.id") {
		t.Fatal("bounded lease lookup lost part of primary key")
	}
	if strings.Contains(s.CTE, "array_agg(observed_type)") || strings.Contains(s.CTE, "JOIN (SELECT DISTINCT coalesce(display_endpoint") {
		t.Fatal("hardware classification still rebuilds replaced recognition aggregates")
	}
	if !strings.Contains(s.CTE, "coalesce(v.data->>'ip','')<>''") {
		t.Fatal("SADP identity lookup cannot imply its partial IP index")
	}
	q.HardwareV2 = false
	legacy, err := buildIndexedDeviceSelection(q)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(legacy.CTE, "observation_tid") || !strings.Contains(legacy.CTE, "array_agg(observed_type)") {
		t.Fatal("default 184 read path changed")
	}
}

func TestHardwareCompactSelectionPreservesFilteringAndClues(t *testing.T) {
	q := DeviceQuery{HardwareV2: true, Mode: "passive", Search: "switch", Protocol: "snmp", DeviceType: "switch", State: "identified", Category: "network", Capability: "routing", OSFamily: "Comware", Domain: "access", VLAN: "201", ReviewReason: "type_change"}
	s, err := buildIndexedDeviceSelection(q)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"lower(profile_type) LIKE", "coalesce(search_model,'') LIKE", "bool_or(origin = ANY", "observation_capabilities ?", "projection_type= ANY", "classification_status = ANY", "category=$", "lower(profile_os) LIKE", "type_changed_at>=", "candidate_role", "profile_candidate_role", "coalesce(data->>'domain','')", "coalesce(data->>'vlan','')"} {
		if !strings.Contains(s.CTE, part) {
			t.Errorf("hardware compact selection lost filter/clue %q", part)
		}
	}
	q.Export = true
	ex, err := buildIndexedDeviceSelection(q)
	if err != nil {
		t.Fatal(err)
	}
	if ex.CTE != s.CTE {
		t.Fatal("export and list selection differ")
	}
}

func TestHardwareDefaultDefersProfilesWithoutDroppingPageClues(t *testing.T) {
	s, err := buildIndexedDeviceSelection(DeviceQuery{HardwareV2: true, Mode: "passive"})
	if err != nil {
		t.Fatal(err)
	}
	if !s.PageProfiles || strings.Contains(s.CTE, "FROM endpoint_recognition_summary") {
		t.Fatal("default hardware selection still parses every legacy profile")
	}
	for _, q := range []DeviceQuery{{HardwareV2: true, Search: "camera"}, {HardwareV2: true, Category: "network"}, {HardwareV2: true, OSFamily: "Comware"}} {
		selected, err := buildIndexedDeviceSelection(q)
		if err != nil {
			t.Fatal(err)
		}
		if selected.PageProfiles || !strings.Contains(selected.CTE, "FROM endpoint_recognition_summary") {
			t.Fatal("a profile filter was moved after pagination")
		}
	}
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	row := func(key, role string, confidence float64, conflict bool, until time.Time) deviceObservationRow {
		return deviceObservationRow{IndexedIdentityKey: key, ProfileDeviceType: role, ProfileTypeConfidence: confidence, ProfileConflict: conflict, Observation: Observation{ValidUntil: until}}
	}
	rows := []deviceObservationRow{
		row("one", "switch", .6, false, now.Add(time.Minute)), row("one", "switch", .6, false, now.Add(time.Minute)),
		row("different", "router", .6, false, now.Add(time.Minute)), row("different", "switch", .6, false, now.Add(time.Minute)),
		row("expired", "printer", .6, false, now), row("conflict", "camera", .6, true, now.Add(time.Minute)),
		row("strong", "switch", .8, false, now.Add(time.Minute)), row("weak", "switch", .39, false, now.Add(time.Minute)),
	}
	got := indexedPageCandidateCategories(rows, now)
	for _, key := range []string{"different", "expired", "conflict", "strong", "weak"} {
		if got[key] != "identity_only" {
			t.Errorf("%s=%s", key, got[key])
		}
	}
	if got["one"] != "network" {
		t.Fatalf("single current candidate lost: %v", got)
	}
}

func TestHardwarePageReadsOnlySelectedPayloadsAndSkipsDeadHistoryLink(t *testing.T) {
	s, err := buildIndexedDeviceSelection(DeviceQuery{HardwareV2: true, Mode: "passive"})
	if err != nil {
		t.Fatal(err)
	}
	page := buildHardwareIndexedPage(s, " WHERE last_seen<$20", "21")
	suffix := page[len(s.CTE):]
	if !strings.Contains(suffix, "page_o.ctid=l.observation_tid") || strings.Contains(suffix, "discovery_identity_links") {
		t.Fatal("page does not stay on selected current rows")
	}
	if !strings.Contains(suffix, "LIMIT $21") || !strings.Contains(suffix, "WHERE last_seen<$20") || !strings.Contains(suffix, "page_rec.endpoint_id=l.recognition_endpoint") {
		t.Fatal("bounded page/profile/cursor clauses lost")
	}
}
