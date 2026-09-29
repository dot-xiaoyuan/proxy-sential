package store

import (
	"database/sql"
	"slices"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/sharedaccess"
)

func TestBuildSharedBehaviorWindowsPreservesSourcesAndRecordReferences(t *testing.T) {
	from := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	to := from.Add(10 * time.Minute)
	rows := []sharedBehaviorSignalRow{
		{
			SensorID: "sensor-1", CampusID: "ncu", AccessDomain: "campus-mirror", IP: "172.21.20.171",
			FeatureFamily: "ua_os", FeatureValue: "Android", FeatureCount: 3, Buckets: []int64{1, 2},
			EventIDs: []string{"event-z"}, Sources: []string{"zeek"},
			EventRefs: [][]string{{"event-z", "zeek", "instance-1"}},
			FirstSeen: from.Add(time.Second).Format(time.RFC3339Nano), LastSeen: to.Add(-time.Second).Format(time.RFC3339Nano),
		},
		{
			SensorID: "sensor-1", CampusID: "ncu", AccessDomain: "campus-mirror", IP: "172.21.20.171",
			FeatureFamily: "tcp_stack", FeatureValue: "stack-a", FeatureCount: 3, Buckets: []int64{1, 2},
			EventIDs: []string{"event-a"}, Sources: []string{"packet-sidecar"},
			EventRefs: [][]string{{"event-a", "packet-sidecar", "instance-1"}, {"event-a", "packet-sidecar", "instance-1"}},
			FirstSeen: from.Add(time.Second).Format(time.RFC3339Nano), LastSeen: to.Add(-2 * time.Second).Format(time.RFC3339Nano),
		},
	}
	windows, err := buildSharedBehaviorWindows(rows, from, to, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != 1 {
		t.Fatalf("windows=%d", len(windows))
	}
	window := windows[0]
	if got, want := len(window.Sources), 2; got != want || window.Sources[0] != "packet-sidecar" || window.Sources[1] != "zeek" {
		t.Fatalf("sources=%v", window.Sources)
	}
	if got, want := len(window.Records), 2; got != want {
		t.Fatalf("records=%v", window.Records)
	}
	if window.Records[0].EventID != "event-a" || window.Records[0].Source != "packet-sidecar" || window.Records[1].EventID != "event-z" || window.Records[1].Source != "zeek" {
		t.Fatalf("records=%v", window.Records)
	}
}

func TestConfirmedSharedBehaviorEvidenceRequiresAllSafetyGates(t *testing.T) {
	now := time.Date(2026, 9, 28, 10, 10, 0, 0, time.UTC)
	window := sharedaccess.Window{
		ID: "shared-1", RuleVersion: sharedaccess.RuleVersion, IP: "172.21.20.171", SensorID: "sensor-1",
		CampusID: "ncu", AccessDomain: "campus-mirror", Sources: []string{"zeek", "packet-sidecar"},
		From: now.Add(-10 * time.Minute), To: now, LastObservedAt: now.Add(-time.Second), Complete: true, CoverageVerified: true,
		EventIDs: []string{"event-1"}, Records: []sharedaccess.RecordRef{{EventID: "event-1", Source: "zeek", InstanceID: "instance-1"}},
	}
	item := sharedaccess.BehaviorAssessment{Status: "confirmed", Confidence: 95, CoverageState: "verified"}
	got, ok := confirmedSharedBehaviorEvidence(window, item)
	if !ok || got.Type != "shared_access_window" || got.Score != 95 || got.Confidence != .95 || got.SharedAccess == nil {
		t.Fatalf("evidence=%+v ok=%v", got, ok)
	}

	for name, mutate := range map[string]func(*sharedaccess.Window, *sharedaccess.BehaviorAssessment){
		"likely":          func(_ *sharedaccess.Window, a *sharedaccess.BehaviorAssessment) { a.Status = "likely" },
		"partial":         func(_ *sharedaccess.Window, a *sharedaccess.BehaviorAssessment) { a.CoverageState = "partial" },
		"incomplete":      func(w *sharedaccess.Window, _ *sharedaccess.BehaviorAssessment) { w.Complete = false },
		"unverified":      func(w *sharedaccess.Window, _ *sharedaccess.BehaviorAssessment) { w.CoverageVerified = false },
		"conflict":        func(w *sharedaccess.Window, _ *sharedaccess.BehaviorAssessment) { w.Conflicts = []string{"ambiguous"} },
		"missing sources": func(w *sharedaccess.Window, _ *sharedaccess.BehaviorAssessment) { w.Sources = nil },
		"missing records": func(w *sharedaccess.Window, _ *sharedaccess.BehaviorAssessment) { w.Records = nil },
	} {
		t.Run(name, func(t *testing.T) {
			copyWindow, copyItem := window, item
			mutate(&copyWindow, &copyItem)
			if _, allowed := confirmedSharedBehaviorEvidence(copyWindow, copyItem); allowed {
				t.Fatal("unsafe observation bridged")
			}
		})
	}
}

func TestSharedBehaviorCoverageAcceptsSuricataAsApplicationCollector(t *testing.T) {
	now := time.Date(2026, 9, 29, 7, 0, 0, 0, time.UTC)
	checkpoints := map[string]sharedBehaviorCheckpoint{
		"device-signals": {eventAt: sql.NullTime{Time: now.Add(-30 * time.Second), Valid: true}, updatedAt: now.Add(-10 * time.Second)},
		"suricata":       {eventAt: sql.NullTime{Time: now.Add(-20 * time.Second), Valid: true}, updatedAt: now.Add(-5 * time.Second)},
	}
	if reasons := sharedBehaviorCoverageReasons(checkpoints, now, now); len(reasons) != 0 {
		t.Fatalf("healthy Suricata deployment was treated as partial: %v", reasons)
	}
}

func TestSharedBehaviorCoverageRequiresTransportAndApplicationCollectors(t *testing.T) {
	now := time.Date(2026, 9, 29, 7, 0, 0, 0, time.UTC)
	checkpoints := map[string]sharedBehaviorCheckpoint{
		"suricata": {eventAt: sql.NullTime{Time: now, Valid: true}, updatedAt: now},
	}
	reasons := sharedBehaviorCoverageReasons(checkpoints, now, now)
	if !slices.Contains(reasons, "device-signals_checkpoint_missing") {
		t.Fatalf("missing packet-sidecar coverage was accepted: %v", reasons)
	}
	delete(checkpoints, "suricata")
	reasons = sharedBehaviorCoverageReasons(checkpoints, now, now)
	if !slices.Contains(reasons, "application_checkpoint_missing") {
		t.Fatalf("missing application collector was accepted: %v", reasons)
	}
}

func TestSharedBehaviorKnownDevicesKeepsOnlyRepeatedExplicitModels(t *testing.T) {
	from := time.Date(2026, 9, 29, 1, 0, 0, 0, time.UTC)
	rows := []sharedBehaviorKnownDeviceRow{
		{SensorID: "sensor", IP: "192.0.2.63", Value: "|Android|mobile|MAA-AN00", Count: 2, Buckets: []int64{1, 2}, FirstSeen: from.Format(time.RFC3339Nano), LastSeen: from.Add(time.Hour).Format(time.RFC3339Nano)},
		{SensorID: "sensor", IP: "192.0.2.63", Value: "Honor|Android|mobile|MAA-AN00", Count: 3, Buckets: []int64{2, 3}, FirstSeen: from.Add(time.Minute).Format(time.RFC3339Nano), LastSeen: from.Add(2 * time.Hour).Format(time.RFC3339Nano)},
		{SensorID: "sensor", IP: "192.0.2.63", Value: "Apple|iOS|mobile|iPhone18,4", Count: 2, Buckets: []int64{4, 5}, FirstSeen: from.Format(time.RFC3339Nano), LastSeen: from.Add(3 * time.Hour).Format(time.RFC3339Nano)},
		{SensorID: "sensor", IP: "192.0.2.63", Value: "Samsung|Android|mobile|GT-I9505", Count: 4, Buckets: []int64{6}, FirstSeen: from.Format(time.RFC3339Nano), LastSeen: from.Add(time.Minute).Format(time.RFC3339Nano)},
	}
	got := sharedBehaviorKnownDevices(rows)[strings.Join([]string{"sensor", "", "", "192.0.2.63"}, "\x00")]
	if len(got) != 2 {
		t.Fatalf("known devices=%+v", got)
	}
	byModel := map[string]sharedaccess.KnownDevice{}
	for _, item := range got {
		byModel[item.Model] = item
	}
	if byModel["MAA-AN00"].Brand != "Honor" || byModel["MAA-AN00"].Observations != 5 || byModel["iPhone18,4"].Brand != "Apple" {
		t.Fatalf("known devices were not merged conservatively: %+v", got)
	}
}

func TestMergeIEEE1905AssociationWindowsCreatesPassiveGatewayWindow(t *testing.T) {
	from := time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)
	to := from.Add(10 * time.Minute)
	groups := []ieee1905AssociationGroup{{
		SensorID: "sensor", CampusID: "ncu", AccessDomain: "campus-mirror",
		GatewayIP: "192.168.0.22", GatewayMAC: "20:3a:eb:e9:de:10",
		Clients: []string{"10:20:30:40:50:60", "10:20:30:40:50:61"}, EventIDs: []string{"event-1", "event-2"},
		FirstSeen: from, LastSeen: to.Add(-time.Minute),
	}}
	windows := mergeIEEE1905AssociationWindows(nil, groups, from, to, true, nil)
	if len(windows) != 1 {
		t.Fatalf("windows=%d", len(windows))
	}
	window := windows[0]
	if window.IP != "192.168.0.22" || len(window.AssociatedClients) != 2 || len(window.Records) != 2 {
		t.Fatalf("unexpected passive gateway window: %+v", window)
	}
	if len(window.Samples["ieee1905_association"]) != 2 || window.Sources[0] != "packet-sidecar" {
		t.Fatalf("association evidence was not retained: %+v", window)
	}
}
