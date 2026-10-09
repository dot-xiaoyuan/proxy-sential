package store

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/sharedaccess"
)

func TestIEEE1905SyncReadsOnlyFreshWindowAndLaterLeaves(t *testing.T) {
	from := time.Date(2026, 9, 30, 14, 5, 0, 0, time.UTC)
	now := from.Add(17 * time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		if query == "" {
			raw, _ := io.ReadAll(r.Body)
			query = string(raw)
		}
		// Reading the live 17 minutes includes leaves after the delayed window
		// end; scanning days of payloads previously exhausted the query deadline.
		for _, bound := range []string{from.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)} {
			if !strings.Contains(query, bound) {
				t.Errorf("association query omitted fresh-window boundary %s", bound)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&DBStore{ch: ch}).syncIEEE1905Associations(context.Background(), "office-30", from, now); err != nil {
		t.Fatal(err)
	}
}

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
	item := sharedaccess.BehaviorAssessment{Status: "confirmed", Confidence: 95, CoverageState: "verified", StrongAnchor: "coexisting_device_models", DeviceLowerBound: 2}
	got, ok := confirmedSharedBehaviorEvidence(window, item)
	if !ok || got.Type != "shared_access_window" || got.Score != 95 || got.Confidence != .95 || got.SharedAccess == nil {
		t.Fatalf("evidence=%+v ok=%v", got, ok)
	}

	for name, mutate := range map[string]func(*sharedaccess.Window, *sharedaccess.BehaviorAssessment){
		"missing anchor": func(_ *sharedaccess.Window, a *sharedaccess.BehaviorAssessment) { a.StrongAnchor = "" },
		"unknown anchor": func(_ *sharedaccess.Window, a *sharedaccess.BehaviorAssessment) {
			a.StrongAnchor = "unsupported-anchor"
		},
		"single device":   func(_ *sharedaccess.Window, a *sharedaccess.BehaviorAssessment) { a.DeviceLowerBound = 1 },
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

func TestSharedBehaviorCoverageAcceptsDedicatedPayloadFreeCollector(t *testing.T) {
	now := time.Date(2026, 10, 8, 14, 0, 0, 0, time.UTC)
	checkpoints := map[string]sharedBehaviorCheckpoint{
		"shared-device-signals": {eventAt: sql.NullTime{Time: now.Add(-30 * time.Second), Valid: true}, updatedAt: now.Add(-10 * time.Second)},
	}
	if reasons := sharedBehaviorCoverageReasons(checkpoints, now, now); len(reasons) != 0 {
		t.Fatalf("healthy dedicated shared-signal collector was treated as partial: %v", reasons)
	}
	checkpoints["shared-device-signals"] = sharedBehaviorCheckpoint{eventAt: sql.NullTime{Time: now.Add(-3 * time.Minute), Valid: true}, updatedAt: now.Add(-3 * time.Minute)}
	if reasons := sharedBehaviorCoverageReasons(checkpoints, now, now); len(reasons) == 0 {
		t.Fatal("stale dedicated shared-signal collector was accepted")
	}
}

func TestSharedBehaviorPrefilterDropsOrdinarySingleStackCampusEndpoints(t *testing.T) {
	now := time.Date(2026, 10, 8, 14, 40, 0, 0, time.UTC)
	ordinary := sharedaccess.Window{From: now.Add(-10 * time.Minute), To: now, LastObservedAt: now.Add(-time.Minute), Complete: true, CoverageVerified: true, TCPStacks: []string{"one"}, Samples: map[string]map[string]sharedaccess.FeatureSample{}, EventIDs: []string{"ordinary"}}
	if sharedBehaviorPotentialWindow(ordinary) {
		t.Fatal("ordinary single-stack endpoint reached PostgreSQL enrichment")
	}
	shared := ordinary
	shared.Sources = []string{"shared-syn-sidecar"}
	shared.TCPStacks = []string{"one", "two", "three"}
	shared.Samples["tcp_stack"] = map[string]sharedaccess.FeatureSample{
		"one":   {Count: 3, Buckets: []int64{now.Add(-3*time.Minute).Unix() / 5, now.Add(-2*time.Minute).Unix() / 5}},
		"two":   {Count: 3, Buckets: []int64{now.Add(-3*time.Minute).Unix() / 5, now.Add(-2*time.Minute).Unix() / 5}},
		"three": {Count: 3, Buckets: []int64{now.Add(-3*time.Minute).Unix() / 5, now.Add(-2*time.Minute).Unix() / 5}},
	}
	if !sharedBehaviorPotentialWindow(shared) {
		t.Fatal("dedicated repeated TCP candidate was removed by the prefilter")
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

func TestSharedBehaviorModelRefsRemainTraceable(t *testing.T) {
	window := sharedaccess.Window{EventIDs: []string{"transport"}, Sources: []string{"packet-sidecar"}}
	rows := []sharedBehaviorKnownDeviceRow{{SensorID: "office", IP: "192.0.2.63", EventIDs: []string{"model"}, Sources: []string{"zeek"}, EventRefs: [][]string{{"model", "zeek", "boot-1"}}}}
	key := "office\x00\x00\x00192.0.2.63"
	appendSharedBehaviorModelRefs(&window, rows, key)
	appendSharedBehaviorModelRefs(&window, rows, key)
	if len(window.EventIDs) != 2 || len(window.Records) != 1 || window.Records[0].EventID != "model" || window.Records[0].InstanceID != "boot-1" {
		t.Fatalf("model proof missing or duplicated: %+v", window)
	}
}

func TestSharedBehaviorDoesNotPromoteOldMeshJoins(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	groups := []ieee1905AssociationGroup{{SensorID: "office", GatewayIP: "192.0.2.22", Clients: []string{"a", "b"}, LastSeen: now.Add(-time.Hour)}}
	if windows := mergeIEEE1905AssociationWindows(nil, groups, now.Add(-10*time.Minute), now, true, nil); len(windows) != 0 {
		t.Fatalf("old join history became current occupancy: %+v", windows)
	}
}

func TestIEEE1905MergePreservesActualSourceTime(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	sourceAt := now.Add(-3 * time.Minute)
	group := ieee1905AssociationGroup{SensorID: "office", GatewayIP: "192.0.2.22", GatewayMAC: "20:3a:eb:e9:de:10", Clients: []string{"02:00:00:00:00:01", "02:00:00:00:00:03"}, LastSeen: sourceAt, EventIDs: []string{"a", "b"}}
	windows := mergeIEEE1905AssociationWindows(nil, []ieee1905AssociationGroup{group}, now.Add(-10*time.Minute), now, true, nil)
	if len(windows) != 1 || !windows[0].LastObservedAt.Equal(sourceAt) {
		t.Fatalf("rebuild fabricated a fresh source observation: %+v", windows)
	}
	for _, sample := range windows[0].Samples["ieee1905_association"] {
		if len(sample.Buckets) != 1 || sample.Buckets[0] != sourceAt.UnixMilli()/5000 {
			t.Fatalf("rebuild fabricated an association bucket: %+v", sample)
		}
	}
	// Independent later traffic keeps its actual observation time.
	later := now.Add(-time.Minute)
	windows = mergeIEEE1905AssociationWindows([]sharedaccess.Window{{SensorID: "office", IP: group.GatewayIP, From: now.Add(-10 * time.Minute), To: now, LastObservedAt: later}}, []ieee1905AssociationGroup{group}, now.Add(-10*time.Minute), now, true, nil)
	if !windows[0].LastObservedAt.Equal(later) {
		t.Fatalf("association overwrote newer source time: %s", windows[0].LastObservedAt)
	}
}

func TestIEEE1905MergeKeepsEachClientSourceBucket(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	a, b := now.Add(-4*time.Minute), now.Add(-3*time.Minute)
	group := ieee1905AssociationGroup{SensorID: "office", GatewayIP: "192.0.2.22", Clients: []string{"a", "b"}, LastSeen: b, ClientLastSeen: map[string]time.Time{"a": a, "b": b}}
	windows := mergeIEEE1905AssociationWindows(nil, []ieee1905AssociationGroup{group}, now.Add(-10*time.Minute), now, true, nil)
	for client, at := range group.ClientLastSeen {
		sample := windows[0].Samples["ieee1905_association"][client]
		if len(sample.Buckets) != 1 || sample.Buckets[0] != at.UnixMilli()/5000 {
			t.Fatalf("client %s source bucket changed: %+v", client, sample)
		}
	}
}
