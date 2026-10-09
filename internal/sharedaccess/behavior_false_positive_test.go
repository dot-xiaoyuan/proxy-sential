package sharedaccess

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestBehaviorProtocolVariantsCannotConfirmSingleDevice(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, os := range [][]string{{"Android", "Linux"}, {"Android", "Windows"}} {
		w := repeatedBehaviorWindow(now, map[string][]string{
			"ua_os": os, "tcp_stack": {"mss=1400,ws=9", "mss=1460,ws=3", "mss=1460,ws=9"}, "tls_stack": {"browser", "application"},
		})
		for _, router := range []BehaviorRouterContext{{}, {Status: "likely", Role: "router", Confidence: 85}} {
			item, present := AssessBehavior("single-phone", "", w, router)
			if present && (item.Status != "candidate" || item.Confidence >= 60) {
				t.Fatalf("single device protocol variants promoted sharing: %+v", item)
			}
		}
	}
}

func TestBehaviorRouterWithOnlyApplicationVariantsHasNoSharedObservation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	w := repeatedBehaviorWindow(now, map[string][]string{"tcp_stack": {"a", "b"}, "tls_stack": {"a", "b"}})
	if item, present := AssessBehavior("router-idle", "", w, BehaviorRouterContext{Brand: "TP-Link", BrandAttribution: true, Status: "confirmed", Role: "router"}); present && item.Status != "candidate" {
		t.Fatalf("router identity and application fingerprints prove no downstream clients: %+v", item)
	}
}

func TestBehaviorCurrentModelsRequireRepeatedCoexistence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	w := repeatedBehaviorWindow(now, map[string][]string{"device_model": {"Honor|Android|mobile|MAA-AN00", "Apple|iOS|mobile|iPhone12,1"}, "tcp_stack": {"a", "b"}})
	item, present := AssessBehavior("nat", "", w, BehaviorRouterContext{})
	if !present || item.Status != "confirmed" || item.StrongAnchor != "coexisting_device_models" || item.DeviceLowerBound != 2 {
		t.Fatalf("repeated models with protocol corroboration rejected: %+v", item)
	}
	w.Samples["device_model"]["Apple|iOS|mobile|iPhone12,1"] = FeatureSample{Count: 3, Buckets: []int64{now.Add(-8*time.Minute).Unix() / 5, now.Add(-7*time.Minute).Unix() / 5}}
	if item, present = AssessBehavior("ip-reuse", "", w, BehaviorRouterContext{}); present && item.Status != "candidate" {
		t.Fatalf("sequential models mistaken for concurrent devices: %+v", item)
	}
	w = repeatedBehaviorWindow(now, map[string][]string{"device_model": {"|Android|mobile|MAA-AN00", "Honor|Android|mobile|MAA-AN00"}, "tcp_stack": {"a", "b"}})
	if item, present = AssessBehavior("brand-alias", "", w, BehaviorRouterContext{}); present && item.Status != "candidate" {
		t.Fatalf("brand aliases counted as devices: %+v", item)
	}
}

func TestBehaviorAssociationAndCoverage(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	w := repeatedBehaviorWindow(now, nil)
	w.AssociatedClients = []string{"10:20:30:40:50:60", "10:20:30:40:50:61"}
	item, present := AssessBehavior("mesh", "", w, BehaviorRouterContext{})
	if !present || item.Status != "confirmed" || item.DeviceLowerBound != 2 {
		t.Fatalf("multi-client association rejected: %+v", item)
	}
	w.CoverageVerified = false
	item, present = AssessBehavior("partial", "", w, BehaviorRouterContext{})
	if !present || item.Status != "candidate" || item.StrongAnchor != "" || item.Confidence >= 60 {
		t.Fatalf("partial association became confirmed: %+v", item)
	}
}

func TestBehaviorReplaysOfficeFalsePositives(t *testing.T) {
	raw, err := os.ReadFile("testdata/discovery_false_positive_20260930.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		BehaviorAssessment
		ExpectedConfirmed bool `json:"expected_confirmed"`
	}
	if err = json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.IP, func(t *testing.T) {
			w := Window{IP: c.IP, SensorID: c.SensorID, From: c.WindowStart, To: c.WindowEnd, LastObservedAt: c.LastSeen, Complete: true, CoverageVerified: true, Samples: c.FeatureSamples, EventIDs: c.EventIDs}
			w.UAOS = sampleKeys(w.Samples["ua_os"])
			w.TTLPaths = sampleKeys(w.Samples["ttl_path"])
			w.TCPStacks = sampleKeys(w.Samples["tcp_stack"])
			w.TLSStacks = sampleKeys(w.Samples["tls_stack"])
			w.DHCPProfiles = sampleKeys(w.Samples["dhcp_stack"])
			w.AssociatedClients = sampleKeys(w.Samples["ieee1905_association"])
			item, present := AssessBehavior(c.ObservationID, c.EndpointID, w, c.Router)
			if got := present && item.Status == "confirmed"; got != c.ExpectedConfirmed {
				t.Fatalf("confirmed=%t want=%t assessment=%+v", got, c.ExpectedConfirmed, item)
			}
		})
	}
}

func sampleKeys(samples map[string]FeatureSample) []string {
	values := []string{}
	for value := range samples {
		values = append(values, value)
	}
	return values
}
