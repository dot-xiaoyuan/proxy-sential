package discovery

import (
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
	"strings"
	"testing"
	"time"
)

func hardwareTestObservation(now time.Time) Observation {
	return Observation{ID: "event", EventID: "event", SourceID: "passive:sensor", Node: "sensor", Site: "campus", Domain: "access", VLAN: "20", MAC: "00:11:22:33:44:55", IP: "10.0.0.2", Origin: "sadp", ModelName: "DS-K1T341AMF", ObservedAt: now, ValidUntil: now.Add(time.Minute), Evidence: normalized.Event{Source: "packet-sidecar", Payload: map[string]any{"is_response": true, "identity_status": "direct_l2", "claimed_mac": "00:11:22:33:44:55", "claimed_ip": "10.0.0.2", "l2_source_mac": "00:11:22:33:44:55", "product_model": "DS-K1T341AMF"}}}
}

func TestHardwareFactsAreScopedAndRequireOwnership(t *testing.T) {
	now := time.Now().UTC()
	o := hardwareTestObservation(now)
	f, err := HardwareFactFromObservation(o)
	if err != nil || f == nil || len(f.Signals) == 0 {
		t.Fatalf("fact=%+v err=%v", f, err)
	}
	o.VLAN = "21"
	other, _ := HardwareFactFromObservation(o)
	if other.IdentityKey == f.IdentityKey {
		t.Fatal("same MAC crossed VLAN")
	}
	o.Evidence.Payload["identity_status"] = "l2_mismatch"
	if fact, _ := HardwareFactFromObservation(o); fact != nil {
		t.Fatal("gateway MAC became hardware identity")
	}
}

func TestHardwareRuleDependenciesChangeOnlyWithRuleSet(t *testing.T) {
	earlier := []fingerprint.HardwareSource{
		{RuleID: "model-a", RuleVersion: "v1", EvidenceID: "first"},
		{RuleID: "model-b", RuleVersion: "v1", EvidenceID: "second"},
	}
	reordered := []fingerprint.HardwareSource{
		{RuleID: "model-b", RuleVersion: "v1", EvidenceID: "new-evidence"},
		{RuleID: "model-a", RuleVersion: "v1", EvidenceID: "first"},
		{RuleID: "model-a", RuleVersion: "v1", EvidenceID: "duplicate"},
	}
	if hardwareRuleDependenciesChanged(earlier, reordered) {
		t.Fatal("evidence refresh rewrote unchanged rule dependencies")
	}
	changed := []fingerprint.HardwareSource{{RuleID: "model-a", RuleVersion: "v2"}}
	if !hardwareRuleDependenciesChanged(earlier, changed) {
		t.Fatal("rule retraction or version change must refresh dependencies")
	}
}

func TestHardwareFactKeepsExpiredSupportAndRevocationTombstone(t *testing.T) {
	now := time.Now().UTC()
	o := hardwareTestObservation(now.Add(-48 * time.Hour))
	first, _ := HardwareFactFromObservation(o)
	if first == nil || len(first.Signals) == 0 {
		t.Fatal("service expiry erased hardware input")
	}
	o.Withdrawn = true
	o.ObservedAt = now
	revoked, _ := HardwareFactFromObservation(o)
	if revoked.FactKey != first.FactKey {
		t.Fatal("withdrawal cannot target its original evidence")
	}
	if HardwareFactNewer(*first, *revoked) {
		t.Fatal("late input resurrects revoked fact")
	}
	if !HardwareFactNewer(*revoked, *first) {
		t.Fatal("new withdrawal ignored")
	}
}

func TestHardwareFactRejectsResponseAndGatewayAmbiguity(t *testing.T) {
	now := time.Now().UTC()
	o := hardwareTestObservation(now)
	o.Origin = "snmp"
	o.Evidence.Payload = map[string]any{"is_response": false, "hardware_identity": "unique_binding", "system_description": "UPS"}
	if f, _ := HardwareFactFromObservation(o); f != nil {
		t.Fatal("legacy aggregate admitted")
	}
	o.Evidence.Payload["is_response"] = true
	o.Evidence.Payload["endpoint_identity_unverified"] = true
	if f, _ := HardwareFactFromObservation(o); f != nil {
		t.Fatal("downstream unit became gateway hardware")
	}
}

func TestHardwareProtocolDirectionDoesNotPromoteClientUserAgent(t *testing.T) {
	now := time.Now().UTC()
	o := hardwareTestObservation(now)
	o.Origin = "http_device"
	o.Evidence.Payload = map[string]any{"is_response": true, "hardware_identity": "unique_binding", "server": "device-banner"}
	fact, err := HardwareFactFromObservation(o)
	if err != nil || fact == nil {
		t.Fatal(err)
	}
	signals := fact.Evidence()
	if len(signals) != 1 || signals[0].Protocol != "http" || signals[0].Direction != "server" {
		t.Fatalf("server ownership lost: %+v", signals)
	}
	o.Origin = "sip"
	o.Evidence.Payload = map[string]any{"hardware_identity": "unique_binding", "user_agent": "forwarded-phone-client"}
	fact, err = HardwareFactFromObservation(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(fact.Signals) != 0 {
		t.Fatal("SIP client was relabeled as server")
	}
}

func TestHardwareReviewUsesFrozenSnapshotWithoutHistory(t *testing.T) {
	at := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	for _, reason := range []string{"new_priority", "type_change", "address_only"} {
		selection, err := buildIndexedDeviceSelection(DeviceQuery{HardwareV2: true, ReviewReason: reason, SnapshotAt: at})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(selection.CTE, "FROM discovery_observations") || strings.Contains(selection.CTE, "now()-interval '7 days'") {
			t.Fatalf("%s uses history/wall clock", reason)
		}
		found := false
		for _, arg := range selection.Args {
			if v, ok := arg.(time.Time); ok && v.Equal(at) {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s omitted snapshot boundary", reason)
		}
	}
}

func TestHardwareFactRejectsExplicitCaptureScopeFailure(t *testing.T) {
	for _, reason := range []string{"capture_scope_collector_mismatch", "capture_scope_interface_mismatch", "capture_scope_outside_validity", "capture_scope_conflict"} {
		o := hardwareTestObservation(time.Now().UTC())
		o.Evidence.Observer = map[string]any{"capture_scope_issue": reason}
		fact, err := HardwareFactFromObservation(o)
		if err != nil || fact != nil {
			t.Errorf("%s produced trusted hardware fact: %+v %v", reason, fact, err)
		}
		if o.Evidence.Observer["capture_scope_issue"] != reason {
			t.Fatal("scope failure was removed from original evidence")
		}
	}
	if fact, err := HardwareFactFromObservation(hardwareTestObservation(time.Now().UTC())); err != nil || fact == nil {
		t.Fatal("legacy event without explicit scope issue changed")
	}
}
