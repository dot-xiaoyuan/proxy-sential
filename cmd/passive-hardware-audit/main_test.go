package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

func TestAuditKeepsScopeAndRequiresOriginalReferences(t *testing.T) {
	now := time.Date(2026, 11, 12, 3, 0, 0, 0, time.UTC)
	observation := discovery.Observation{ID: "model-1", EventID: "model-1", SourceID: "passive:sensor", Node: "sensor", Site: "campus", Domain: "access", VLAN: "20", IP: "192.0.2.1", MAC: "00:11:22:33:44:55", Origin: "sadp", ObservedAt: now.Add(-48 * time.Hour), ValidUntil: now.Add(-47 * time.Hour), Evidence: normalized.Event{RawRef: map[string]any{"payload_sha256": strings.Repeat("1", 64)}, Payload: map[string]any{"is_response": true, "identity_status": "direct_l2", "claimed_ip": "192.0.2.1", "claimed_mac": "00:11:22:33:44:55", "product_model": "DS-K1T341AMF"}}}
	var input strings.Builder
	write := func(o discovery.Observation) {
		raw, _ := json.Marshal(inputRow{AsOf: now, Observation: o})
		input.Write(raw)
		input.WriteByte('\n')
	}
	write(observation)
	write(observation) // identical repeated source does not increase the denominator
	observation.VLAN = "21"
	write(observation)
	observation.VLAN = "22"
	observation.Evidence.RawRef = nil
	write(observation)
	got, err := audit(strings.NewReader(input.String()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Observations != 4 || got.TrustedIdentities != 2 || got.Identified != 2 || len(got.Skipped) != 1 {
		t.Fatalf("incorrect scope/ref accounting: %+v", got)
	}
	if got.Rows[0].State.TypeEvidenceAt == nil || got.Rows[0].State.TypeEvidenceAt.After(now.Add(-time.Hour)) {
		t.Fatal("old hardware timestamp was replaced with current time")
	}
}

func TestAuditRejectsMixedSnapshots(t *testing.T) {
	_, err := audit(strings.NewReader("{\"as_of\":\"2026-11-12T03:00:00Z\"}\n{\"as_of\":\"2026-11-12T04:00:00Z\"}\n"))
	if err == nil {
		t.Fatal("mixed snapshots must not be reported as a complete observation window")
	}
}
