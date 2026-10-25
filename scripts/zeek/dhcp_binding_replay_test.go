package zeekvalidation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
)

func dhcpBindingFixture() (normalized.Event, discovery.CollectionConfig) {
	event := normalized.Event{
		SchemaVersion: "v1", EventID: "synthetic-dhcp-binding", Source: "zeek", SourceEventType: "dhcp", Type: "device",
		Timestamp: sampleTime.Format(time.RFC3339Nano),
		Observer:  map[string]any{"sensor_id": "ncu-184-router-pilot", "collector_instance_id": "synthetic-instance", "capture_scope_id": "synthetic-scope"},
		Subject:   map[string]any{"ip": "10.1.2.9", "mac": "02:11:22:33:44:55", "campus_id": "ncu", "vlan": "20"},
		Payload:   map[string]any{"origin": "dhcp", "msg_types": "REQUEST,ACK", "lease_time": 600, "access_domain": "bond0-router-minimal-overnight"},
		RawRef:    map[string]any{"backend": "zeek", "log": "dhcp"},
	}
	config := discovery.CollectionConfig{
		Version: 1, AllowedCIDRs: "10.0.0.0/8",
		Protocols: []discovery.ProtocolOwner{{Protocol: "dhcp", Source: "zeek", Enabled: true}},
		EventBindings: []discovery.EventBinding{{
			Source: "zeek", Protocol: "dhcp", Sensor: "ncu-184-router-pilot",
			Site: "ncu", Domain: "bond0-router-minimal-overnight", Interface: "bond0",
			ValidFrom: sampleTime.Add(-time.Minute),
		}},
	}
	return event, config
}

func TestDHCPV2BindingPreservesObservedDomainAndOriginal(t *testing.T) {
	event, config := dhcpBindingFixture()
	original, _ := json.Marshal(event)
	selected := config.SelectEvents([]normalized.Event{event})
	if len(selected) != 1 {
		t.Fatal("matching DHCP binding was not selected")
	}
	got := selected[0]
	if got.Subject["site"] != "ncu" || got.Subject["domain"] != "bond0-router-minimal-overnight" || got.Observer["interface"] != "bond0" || got.Observer["discovery_scope_version"] != 1 {
		t.Fatalf("explicit scope not retained: %+v", got)
	}
	digest := sha256.Sum256(original)
	if got.EventID != event.EventID || got.Payload["access_domain"] != event.Payload["access_domain"] || got.RawRef["source_event_hash"] != hex.EncodeToString(digest[:]) {
		t.Fatal("original event reference lost")
	}
	after, _ := json.Marshal(event)
	if string(after) != string(original) {
		t.Fatal("binding modified the immutable input event")
	}
	observation, err := discovery.FromEvent(got)
	if err != nil || observation.Domain != "bond0-router-minimal-overnight" || observation.Interface != "bond0" {
		t.Fatalf("selected event cannot become scoped observation: %+v %v", observation, err)
	}
}

func TestDHCPV2SelectionRejectsDisabledAndConflictingBindings(t *testing.T) {
	for _, kind := range []string{"disabled", "domain", "site", "too_early", "aggregate_conflict", "wrong_source", "request_only", "outside_cidr"} {
		t.Run(kind, func(t *testing.T) {
			event, config := dhcpBindingFixture()
			switch kind {
			case "disabled":
				config.Protocols[0].Enabled = false
			case "domain":
				config.EventBindings[0].Domain = "bond0-passive-pilot"
			case "site":
				config.EventBindings[0].Site = "another-site"
			case "too_early":
				config.EventBindings[0].ValidFrom = sampleTime.Add(time.Second)
			case "aggregate_conflict":
				event.Payload["discovery_scope_conflict"] = true
			case "wrong_source":
				event.Source = "suricata"
			case "request_only":
				event.Payload["msg_types"] = "DISCOVER,REQUEST"
			case "outside_cidr":
				event.Subject["ip"] = "192.168.1.9"
			}
			if selected := config.SelectEvents([]normalized.Event{event}); len(selected) != 0 {
				t.Fatalf("invalid input selected for %s", kind)
			}
		})
	}
}

func TestDHCPMissingOrUnmatchedBindingDoesNotProveCompleteScope(t *testing.T) {
	for _, unmatched := range []bool{false, true} {
		event, config := dhcpBindingFixture()
		if unmatched {
			config.EventBindings[0].Sensor = "another-sensor"
		} else {
			config.EventBindings = nil
		}
		selected := config.SelectEvents([]normalized.Event{event})
		if len(selected) != 1 {
			t.Fatal("fixture no longer exercises the current unbound selection path")
		}
		if selected[0].Observer["interface"] != nil || selected[0].Observer["discovery_scope_version"] != nil {
			t.Fatal("unmatched binding unexpectedly assigned an interface")
		}
	}
}
