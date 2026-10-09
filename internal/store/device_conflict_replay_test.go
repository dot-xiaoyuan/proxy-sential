package store

import (
	"encoding/json"
	"testing"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

func TestDeviceConflictComparableDimensionsReplay(t *testing.T) {
	const ip = "192.0.2.82"
	dhcp := func(id, hint, vendor string) normalized.Event {
		return dhcpDeviceEvent(id, ip, "02:00:00:00:00:82", "fixture", vendor, "1,3,6", hint, "2026-10-01T00:00:00Z")
	}
	for _, tc := range []struct {
		name     string
		events   []normalized.Event
		conflict bool
	}{
		{"one_linux_client", []normalized.Event{dhcp("linux", "linux", "dhcpcd-16")}, false},
		{"one_windows_client", []normalized.Event{dhcp("windows", "windows", "MSFT 5.0")}, false},
		{"client_version_change", []normalized.Event{dhcp("old", "linux", "dhcpcd-15"), dhcp("new", "linux", "dhcpcd-16")}, false},
		{"android_kernel_compatible", []normalized.Event{dhcp("android", "android", "dhcpcd-16")}, false},
		{"unknown_vendor_is_not_second_os", []normalized.Event{dhcp("vendor", "linux", "custom-client-1")}, false},
		{"different_system_clues", []normalized.Event{dhcp("windows", "windows", "MSFT 5.0"), dhcp("android", "android", "android-dhcp-13")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildDeviceInventory(ip, "1h", tc.events, risk.Snapshot{})
			if hasDeviceConflict(got.Conflicts, "dhcp_stack_conflict") != tc.conflict {
				t.Fatalf("raw DHCP aliases became a conflict: %+v", got.Conflicts)
			}
			for _, conflict := range got.Conflicts {
				if conflict.Type == "dhcp_stack_conflict" && (conflict.Strength == "strong" || conflict.Confidence >= .8) {
					t.Fatalf("OS clues became physical-sharing proof: %+v", conflict)
				}
			}
			if findInventorySignal(got.Signals, "dhcp_vendor_class", tc.events[0].Payload["vendor_class"].(string)) == nil {
				t.Fatal("raw client evidence was lost")
			}
		})
	}
	for _, tc := range []struct {
		name        string
		signals     []DeviceSignal
		tlsConflict bool
	}{
		{"one_tls_handshake_two_encodings", []DeviceSignal{{Kind: "ja3", Value: "ja3-a"}, {Kind: "ja4", Value: "ja4-a"}}, false},
		{"two_tls_clients", []DeviceSignal{{Kind: "ja3", Value: "ja3-a"}, {Kind: "ja3", Value: "ja3-b"}, {Kind: "ja4", Value: "ja4-a"}}, true},
		{"one_tcp_packet_different_fields", []DeviceSignal{{Kind: "ttl", Value: "64"}, {Kind: "ipid", Value: "117"}}, false},
		{"ipid_counter_and_path_variation", []DeviceSignal{{Kind: "ttl", Value: "63"}, {Kind: "ttl", Value: "64"}, {Kind: "ipid", Value: "117"}, {Kind: "ipid", Value: "118"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildDeviceInventoryFromSignals(ip, "1h", tc.signals, risk.Snapshot{})
			if hasDeviceConflict(got.Conflicts, "tls_stack_conflict") != tc.tlsConflict || hasDeviceConflict(got.Conflicts, "tcp_stack_conflict") {
				t.Fatalf("incomparable protocol dimensions became conflicts: %+v", got.Conflicts)
			}
			if len(got.Signals) != len(tc.signals) {
				t.Fatal("raw protocol evidence was lost")
			}
		})
	}
}

func TestStoredDeviceConflictExplanationRefreshPreservesSources(t *testing.T) {
	const ip = "192.0.2.82"
	got := BuildDeviceInventory(ip, "24h", []normalized.Event{dhcpDeviceEvent("fixture-dhcp", ip, "02:00:00:00:00:82", "fixture", "dhcpcd-16", "1,3,6", "linux", "2026-10-01T00:00:00Z")}, risk.Snapshot{})
	got.Conflicts = []DeviceConflict{{ConflictID: "legacy-false-conflict", Type: "dhcp_stack_conflict", Strength: "strong", Confidence: .84, Samples: []string{"linux", "dhcpcd-16"}}}
	got.Confidence = .84
	beforeSignals, _ := json.Marshal(got.Signals)
	beforeDevices, _ := json.Marshal(got.Devices)
	refreshDeviceInventoryConflicts(&got)
	afterSignals, _ := json.Marshal(got.Signals)
	afterDevices, _ := json.Marshal(got.Devices)
	if len(got.Conflicts) != 0 || got.Confidence != .82 {
		t.Fatalf("obsolete conflict survived projection: %+v", got.Conflicts)
	}
	if string(beforeSignals) != string(afterSignals) || string(beforeDevices) != string(afterDevices) || got.SuspectedDeviceCount != 1 || got.Window != "24h" || got.LastSeen != "2026-10-01T00:00:00Z" {
		t.Fatal("refresh changed source evidence or candidate identity")
	}
}
