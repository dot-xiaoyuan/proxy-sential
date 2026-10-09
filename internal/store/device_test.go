package store

import (
	"encoding/json"
	"fmt"
	"testing"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

func TestTLSFingerprintDiversityDoesNotCreatePhysicalDeviceCandidates(t *testing.T) {
	// Field snapshots contained almost 5,000 TLS variants on one IPv6 address.
	// A client stack is an application clue, not an endpoint identity.
	const count = 5000
	signals := make([]DeviceSignal, count)
	for i := range signals {
		signals[i] = DeviceSignal{SignalID: fmt.Sprintf("tls-%d", i), IP: "192.0.2.1", Kind: "ja3", Strength: "medium", Value: fmt.Sprintf("fingerprint-%d", i), NormalizedValue: fmt.Sprintf("fingerprint-%d", i), EventIDs: []string{fmt.Sprintf("event-%d", i)}}
	}
	inventory := BuildDeviceInventoryFromSignals("192.0.2.1", "24h", signals, risk.Snapshot{})
	if inventory.SuspectedDeviceCount != 0 || len(inventory.Devices) != 0 {
		t.Fatalf("application variants became %d physical device candidates", len(inventory.Devices))
	}
	if len(inventory.Signals) != count {
		t.Fatal("raw protocol clues were discarded")
	}
	mixed := append(signals, DeviceSignal{SignalID: "http", IP: "192.0.2.1", Kind: "user_agent", Strength: "weak", Value: "Mozilla/5.0", EventIDs: []string{"event-1"}})
	if got := BuildDeviceInventoryFromSignals("192.0.2.1", "24h", mixed, risk.Snapshot{}); got.SuspectedDeviceCount != 0 {
		t.Fatalf("weak UA bundled the protocol clues into an endpoint: count=%d", got.SuspectedDeviceCount)
	}
	raw, err := json.Marshal(inventory)
	if err != nil || len(raw) > 2<<20 {
		t.Fatalf("protocol-only snapshot expanded instead of retaining one copy of each clue: bytes=%d err=%v", len(raw), err)
	}
}

func TestBuildDeviceInventoryUsesDHCPStrongSignals(t *testing.T) {
	ip := "192.168.10.55"
	events := []normalized.Event{
		dhcpDeviceEvent("dhcp-windows", ip, "aa-bb-cc-dd-ee-01", "DESKTOP-TEST", "MSFT 5.0", "1,3,6,15,119,252", "windows", "2026-07-29T02:56:00Z"),
		dhcpDeviceEvent("dhcp-windows-renew", ip, "aa:bb:cc:dd:ee:01", "DESKTOP-TEST", "MSFT 5.0", "1,3,6,15,119,252", "windows", "2026-07-29T02:57:00Z"),
		dhcpDeviceEvent("dhcp-android", ip, "aa:bb:cc:dd:ee:02", "android-phone", "android-dhcp-13", "1,3,6,15,26,28,51,58,59", "android", "2026-07-29T02:58:00Z"),
	}

	inventory := BuildDeviceInventory(ip, "1h", events, risk.Snapshot{IP: ip, Confidence: 0.7})
	if inventory.SuspectedDeviceCount != 2 || inventory.Status != "multi_candidate" {
		t.Fatalf("expected two strong device candidates, got %+v", inventory)
	}
	if len(inventory.Devices) != 2 {
		t.Fatalf("expected two observed devices, got %+v", inventory.Devices)
	}
	if len(inventory.Conflicts) == 0 || !hasDeviceConflict(inventory.Conflicts, "multi_observed_device") {
		t.Fatalf("expected strong multi-device conflict, got %+v", inventory.Conflicts)
	}

	windows := findDeviceByOS(inventory.Devices, "Windows")
	if windows == nil {
		t.Fatalf("expected Windows device from MSFT DHCP signal, got %+v", inventory.Devices)
	}
	if windows.StrongSignalCount < 4 {
		t.Fatalf("expected Windows device to include DHCP strong context, got %+v", windows.Signals)
	}
	if !hasDeviceSignal(windows.Signals, "mac", "aa:bb:cc:dd:ee:01") ||
		!hasDeviceSignal(windows.Signals, "dhcp_vendor_class", "MSFT 5.0") ||
		!hasDeviceSignal(windows.Signals, "device_hint", "windows") ||
		!hasDeviceSignal(windows.Signals, "dhcp_requested_options", "1,3,6,15,119,252") {
		t.Fatalf("expected DHCP MAC/vendor/hint/options signals, got %+v", windows.Signals)
	}
	if len(windows.Fingerprints) == 0 {
		t.Fatalf("expected DHCP fingerprints on Windows device")
	}
}

func TestBuildDeviceInventoryCollapsesRepeatedDHCPSignals(t *testing.T) {
	ip := "192.168.10.55"
	events := []normalized.Event{
		dhcpDeviceEvent("dhcp-lease-1", ip, "aa-bb-cc-dd-ee-01", "DESKTOP-TEST", "MSFT 5.0", "1,3,6,15,119,252", "windows", "2026-07-29T02:56:00Z"),
		dhcpDeviceEvent("dhcp-lease-2", ip, "aa:bb:cc:dd:ee:01", "DESKTOP-TEST", "MSFT 5.0", "1,3,6,15,119,252", "windows", "2026-07-29T02:57:00Z"),
	}

	inventory := BuildDeviceInventory(ip, "1h", events, risk.Snapshot{})
	macSignal := findInventorySignal(inventory.Signals, "mac", "aa:bb:cc:dd:ee:01")
	if macSignal == nil {
		t.Fatalf("expected collapsed DHCP MAC signal, got %+v", inventory.Signals)
	}
	if macSignal.SeenCount != 2 {
		t.Fatalf("expected repeated DHCP leases to increment seen_count, got %+v", macSignal)
	}
	if len(macSignal.EventIDsSample) != 2 || len(macSignal.EventIDs) != 2 {
		t.Fatalf("expected bounded event id sample to preserve both source event ids, got %+v", macSignal)
	}
}

func TestBuildDeviceInventoriesRanksStrongSignalsBeforeRecentWeakSignals(t *testing.T) {
	strongIP := "192.168.10.55"
	weakIP := "192.168.10.99"
	events := []normalized.Event{
		weakUAEvent("weak-newer", weakIP, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "2026-07-29T03:00:00Z"),
		dhcpDeviceEvent("dhcp-older", strongIP, "aa:bb:cc:dd:ee:01", "DESKTOP-TEST", "MSFT 5.0", "1,3,6,15,119,252", "windows", "2026-07-29T02:56:00Z"),
	}

	inventories := BuildDeviceInventories("1h", events, map[string]risk.Snapshot{})
	if len(inventories) != 2 {
		t.Fatalf("expected two inventories, got %+v", inventories)
	}
	if inventories[0].IP != strongIP {
		t.Fatalf("expected strong DHCP inventory first, got %+v", inventories)
	}
	if inventories[0].Summary == "当前观测到单个设备候选；仍需结合 DHCP/OUI/TCP 指纹等强信号提升准确性" {
		t.Fatalf("expected strong-signal summary, got %q", inventories[0].Summary)
	}
}

func findInventorySignal(signals []DeviceSignal, kind string, value string) *DeviceSignal {
	for index := range signals {
		if signals[index].Kind == kind && signals[index].Value == value {
			return &signals[index]
		}
	}
	return nil
}

func TestMergeEventSamplesAddsRareDeviceEventsWithoutDuplicates(t *testing.T) {
	ip := "192.168.10.55"
	weak := weakUAEvent("weak-newer", ip, "Mozilla/5.0", "2026-07-29T03:00:00Z")
	device := dhcpDeviceEvent("dhcp-rare", ip, "aa:bb:cc:dd:ee:01", "DESKTOP-TEST", "MSFT 5.0", "", "windows", "2026-07-29T02:56:00Z")

	merged := mergeEventSamples([]normalized.Event{weak, device}, []normalized.Event{device})
	if len(merged) != 2 {
		t.Fatalf("expected merged events to dedupe duplicate device event, got %+v", merged)
	}
	if merged[1].EventID != device.EventID {
		t.Fatalf("expected rare device event to be preserved, got %+v", merged)
	}
}

func TestBuildDeviceInventoryUsesZeekSoftwareSignals(t *testing.T) {
	ip := "192.168.10.6"
	inventory := BuildDeviceInventory(ip, "1h", []normalized.Event{softwareDeviceEvent("software-msft", ip, "DHCP::CLIENT", "MSFT", "MSFT 5.0", "windows", "2026-07-29T02:56:00Z")}, risk.Snapshot{})
	if inventory.Status != "single_candidate" || inventory.Confidence < 0.8 {
		t.Fatalf("expected strong software-backed device candidate, got %+v", inventory)
	}
	device := findDeviceByOS(inventory.Devices, "Windows")
	if device == nil {
		t.Fatalf("expected Windows device from software signal, got %+v", inventory.Devices)
	}
	if !hasDeviceSignal(device.Signals, "software_name", "MSFT") ||
		!hasDeviceSignal(device.Signals, "software_version", "MSFT 5.0") ||
		!hasDeviceSignal(device.Signals, "dhcp_vendor_class", "MSFT 5.0") {
		t.Fatalf("expected Zeek software signals, got %+v", device.Signals)
	}
}

func dhcpDeviceEvent(eventID, ip, mac, hostname, vendorClass, requestedOptions, hint, timestamp string) normalized.Event {
	return normalized.Event{
		SchemaVersion:   "v1",
		EventID:         eventID,
		Source:          "zeek",
		SourceEventType: "dhcp",
		Type:            "device",
		Timestamp:       timestamp,
		Observer:        map[string]any{"sensor_id": "test"},
		Subject:         map[string]any{"ip": ip, "mac": mac},
		Flow:            map[string]any{"src_ip": ip, "dst_ip": "192.168.10.1", "src_port": 68, "dst_port": 67, "proto": "udp"},
		Payload: map[string]any{
			"origin":            "dhcp",
			"mac":               mac,
			"client_mac":        mac,
			"hostname":          hostname,
			"vendor_class":      vendorClass,
			"requested_options": requestedOptions,
			"assigned_addr":     ip,
			"device_hint":       hint,
		},
		Confidence: 0.9,
	}
}

func softwareDeviceEvent(eventID, ip, softwareType, name, version, hint, timestamp string) normalized.Event {
	return normalized.Event{
		SchemaVersion:   "v1",
		EventID:         eventID,
		Source:          "zeek",
		SourceEventType: "software",
		Type:            "device",
		Timestamp:       timestamp,
		Observer:        map[string]any{"sensor_id": "test"},
		Subject:         map[string]any{"ip": ip},
		Flow:            map[string]any{"src_ip": ip, "src_port": 68},
		Payload: map[string]any{
			"origin":           "software",
			"software_type":    softwareType,
			"software_name":    name,
			"software_version": version,
			"vendor_class":     version,
			"device_hint":      hint,
		},
		Confidence: 0.78,
	}
}

func weakUAEvent(eventID, ip, ua, timestamp string) normalized.Event {
	return normalized.Event{
		SchemaVersion:   "v1",
		EventID:         eventID,
		Source:          "suricata",
		SourceEventType: "http",
		Type:            "http",
		Timestamp:       timestamp,
		Observer:        map[string]any{"sensor_id": "test"},
		Subject:         map[string]any{"ip": ip},
		Flow:            map[string]any{"src_ip": ip, "dst_ip": "198.51.100.10", "src_port": 50000, "dst_port": 80, "proto": "tcp"},
		Payload:         map[string]any{"user_agent": ua, "host": "example.test"},
		Confidence:      0.7,
	}
}

func findDeviceByOS(devices []ObservedDevice, osFamily string) *ObservedDevice {
	for index := range devices {
		if devices[index].OSFamily == osFamily {
			return &devices[index]
		}
	}
	return nil
}

func hasDeviceSignal(signals []DeviceSignal, kind, value string) bool {
	for _, signal := range signals {
		if signal.Kind == kind && signal.Value == value {
			return true
		}
	}
	return false
}

func hasDeviceConflict(conflicts []DeviceConflict, conflictType string) bool {
	for _, conflict := range conflicts {
		if conflict.Type == conflictType {
			return true
		}
	}
	return false
}
