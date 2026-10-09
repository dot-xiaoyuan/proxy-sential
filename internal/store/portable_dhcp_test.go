package store

import (
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
	"testing"
)

func TestPortableDHCPDoesNotCreateLinuxDesktopProfile(t *testing.T) {
	const ip = "192.0.2.82"
	for _, client := range []string{"dhcpcd-16", "udhcpc-1.36", "dhclient/4.4"} {
		event := dhcpDeviceEvent("fixture", ip, "02:00:00:00:00:82", "fixture-phone", client, "1,3,6", "linux", "2026-10-01T00:00:00Z")
		inv := BuildDeviceInventory(ip, "24h", []normalized.Event{event}, risk.Snapshot{})
		if inv.SuspectedDeviceCount != 1 || len(inv.Devices) != 1 {
			t.Fatal("observed MAC identity was lost")
		}
		if inv.Devices[0].OSFamily != "unknown" || inv.Devices[0].DeviceType != "unknown" {
			t.Errorf("portable %s became %s/%s", client, inv.Devices[0].OSFamily, inv.Devices[0].DeviceType)
		}
		if !hasDeviceSignal(inv.Signals, "dhcp_vendor_class", client) {
			t.Fatal("raw client evidence lost")
		}
	}
}

func TestLegacyPortableProfileProjectionKeepsIdentityAndIndependentOS(t *testing.T) {
	const ip = "192.0.2.82"
	inv := BuildDeviceInventory(ip, "24h", []normalized.Event{dhcpDeviceEvent("fixture", ip, "02:00:00:00:00:82", "fixture-phone", "dhcpcd-16", "1,3,6", "linux", "2026-10-01T00:00:00Z")}, risk.Snapshot{})
	inv.Devices[0].OSFamily, inv.Devices[0].DeviceType, inv.Devices[0].Label = "Linux", "desktop", "Linux / desktop"
	inv.Devices[0].Signals = append(inv.Devices[0].Signals, DeviceSignal{Source: "dhcp", Kind: "os_family", Value: "Linux", Strength: "strong"})
	id := inv.Devices[0].DeviceID
	before, _ := json.Marshal(inv.Devices[0].Signals)
	refreshDeviceInventoryConflicts(&inv)
	after, _ := json.Marshal(inv.Devices[0].Signals)
	if inv.Devices[0].OSFamily != "unknown" || inv.Devices[0].DeviceType != "unknown" || inv.Devices[0].DeviceID != id || inv.SuspectedDeviceCount != 1 || string(before) != string(after) {
		t.Fatal("legacy inferred profile was retained or source identity changed")
	}
	inv.Devices[0].OSFamily, inv.Devices[0].DeviceType = "Linux", "desktop"
	inv.Devices[0].Signals = append(inv.Devices[0].Signals, DeviceSignal{Source: "identity", Kind: "device_type", Value: "desktop", Strength: "strong"})
	refreshDeviceInventoryConflicts(&inv)
	if inv.Devices[0].OSFamily != "unknown" || inv.Devices[0].DeviceType != "desktop" {
		t.Fatal("independent hardware type was suppressed")
	}
	inv.Devices[0].OSFamily = "Linux"
	inv.Devices[0].Signals = append(inv.Devices[0].Signals, DeviceSignal{Source: "identity", Kind: "os_family", Value: "Linux", Strength: "strong"})
	refreshDeviceInventoryConflicts(&inv)
	if inv.Devices[0].OSFamily != "Linux" || inv.Devices[0].DeviceType != "desktop" {
		t.Fatal("independent explicit OS evidence was suppressed")
	}
}
