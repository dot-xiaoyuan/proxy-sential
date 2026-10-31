package controlplane

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCachedPassiveSignalsMergeMirrorEvidence(t *testing.T) {
	dir := t.TempDir()
	ttlPath, dhcpPath := filepath.Join(dir, "ttl.jsonl"), filepath.Join(dir, "dhcp.jsonl")
	t.Setenv("PROXY_SENTINEL_TTL_SIGNAL_PATH", ttlPath)
	t.Setenv("PROXY_SENTINEL_DHCP_MESSAGE_PATH", dhcpPath)
	t.Setenv("PROXY_SENTINEL_SENSOR_ID", "sensor-a")
	if err := os.WriteFile(ttlPath, []byte(`{"ts":1793404800,"observer":{"sensor_id":"sensor-a"},"subject":{"ip":"192.0.2.8","mac":"aa:bb:cc:dd:ee:ff","vlan":"8"},"payload":{"ttl":64}}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dhcpPath, []byte(`{"ts":1793404801,"msg_types":"REQUEST","mac":"aa:bb:cc:dd:ee:ff","requested_addr":"192.0.2.8","host_name":"DESKTOP-8","vendor_class":"MSFT 5.0","requested_options":"1,3,6,15","client_id_hwtype":1,"option93_present":true,"capture_vlan":"8"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	items := cachedPassiveSignals()
	if len(items) != 1 {
		t.Fatalf("want one merged device, got %+v", items)
	}
	item := items[0]
	if item.SensorID != "sensor-a" || item.TTL != 64 || item.DHCPHostname != "DESKTOP-8" || item.OSFamily != "Windows" || item.OSEvidence == "" || item.DHCPObservedAt == "" || item.DHCPClientIDHWType != "1" || !item.DHCPOption93Present {
		t.Fatalf("lost passive evidence: %+v", item)
	}
	file, err := os.OpenFile(dhcpPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteString(`{"ts":1793404802,"msg_types":"REQUEST","mac":"aa:bb:cc:dd:ee:ff","vendor_class":"android-dhcp-13","capture_vlan":"8"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	passiveSignalSnapshot.Lock()
	passiveSignalSnapshot.checkedAt = time.Time{}
	passiveSignalSnapshot.Unlock()
	conflicted := cachedPassiveSignals()
	if len(conflicted) != 1 || !conflicted[0].OSConflict || conflicted[0].OSEvidence == "" {
		t.Fatalf("conflicting OS evidence was hidden: %+v", conflicted)
	}
	// A new log path is a new snapshot even during the short refresh interval.
	secondPath := filepath.Join(dir, "other.jsonl")
	t.Setenv("PROXY_SENTINEL_DHCP_MESSAGE_PATH", secondPath)
	if got := cachedPassiveSignals(); len(got) != 1 || got[0].DHCPHostname != "" {
		t.Fatalf("stale DHCP evidence after rotation: %+v", got)
	}
}

func TestPassiveSignalsDoNotMergeSameMACAcrossSensors(t *testing.T) {
	byKey := map[string]*PassiveSignal{}
	mergePassiveSignal(byKey, &PassiveSignal{SensorID: "sensor-a", MAC: "aa:bb:cc:dd:ee:ff", DHCPVLAN: "8", OSFamily: "Windows", OSEvidence: "DHCP option 60"})
	mergePassiveSignal(byKey, &PassiveSignal{SensorID: "sensor-b", MAC: "aa:bb:cc:dd:ee:ff", DHCPVLAN: "8", OSFamily: "Android", OSEvidence: "DHCP option 60"})
	if len(byKey) != 2 || byKey["sensor-a|mac:aa:bb:cc:dd:ee:ff|8"].OSConflict || byKey["sensor-b|mac:aa:bb:cc:dd:ee:ff|8"].OSConflict {
		t.Fatalf("cross-sensor OS clues were merged: %+v", byKey)
	}
}

func TestDurableDHCPEventDoesNotInheritUnprojectedTailFields(t *testing.T) {
	byKey := map[string]*PassiveSignal{}
	mergePassiveSignal(byKey, &PassiveSignal{SensorID: "sensor-a", MAC: "aa:bb:cc:dd:ee:ff", DHCPVLAN: "8", DHCPVendorClass: "MSFT 5.0", DHCPObservedAt: "2026-11-01T00:00:00Z", DHCPEvidenceID: "event-ack", OSFamily: "Windows", OSEvidence: "DHCP option 60"})
	mergeCachedPassiveSignal(byKey, PassiveSignal{SensorID: "sensor-a", MAC: "aa:bb:cc:dd:ee:ff", DHCPVLAN: "8", DHCPVendorClass: "android-dhcp-13", DHCPObservedAt: "2026-11-01T00:01:00Z", OSFamily: "Android", OSEvidence: "DHCP option 60", TTL: 64, TTLVLAN: "8"})
	got := byKey["sensor-a|mac:aa:bb:cc:dd:ee:ff|8"]
	if got == nil || got.DHCPEvidenceID != "event-ack" || got.DHCPObservedAt != "2026-11-01T00:00:00Z" || got.DHCPVendorClass != "MSFT 5.0" || got.OSConflict || got.TTL != 64 {
		t.Fatalf("tail was mistaken for durable evidence: %+v", got)
	}
}
