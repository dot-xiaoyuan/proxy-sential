package fingerprint

import (
	"testing"
	"time"
)

func TestHypervisorVendorForcesVirtualMachine(t *testing.T) {
	library := MustLoad("test", []byte("Assignment,Organization Name\nBC2411,Proxmox Server Solutions GmbH\n"), embeddedRules)
	got := library.Identify("bc:24:11:66:87:46")
	if got.DeviceType != "virtual_machine" || got.DeviceTypeConfidence > .8 {
		t.Fatalf("hypervisor NIC was not classified as virtual machine: %+v", got)
	}
}

func TestHypervisorOverrideBeatsWindowsHostname(t *testing.T) {
	library := MustLoad("test", []byte("Assignment,Organization Name\nBC2411,Proxmox Server Solutions GmbH\n"), embeddedRules)
	got := library.IdentifyEvidence("bc:24:11:6d:51:48", []EvidenceSignal{
		{Protocol: "dhcp", Field: "hostname", Value: "WIN-4C932S0VP7H", Direction: "device", Association: "direct", SourceFamily: "dhcp"},
	}, time.Now().UTC())
	if got.DeviceType != "virtual_machine" {
		t.Fatalf("guest hostname overrode the hypervisor NIC: %+v", got)
	}
}
