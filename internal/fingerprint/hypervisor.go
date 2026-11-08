package fingerprint

import "strings"

// hypervisorVendorMarkers identify NIC OUIs issued by virtualization platforms.
// A NIC from one of these vendors belongs to a virtual machine, not to the
// guest's reported hardware.
var hypervisorVendorMarkers = []string{"proxmox", "vmware", "virtualbox", "qemu", "xen", "innotek", "virtio", "microsoft hyper-v", "parallels"}

func isHypervisorVendor(vendor string) bool {
	lower := strings.ToLower(strings.TrimSpace(vendor))
	if lower == "" {
		return false
	}
	for _, marker := range hypervisorVendorMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
