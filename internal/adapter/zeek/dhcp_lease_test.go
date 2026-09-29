package zeek

import "testing"

func TestDHCPPreservesLeaseAndFingerprint(t *testing.T) {
	p := dhcpPayload(map[string]string{"lease_time": "7200.000000", "lease_observed_at": "1789537676.8", "requested_options": "1,3,6,15", "vendor_class": "MSFT 5.0", "msg_types": "REQUEST,ACK"})
	for _, k := range []string{"lease_time", "lease_observed_at", "requested_options", "vendor_class"} {
		if p[k] == nil {
			t.Fatalf("missing %s", k)
		}
	}
}
