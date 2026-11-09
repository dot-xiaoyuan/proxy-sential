package discovery

import "testing"

func TestScoreChassisCandidateIKuaiPair(t *testing.T) {
	neighbor := chassisObservation{origin: "lldp", mac: "00:e0:67:2a:4f:4f", systemName: "iKuai-X86", description: "4.0.310@iKuaiOS"}
	partner := chassisObservation{origin: "ssdp", mac: "00:e0:67:2a:4f:4c", ip: "192.168.0.1", deviceType: "gateway", server: "iKuaiOS/iKuaiOS UPnP/1.1 MiniUPnPd/1.9"}
	confidence, evidence := scoreChassisCandidate(neighbor, partner)
	if confidence != 0.9 {
		t.Fatalf("confidence = %v, want 0.9", confidence)
	}
	if len(evidence) != 4 {
		t.Fatalf("evidence = %v, want four signals", evidence)
	}
}

func TestChassisCandidateRequiresASecondSignal(t *testing.T) {
	neighbor := chassisObservation{origin: "lldp", mac: "00:e0:67:2a:4f:4f", systemName: "edge-switch"}
	partner := chassisObservation{origin: "arp", mac: "00:e0:67:2a:4f:40", ip: "192.168.9.20", deviceType: "switch"}
	confidence, _ := scoreChassisCandidate(neighbor, partner)
	if confidence != 0.55 {
		t.Fatalf("confidence = %v, want only the vendor-prefix baseline", confidence)
	}
	if _, ok := bestChassisPartner(neighbor, []chassisObservation{partner}); ok {
		t.Fatal("vendor-prefix-only pair must not become a candidate")
	}
}

func TestMacTailDistance(t *testing.T) {
	if got := macTailDistance("00:e0:67:2a:4f:4f", "00:e0:67:2a:4f:4c"); got != 3 {
		t.Fatalf("distance = %d, want 3", got)
	}
	if got := macTailDistance("00:e0:67:2a:4f:4f", "00:e0:67:2a:4f:4f"); got != 0 {
		t.Fatalf("distance = %d, want 0", got)
	}
}
